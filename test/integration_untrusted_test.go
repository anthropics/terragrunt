package test_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gruntwork-io/terragrunt/test/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testFixtureUntrustedRunCmd    = "fixtures/untrusted/run-cmd"
	testFixtureUntrustedHook      = "fixtures/untrusted/hook"
	testFixtureUntrustedTflint    = "fixtures/untrusted/tflint-hook"
	testFixtureUntrustedExtraArgs = "fixtures/untrusted/extra-arguments"
	testFixtureUntrustedGenerate  = "fixtures/untrusted/generate-escape"
	testFixtureUntrustedDlDir     = "fixtures/untrusted/download-dir"
	testFixtureUntrustedSymlink   = "fixtures/untrusted/source-symlink"
	testFixtureUntrustedGetEnv    = "fixtures/untrusted/get-env"
	testFixtureUntrustedFile      = "fixtures/untrusted/file-confined"
)

func TestUntrustedRunCmd(t *testing.T) {
	t.Parallel()

	tmpEnvPath := helpers.CopyEnvironment(t, testFixtureUntrustedRunCmd)
	rootPath := filepath.Join(tmpEnvPath, testFixtureUntrustedRunCmd)

	t.Run("allowed by default", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := helpers.RunTerragruntCommandWithOutput(t,
			"terragrunt run --non-interactive --working-dir "+rootPath+" -- init")
		require.NoError(t, err)
		assert.Contains(t, stdout+stderr, "UNTRUSTED_CANARY")
	})

	t.Run("blocked with --untrusted", func(t *testing.T) {
		t.Parallel()
		_, _, err := helpers.RunTerragruntCommandWithOutput(t,
			"terragrunt run --untrusted --non-interactive --working-dir "+rootPath+" -- init")
		require.Error(t, err)
		assert.Contains(t, err.Error(), `HCL-sourced command "echo" is blocked by --untrusted`)
	})
}

func TestUntrustedHook(t *testing.T) {
	t.Parallel()

	tmpEnvPath := helpers.CopyEnvironment(t, testFixtureUntrustedHook)
	rootPath := filepath.Join(tmpEnvPath, testFixtureUntrustedHook)

	t.Run("allowed by default", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := helpers.RunTerragruntCommandWithOutput(t,
			"terragrunt run --non-interactive --working-dir "+rootPath+" -- init")
		require.NoError(t, err)
		assert.Contains(t, stdout+stderr, "UNTRUSTED_HOOK_CANARY")
	})

	t.Run("blocked with --untrusted", func(t *testing.T) {
		t.Parallel()
		_, stderr, err := helpers.RunTerragruntCommandWithOutput(t,
			"terragrunt run --untrusted --non-interactive --working-dir "+rootPath+" -- init")
		require.Error(t, err)
		assert.Contains(t, stderr+err.Error(), `HCL-sourced command "echo" is blocked by --untrusted`)
	})
}

// TestUntrustedTflintHook verifies the hook.go tflint special-case doesn't
// bypass the gate. Without the fix, execute=["tflint"] branches before
// RunHclCommandWithOutput and tflint reads .tflint.hcl from the PR tree
// (plugin download → arbitrary Go plugin exec).
func TestUntrustedTflintHook(t *testing.T) {
	t.Parallel()

	tmpEnvPath := helpers.CopyEnvironment(t, testFixtureUntrustedTflint)
	rootPath := filepath.Join(tmpEnvPath, testFixtureUntrustedTflint)

	_, stderr, err := helpers.RunTerragruntCommandWithOutput(t,
		"terragrunt run --untrusted --non-interactive --working-dir "+rootPath+" -- init")

	require.Error(t, err)
	combined := stderr + err.Error()
	assert.Contains(t, combined, `HCL-sourced command "tflint" is blocked by --untrusted`)
	assert.NotContains(t, combined, "TFLint version")
}

func TestUntrustedExtraArguments(t *testing.T) {
	t.Parallel()

	t.Run("applied by default", func(t *testing.T) {
		t.Parallel()
		rootPath := filepath.Join(helpers.CopyEnvironment(t, testFixtureUntrustedExtraArgs), testFixtureUntrustedExtraArgs)
		stdout, stderr, err := helpers.RunTerragruntCommandWithOutput(t,
			"terragrunt run --non-interactive --working-dir "+rootPath+" -- plan")
		require.NoError(t, err)
		assert.Contains(t, stdout+stderr, "EXTRA_ARGS_LEAKED")
	})

	t.Run("dropped with --untrusted", func(t *testing.T) {
		t.Parallel()
		rootPath := filepath.Join(helpers.CopyEnvironment(t, testFixtureUntrustedExtraArgs), testFixtureUntrustedExtraArgs)
		stdout, stderr, err := helpers.RunTerragruntCommandWithOutput(t,
			"terragrunt run --untrusted --non-interactive --working-dir "+rootPath+" -- plan")
		require.NoError(t, err)

		combined := stdout + stderr
		assert.Contains(t, combined, "SAFE_DEFAULT")
		assert.NotContains(t, combined, "EXTRA_ARGS_LEAKED")
	})
}

// TestUntrustedGenerateEscape replays the write-then-exec chain: generate
// overwrites a file outside the working dir. Without the gate, the write
// succeeds regardless of what reads it later.
func TestUntrustedGenerateEscape(t *testing.T) {
	t.Parallel()

	tmpEnvPath := helpers.CopyEnvironment(t, testFixtureUntrustedGenerate)
	rootPath := filepath.Join(tmpEnvPath, testFixtureUntrustedGenerate)

	targetDir := t.TempDir()
	targetFile := filepath.Join(targetDir, "target.sh")
	require.NoError(t, os.WriteFile(targetFile, []byte("ORIGINAL\n"), 0o755))

	hcl := `
generate "escape" {
  path              = "` + targetFile + `"
  if_exists         = "overwrite"
  disable_signature = true
  contents          = "PWNED\n"
}
`
	require.NoError(t, os.WriteFile(filepath.Join(rootPath, "terragrunt.hcl"), []byte(hcl), 0o644))

	_, stderr, err := helpers.RunTerragruntCommandWithOutput(t,
		"terragrunt run --untrusted --non-interactive --working-dir "+rootPath+" -- init")

	require.Error(t, err)
	assert.Contains(t, stderr+err.Error(), "blocked by --untrusted")
	assert.Contains(t, stderr+err.Error(), "outside working directory")

	contents, readErr := os.ReadFile(targetFile)
	require.NoError(t, readErr)
	assert.Equal(t, "ORIGINAL\n", string(contents), "target must not be overwritten")
}

// TestUntrustedDownloadDir verifies HCL download_dir is ignored. Without the
// gate, a PR can relocate the working tree anywhere the Atlantis process can
// write, which breaks any filesystem-path-based trust boundary.
func TestUntrustedDownloadDir(t *testing.T) {
	t.Parallel()

	tmpEnvPath := helpers.CopyEnvironment(t, testFixtureUntrustedDlDir)
	rootPath := filepath.Join(tmpEnvPath, testFixtureUntrustedDlDir)

	relocateTarget := t.TempDir()

	hcl := `
download_dir = "` + relocateTarget + `"
terraform { source = "." }
`
	require.NoError(t, os.WriteFile(filepath.Join(rootPath, "terragrunt.hcl"), []byte(hcl), 0o644))

	_, _, err := helpers.RunTerragruntCommandWithOutput(t,
		"terragrunt run --untrusted --non-interactive --working-dir "+rootPath+" -- init")
	require.NoError(t, err)

	entries, _ := os.ReadDir(relocateTarget)
	assert.Empty(t, entries, "HCL download_dir must be ignored under --untrusted")
}

// TestUntrustedSourceSymlink verifies PR-committed symlinks that point outside
// the source tree are rejected before CopyFolderContents dereferences them.
// Without this, file("./stolen") in .tf can read absolute paths with relative
// syntax, defeating path-based .tf scanning.
func TestUntrustedSourceSymlink(t *testing.T) {
	t.Parallel()

	tmpEnvPath := helpers.CopyEnvironment(t, testFixtureUntrustedSymlink)
	rootPath := filepath.Join(tmpEnvPath, testFixtureUntrustedSymlink)

	secretDir := t.TempDir()
	secretFile := filepath.Join(secretDir, "token")
	require.NoError(t, os.WriteFile(secretFile, []byte("SECRET_TOKEN_VALUE"), 0o644))

	// PR-committed symlink → /var/run/secrets-equivalent
	require.NoError(t, os.Symlink(secretFile, filepath.Join(rootPath, "stolen")))
	require.NoError(t, os.WriteFile(filepath.Join(rootPath, "terragrunt.hcl"),
		[]byte(`terraform { source = "." }`), 0o644))

	_, stderr, err := helpers.RunTerragruntCommandWithOutput(t,
		"terragrunt run --untrusted --non-interactive --working-dir "+rootPath+" -- init")

	require.Error(t, err)
	combined := stderr + err.Error()
	assert.Contains(t, combined, "resolves outside the source tree")
	assert.Contains(t, combined, "blocked by --untrusted")

	// Verify the secret was NOT dereferenced into .terragrunt-cache
	cacheEntries, _ := filepath.Glob(filepath.Join(rootPath, ".terragrunt-cache", "*", "*", "stolen"))
	for _, entry := range cacheEntries {
		contents, _ := os.ReadFile(entry)
		assert.NotContains(t, string(contents), "SECRET_TOKEN_VALUE", "symlink must not be dereferenced into cache")
	}
}

// TestUntrustedGetEnv verifies get_env is blocked entirely under --untrusted.
// Env vars in the Atlantis pod may include AWS credentials.
//
//nolint:paralleltest
func TestUntrustedGetEnv(t *testing.T) {
	tmpEnvPath := helpers.CopyEnvironment(t, testFixtureUntrustedGetEnv)
	rootPath := filepath.Join(tmpEnvPath, testFixtureUntrustedGetEnv)

	t.Setenv("UNTRUSTED_SECRET_ENV", "SECRET_VALUE")

	t.Run("allowed by default", func(t *testing.T) {
		stdout, stderr, err := helpers.RunTerragruntCommandWithOutput(t,
			"terragrunt run --non-interactive --working-dir "+rootPath+" -- plan")
		require.NoError(t, err)
		assert.Contains(t, stdout+stderr, "SECRET_VALUE")
	})

	t.Run("blocked with --untrusted", func(t *testing.T) {
		_, _, err := helpers.RunTerragruntCommandWithOutput(t,
			"terragrunt run --untrusted --non-interactive --working-dir "+rootPath+" -- plan")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get_env is blocked by --untrusted")
	})
}

// TestUntrustedFileConfinement verifies file() is confined to the worktree.
// Absolute paths outside the boundary should error at HCL parse.
func TestUntrustedFileConfinement(t *testing.T) {
	t.Parallel()

	tmpEnvPath := helpers.CopyEnvironment(t, testFixtureUntrustedFile)
	rootPath := filepath.Join(tmpEnvPath, testFixtureUntrustedFile)

	outsideFile := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(outsideFile, []byte("OUTSIDE_SECRET\n"), 0o644))

	insideFile := filepath.Join(rootPath, "inside.txt")
	require.NoError(t, os.WriteFile(insideFile, []byte("INSIDE_OK\n"), 0o644))

	t.Run("file inside worktree allowed", func(t *testing.T) {
		t.Parallel()

		hcl := `
locals { content = file("./inside.txt") }
inputs = { content = local.content }
`
		ownRoot := filepath.Join(helpers.CopyEnvironment(t, testFixtureUntrustedFile), testFixtureUntrustedFile)
		require.NoError(t, os.WriteFile(filepath.Join(ownRoot, "inside.txt"), []byte("INSIDE_OK\n"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(ownRoot, "terragrunt.hcl"), []byte(hcl), 0o644))

		stdout, stderr, err := helpers.RunTerragruntCommandWithOutput(t,
			"terragrunt run --untrusted --non-interactive --working-dir "+ownRoot+" -- plan")
		require.NoError(t, err)
		assert.Contains(t, stdout+stderr, "INSIDE_OK")
	})

	t.Run("file outside worktree blocked", func(t *testing.T) {
		t.Parallel()

		hcl := `
locals { content = file("` + outsideFile + `") }
inputs = { content = local.content }
`
		require.NoError(t, os.WriteFile(filepath.Join(rootPath, "terragrunt.hcl"), []byte(hcl), 0o644))

		_, _, err := helpers.RunTerragruntCommandWithOutput(t,
			"terragrunt run --untrusted --non-interactive --working-dir "+rootPath+" -- plan")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolves outside the repo root")
		assert.Contains(t, err.Error(), "blocked by --untrusted")
	})
}

// TestUntrustedEnvVar uses t.Setenv and cannot run in parallel.
//
//nolint:paralleltest
func TestUntrustedEnvVar(t *testing.T) {
	tmpEnvPath := helpers.CopyEnvironment(t, testFixtureUntrustedRunCmd)
	rootPath := filepath.Join(tmpEnvPath, testFixtureUntrustedRunCmd)

	t.Setenv("TG_UNTRUSTED", "true")
	_, _, err := helpers.RunTerragruntCommandWithOutput(t,
		"terragrunt run --non-interactive --working-dir "+rootPath+" -- init")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `blocked by --untrusted`)
}
