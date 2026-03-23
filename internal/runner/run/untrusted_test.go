package run_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gruntwork-io/terragrunt/internal/runner/run"
	"github.com/stretchr/testify/require"
)

// Subtests mutate shared source dir sequentially; cannot run in parallel.
//
//nolint:paralleltest,tparallel
func TestCheckSourceSymlinksConfined(t *testing.T) {
	t.Parallel()

	source := t.TempDir()
	outside := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(source, "ok.tf"), []byte{}, 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(source, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(source, "sub", "inner.tf"), []byte{}, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret"), []byte("token"), 0o644))

	// Internal symlink (OK)
	require.NoError(t, os.Symlink("sub/inner.tf", filepath.Join(source, "ok-link")))

	t.Run("clean tree passes", func(t *testing.T) {
		require.NoError(t, run.CheckSourceSymlinksConfined(source))
	})

	// Add escaping symlinks
	require.NoError(t, os.Symlink(filepath.Join(outside, "secret"), filepath.Join(source, "stolen")))

	t.Run("file symlink escaping is rejected", func(t *testing.T) {
		err := run.CheckSourceSymlinksConfined(source)
		require.Error(t, err)
		require.Contains(t, err.Error(), "stolen")
		require.Contains(t, err.Error(), "resolves outside the source tree")
	})

	require.NoError(t, os.Remove(filepath.Join(source, "stolen")))

	// Dir symlink escaping
	require.NoError(t, os.Symlink(outside, filepath.Join(source, "stolen-dir")))

	t.Run("dir symlink escaping is rejected", func(t *testing.T) {
		err := run.CheckSourceSymlinksConfined(source)
		require.Error(t, err)
		require.Contains(t, err.Error(), "stolen-dir")
	})

	require.NoError(t, os.Remove(filepath.Join(source, "stolen-dir")))

	// Dangling symlink (harmless)
	require.NoError(t, os.Symlink("/does/not/exist", filepath.Join(source, "dangling")))

	t.Run("dangling symlink is tolerated", func(t *testing.T) {
		require.NoError(t, run.CheckSourceSymlinksConfined(source))
	})
}

func TestCheckGeneratePathConfined(t *testing.T) {
	t.Parallel()

	workingDir := t.TempDir()
	outsideDir := t.TempDir()

	sub := filepath.Join(workingDir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o755))

	existingInside := filepath.Join(workingDir, "backend.tf")
	require.NoError(t, os.WriteFile(existingInside, []byte{}, 0o644))

	outsideTarget := filepath.Join(outsideDir, "good.sh")
	require.NoError(t, os.WriteFile(outsideTarget, []byte("#!/bin/sh\n"), 0o755))

	// Attack: symlinked file in working dir → outside (git-cloned source scenario)
	symlinkFile := filepath.Join(workingDir, "sneaky.sh")
	require.NoError(t, os.Symlink(outsideTarget, symlinkFile))

	// Attack: symlinked subdir in working dir → outside
	symlinkDir := filepath.Join(workingDir, "sneakydir")
	require.NoError(t, os.Symlink(outsideDir, symlinkDir))

	siblingDir := workingDir + "-evil"
	require.NoError(t, os.Mkdir(siblingDir, 0o755))
	t.Cleanup(func() { os.RemoveAll(siblingDir) })

	tcs := []struct {
		name    string
		path    string
		wantErr string
	}{
		{name: "relative path inside working dir", path: "backend.tf"},
		{name: "relative path in subdir", path: "sub/backend.tf"},
		{name: "nonexistent relative path inside working dir", path: "new-file.tf"},
		{name: "absolute path outside working dir", path: outsideTarget, wantErr: "outside working directory"},
		{name: "dotdot escaping working dir", path: filepath.Join("..", filepath.Base(outsideDir), "good.sh"), wantErr: "outside working directory"},
		{name: "dotdot resolving back inside", path: "sub/../backend.tf"},
		{name: "existing symlink file pointing outside (git-cloned source attack)", path: "sneaky.sh", wantErr: "outside working directory"},
		{name: "nonexistent file in symlinked dir pointing outside", path: "sneakydir/new.sh", wantErr: "outside working directory"},
		{name: "existing file in symlinked dir pointing outside", path: "sneakydir/good.sh", wantErr: "outside working directory"},
		{name: "sibling dir with shared prefix", path: filepath.Join(siblingDir, "x.tf"), wantErr: "outside working directory"},
		{name: "nonexistent parent dir (generate would fail anyway)", path: "does-not-exist/foo.tf", wantErr: "parent directory unresolvable"},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := run.CheckGeneratePathConfined(tc.path, workingDir)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}
