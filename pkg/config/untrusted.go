package config

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gruntwork-io/terragrunt/internal/errors"
	"github.com/gruntwork-io/terragrunt/internal/shell"
	"github.com/gruntwork-io/terragrunt/pkg/log"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// confinedFileFuncs are HCL stdlib functions that take a path as their first
// argument and read from that path. Under --untrusted they are confined to the
// git repo root so that file("/var/run/secrets/...") at HCL-parse time can't
// bypass .tf scanning (which only sees files after generate).
var confinedFileFuncs = []string{
	"file",
	"fileexists",
	"filebase64",
	"filebase64sha256",
	"filebase64sha512",
	"filemd5",
	"filesha1",
	"filesha256",
	"filesha512",
	"fileset",
	"templatefile",
}

// applyUntrustedConfinement mutates functions in place: wraps file-reading
// functions with a confinement check and replaces get_env with a blocking
// stub. The confinement boundary is the git repo root (so cross-unit reads
// like file("${get_repo_root()}/common/foo.yaml") work), falling back to
// RootWorkingDir if no git repo is present.
func applyUntrustedConfinement(
	ctx context.Context,
	l log.Logger,
	pctx *ParsingContext,
	functions map[string]function.Function,
	baseDir string,
) error {
	boundary, err := shell.GitTopLevelDir(ctx, l, pctx.Env, pctx.WorkingDir)
	if err != nil || boundary == "" {
		boundary = pctx.RootWorkingDir
	}

	if boundary == "" {
		boundary = pctx.WorkingDir
	}

	canonRoot, err := filepath.EvalSymlinks(boundary)
	if err != nil {
		return errors.New(err)
	}

	for _, name := range confinedFileFuncs {
		if orig, ok := functions[name]; ok {
			functions[name] = wrapConfinedFileFunc(name, orig, canonRoot, baseDir)
		}
	}

	functions[FuncNameGetEnv] = blockedFunc(FuncNameGetEnv)
	functions[FuncNameReadTfvarsFile] = wrapConfinedFileFunc(FuncNameReadTfvarsFile, functions[FuncNameReadTfvarsFile], canonRoot, baseDir)
	functions[FuncNameSopsDecryptFile] = wrapConfinedFileFunc(FuncNameSopsDecryptFile, functions[FuncNameSopsDecryptFile], canonRoot, baseDir)

	return nil
}

// wrapConfinedFileFunc returns a function that checks its first argument
// resolves inside root before delegating to orig.
func wrapConfinedFileFunc(name string, orig function.Function, root, baseDir string) function.Function {
	return function.New(&function.Spec{
		Params:   orig.Params(),
		VarParam: orig.VarParam(),
		Type:     orig.ReturnTypeForValues,
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			if len(args) > 0 && args[0].Type() == cty.String && args[0].IsKnown() && !args[0].IsNull() {
				if err := checkPathConfined(name, args[0].AsString(), baseDir, root); err != nil {
					return cty.NilVal, err
				}
			}

			return orig.Call(args)
		},
	})
}

func checkPathConfined(funcName, path, baseDir, root string) error {
	resolved := path
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(baseDir, resolved)
	}

	resolved, err := filepath.Abs(resolved)
	if err != nil {
		return errors.Errorf("%s(%q): %w", funcName, path, err)
	}

	// EvalSymlinks on the deepest existing ancestor — the target may not exist
	// yet (fileexists checks existence, so it must be allowed to receive a
	// nonexistent path). Walk up until a component resolves.
	probe := resolved
	for {
		if canon, symErr := filepath.EvalSymlinks(probe); symErr == nil {
			resolved = filepath.Join(canon, strings.TrimPrefix(resolved, probe))
			break
		}

		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}

		probe = parent
	}

	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.Errorf("%s(%q) resolves outside the repo root %q; blocked by --untrusted", funcName, path, root)
	}

	return nil
}

func blockedFunc(name string) function.Function {
	return function.New(&function.Spec{
		Params:   []function.Parameter{{Type: cty.String}},
		VarParam: &function.Parameter{Type: cty.String},
		Type:     function.StaticReturnType(cty.String),
		Impl: func(_ []cty.Value, _ cty.Type) (cty.Value, error) {
			return cty.NilVal, errors.New(fmt.Errorf("%s is blocked by --untrusted", name))
		},
	})
}
