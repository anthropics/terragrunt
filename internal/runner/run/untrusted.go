package run

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gruntwork-io/terragrunt/internal/errors"
)

// GenerateEscapesWorkingDirError is returned when --untrusted is set and a
// generate block targets a path outside the working directory.
type GenerateEscapesWorkingDirError struct {
	Path     string
	Resolved string
	Reason   string
}

func (e GenerateEscapesWorkingDirError) Error() string {
	msg := fmt.Sprintf("generate path %q is blocked by --untrusted: %s", e.Path, e.Reason)
	if e.Resolved != "" && e.Resolved != e.Path {
		msg += fmt.Sprintf(" (resolved to %q)", e.Resolved)
	}

	return msg
}

// SourceSymlinkEscapesError is returned when --untrusted is set and the source
// tree contains a symlink that resolves outside it.
type SourceSymlinkEscapesError struct {
	Link     string
	Resolved string
}

func (e SourceSymlinkEscapesError) Error() string {
	return fmt.Sprintf("source symlink %q resolves outside the source tree to %q; blocked by --untrusted", e.Link, e.Resolved)
}

// CheckSourceSymlinksConfined walks source and rejects any symlink that
// resolves outside it. This closes the "PR commits ./stolen -> /var/run/secrets"
// route that turns file("./stolen") into an absolute-path read with relative
// syntax, defeating path-based .tf scanning.
func CheckSourceSymlinksConfined(source string) error {
	canonSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return errors.New(err)
	}

	return filepath.WalkDir(source, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if d.Type()&os.ModeSymlink == 0 {
			return nil
		}

		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			// Dangling symlinks are harmless here — the copy will skip or fail
			// on them later, and there's nothing to read through.
			return nil //nolint:nilerr
		}

		rel, err := filepath.Rel(canonSource, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New(SourceSymlinkEscapesError{Link: path, Resolved: resolved})
		}

		return nil
	})
}

// CheckGeneratePathConfined rejects generate targets that resolve outside
// workingDir. Exported for use by pkg/config/dependency.go, which has its own
// GenerateOpenTofuCode call site in the dependency-output-fetching path.
//
// Symlinks matter here because terraform { source = ... } clones into the
// working tree, and a malicious source can contain symlinks pointing outside.
// If the target file exists, its symlinks are resolved; otherwise the parent
// directory's symlinks are resolved (generate requires the parent to exist —
// os.WriteFile doesn't create intermediate dirs).
func CheckGeneratePathConfined(path, workingDir string) error {
	target := path
	if !filepath.IsAbs(target) {
		target = filepath.Join(workingDir, target)
	}

	target, err := filepath.Abs(target)
	if err != nil {
		return errors.New(GenerateEscapesWorkingDirError{Path: path, Reason: "failed to resolve absolute path: " + err.Error()})
	}

	var resolved string
	if _, statErr := os.Lstat(target); statErr == nil {
		resolved, err = filepath.EvalSymlinks(target)
		if err != nil {
			return errors.New(GenerateEscapesWorkingDirError{Path: path, Reason: "failed to resolve symlinks: " + err.Error()})
		}
	} else {
		parent, err := filepath.EvalSymlinks(filepath.Dir(target))
		if err != nil {
			return errors.New(GenerateEscapesWorkingDirError{Path: path, Reason: "parent directory unresolvable: " + err.Error()})
		}

		resolved = filepath.Join(parent, filepath.Base(target))
	}

	canonWorkingDir, err := filepath.EvalSymlinks(workingDir)
	if err != nil {
		return errors.New(GenerateEscapesWorkingDirError{Path: path, Reason: "working dir unresolvable: " + err.Error()})
	}

	rel, err := filepath.Rel(canonWorkingDir, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New(GenerateEscapesWorkingDirError{Path: path, Resolved: resolved, Reason: "target is outside working directory"})
	}

	return nil
}
