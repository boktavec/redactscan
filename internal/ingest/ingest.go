// Package ingest turns inputs into artifacts. Walk lists a directory tree
// without following symlinks or leaving the root. It reads no file contents.
//
// Fail closed: a Walk that returns an error matching ErrIncomplete returned a
// partial result. Callers must never treat it as a complete or clean scan.
//
// Untrusted fields: Artifact.RelativePath, Artifact.Name and Finding.File are
// file names from the scanned tree. They may contain control, ANSI and bidi
// characters and invalid UTF-8 (distinct names can look identical once
// escaped). Display only; output code must escape them. Never join them to a
// directory or pass them to a filesystem call; open Artifact.Path with
// safefs.OpenRegular.
//
// A relative root is resolved against the current directory, which is not
// itself checked (as in safefs).
package ingest

import (
	"errors"
	"strings"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/safefs"
)

const (
	DefaultMaxDepth   = 64
	DefaultMaxEntries = 100_000
	MaxMaxDepth       = 256 // one open descriptor per level
	MaxMaxEntries     = 1_000_000

	// MaxPathBytes is macOS PATH_MAX, which counts the NUL. An entry is
	// accepted only if len(Path) + len("/private") < MaxPathBytes, so the
	// longest Path is 1015: one byte for the NUL, and room for OpenRegular to
	// rewrite a /tmp, /var or /etc root to /private/... on macOS. One rule on
	// every OS keeps results the same everywhere.
	MaxPathBytes = 1024
)

// Limits bounds a walk. A zero field means its default, never unlimited.
type Limits struct {
	MaxDepth   int // 0 means DefaultMaxDepth
	MaxEntries int // 0 means DefaultMaxEntries; counts every directory entry
}

// Result holds what a walk found. It is partial when Walk returns ErrIncomplete.
type Result struct {
	Artifacts []artifact.Artifact
	Findings  []finding.Finding
}

var (
	ErrIncomplete    = errors.New("ingest: scan incomplete")
	ErrInvalidLimits = errors.New("ingest: invalid limits")
	ErrInvalidRoot   = errors.New("ingest: invalid root")
	ErrInternal      = errors.New("ingest: internal error")
)

// Walk lists root. Fatal errors (ErrInvalidRoot, ErrInvalidLimits, ErrInternal,
// and whatever safefs.OpenDirRoot returns) come with an empty Result. The only
// non-fatal error is ErrIncomplete, returned with the partial Result. No error
// contains a path, name or OS error text.
func Walk(root string, lim Limits) (Result, error) {
	if root == "" || strings.ContainsRune(root, 0) {
		return Result{}, ErrInvalidRoot
	}
	maxDepth, maxEntries, err := lim.resolve()
	if err != nil {
		return Result{}, err
	}
	dir, top, err := safefs.OpenDirRoot(root)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = top.Close() }()

	w := &walker{top: top, prefix: pathPrefix(root), maxDepth: maxDepth, maxEntries: maxEntries}
	w.walkDir(dir, top, w.prefix, 0)
	return w.result()
}

func (l Limits) resolve() (depth, entries int, err error) {
	if l.MaxDepth < 0 || l.MaxDepth > MaxMaxDepth || l.MaxEntries < 0 || l.MaxEntries > MaxMaxEntries {
		return 0, 0, ErrInvalidLimits
	}
	depth, entries = l.MaxDepth, l.MaxEntries
	if depth == 0 {
		depth = DefaultMaxDepth
	}
	if entries == 0 {
		entries = DefaultMaxEntries
	}
	return depth, entries, nil
}

// pathPrefix is root made ready to prepend to a relative path. It does not
// clean root: Clean would change the "/tmp/" prefix rule and ".." semantics
// that OpenRegular relies on.
func pathPrefix(root string) string {
	// A root of only slashes trims to "", which gives "/".
	return strings.TrimRight(root, "/") + "/"
}
