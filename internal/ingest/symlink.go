package ingest

import (
	"errors"
	"io/fs"
	"os"
	"syscall"

	"github.com/boktavec/redactscan/internal/finding"
)

type linkKind string

const (
	linkEscape   linkKind = "escape"
	linkLoop     linkKind = "loop"
	linkDangling linkKind = "dangling"
	linkInRoot   linkKind = "in-root"
	linkUnknown  linkKind = "unknown"
)

var linkSeverity = map[linkKind]finding.Severity{
	linkEscape:   finding.SeverityMedium,
	linkLoop:     finding.SeverityLow,
	linkDangling: finding.SeverityInfo,
	linkInRoot:   finding.SeverityInfo,
	linkUnknown:  finding.SeverityMedium,
}

// classify says where the symlink at rel (slash-joined, relative to the top
// root) points, without recording the link target. It resolves against the top
// root, not the child root of rel's directory, so a sibling link such as
// a/b/c -> ../d is not mistaken for an escape. os.Root refuses an escape
// before touching anything outside the tree.
//
// Cost: Stat resolves targets in user space with one openat+close per target
// component over up to 8 chained links, so the cost depends on target length
// and hops, not on MaxDepth or MaxEntries (see the threat model).
//
// errno is non-zero only for linkUnknown with a system error. ELOOP also means
// a chain longer than the OS link limit. An empty-target link gives a non-Errno
// error and is labelled an escape (fail closed).
func classify(top *os.Root, rel string) (kind linkKind, errno int) {
	_, err := top.Stat(rel)
	var pe *fs.PathError
	var en syscall.Errno
	switch {
	case err == nil:
		return linkInRoot, 0
	case errors.Is(err, syscall.ELOOP):
		return linkLoop, 0
	case errors.Is(err, fs.ErrNotExist):
		return linkDangling, 0
	// EXDEV is unreachable on current Go (an escape is a non-Errno error);
	// kept as defence in case a Go release reports escapes that way.
	case errors.As(err, &pe) && !errors.As(pe.Err, &en), errors.Is(err, syscall.EXDEV):
		return linkEscape, 0
	case errors.As(err, &en):
		return linkUnknown, int(en)
	}
	return linkUnknown, 0
}

// addSymlink records the symlink at rel. The link is never opened or listed.
func (w *walker) addSymlink(rel string) {
	kind, errno := classify(w.top, rel)
	meta := map[string]any{"link_kind": string(kind)}
	if errno != 0 {
		meta["errno"] = errno
	}
	w.addFinding(kindSymlink, linkSeverity[kind], rel, meta)
}
