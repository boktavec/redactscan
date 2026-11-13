// Package scannertest holds test helpers for scanner implementations. Every
// scanner's tests must call AssertNoMutation, because the scanner contract
// forbids modifying artifact metadata and reading outside the content, and
// Registry.Run does not enforce either.
package scannertest

import (
	"context"
	"io"
	"maps"
	"testing"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/scanner"
)

// Reader is an io.ReaderAt over fixed content that records every read, so a
// test can check how a scanner reads. Its content is never modified.
type Reader struct {
	content []byte
	calls   []call
}

type call struct {
	off int64
	n   int
}

// NewReader returns a Reader over content.
func NewReader(content []byte) *Reader { return &Reader{content: content} }

// ReadAt records the call and reads from the content like bytes.Reader.
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	r.calls = append(r.calls, call{off, len(p)})
	if off < 0 || off >= int64(len(r.content)) {
		return 0, io.EOF
	}
	n := copy(p, r.content[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// Calls returns the number of ReadAt calls so far.
func (r *Reader) Calls() int { return len(r.calls) }

// outOfBounds reports whether any recorded call had a negative offset, ended
// past the content, or asked for bytes at or past the end.
func (r *Reader) outOfBounds() bool {
	size := int64(len(r.content))
	for _, c := range r.calls {
		if c.off < 0 || c.off+int64(c.n) > size || (c.n > 0 && c.off >= size) {
			return true
		}
	}
	return false
}

// AssertNoMutation calls s.Scan once over content and fails t if Scan changed
// a.Metadata or made a read outside the content (negative offset, past the end,
// or at or after the end). The artifact must be valid (a.Validate), or the test
// fails without calling Scan. Metadata is scalar-only (enforced by that
// Validate gate), so a shallow comparison detects every change.
func AssertNoMutation(t testing.TB, s scanner.Scanner, a artifact.Artifact, content []byte) {
	t.Helper()
	// maps.Equal panics on uncomparable values; Validate rejects them.
	if a.Validate() != nil {
		t.Error("artifact is invalid: metadata must pass artifact.ValidateMetadata")
		return
	}
	metadataBefore := maps.Clone(a.Metadata)
	r := NewReader(content)

	_, _ = s.Scan(context.Background(), a, r, int64(len(content)))

	if !maps.Equal(a.Metadata, metadataBefore) {
		t.Error("Scan modified artifact metadata")
	}
	if r.outOfBounds() {
		t.Error("Scan read outside the content")
	}
}
