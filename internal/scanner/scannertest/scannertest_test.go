package scannertest

import (
	"context"
	"io"
	"testing"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
)

type fake struct {
	mutateMetadata bool
	// reads lists the (offset, length) pairs to read, in order.
	reads [][2]int64
}

func (fake) Name() string                    { return "fake" }
func (fake) Supports(artifact.Artifact) bool { return true }
func (f fake) Scan(_ context.Context, a artifact.Artifact, r io.ReaderAt, _ int64) ([]finding.Finding, error) {
	if f.mutateMetadata {
		a.Metadata["k"] = "changed"
	}
	for _, rd := range f.reads {
		_, _ = r.ReadAt(make([]byte, rd[1]), rd[0])
	}
	return nil, nil
}

// recorder is a testing.TB that records failures instead of failing.
type recorder struct {
	testing.TB
	failed bool
}

func (r *recorder) Error(...any) { r.failed = true }
func (r *recorder) Helper()      {}

func TestAssertNoMutationRejectsInvalidArtifact(t *testing.T) {
	a := artifact.Artifact{ID: "file-1", Metadata: map[string]any{"k": func() {}}}
	rec := &recorder{TB: t}
	AssertNoMutation(rec, fake{}, a, []byte("content"))
	if !rec.failed {
		t.Error("want failure for uncomparable metadata, not a panic")
	}
}

func TestAssertNoMutation(t *testing.T) {
	// "content" has 7 bytes.
	tests := []struct {
		name     string
		s        fake
		wantFail bool
	}{
		{"clean", fake{}, false},
		{"reads whole content", fake{reads: [][2]int64{{0, 7}}}, false},
		{"reads last byte", fake{reads: [][2]int64{{6, 1}}}, false},
		{"zero-length read at the end", fake{reads: [][2]int64{{7, 0}}}, false},
		{"mutates metadata", fake{mutateMetadata: true}, true},
		{"reads past the end", fake{reads: [][2]int64{{4, 4}}}, true},
		{"reads at the end", fake{reads: [][2]int64{{7, 1}}}, true},
		{"reads beyond the end", fake{reads: [][2]int64{{100, 1}}}, true},
		{"negative offset", fake{reads: [][2]int64{{-1, 1}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := artifact.Artifact{ID: "file-1", Metadata: map[string]any{"k": "v"}}
			rec := &recorder{TB: t}
			AssertNoMutation(rec, tt.s, a, []byte("content"))
			if rec.failed != tt.wantFail {
				t.Errorf("failed = %v, want %v", rec.failed, tt.wantFail)
			}
		})
	}
}

func TestReaderCountsAndReads(t *testing.T) {
	r := NewReader([]byte("abcdef"))
	buf := make([]byte, 4)
	n, err := r.ReadAt(buf, 4)
	if n != 2 || err != io.EOF || string(buf[:n]) != "ef" {
		t.Errorf("ReadAt = %d, %v, %q", n, err, buf[:n])
	}
	if n, err := r.ReadAt(buf, 0); n != 4 || err != nil || string(buf) != "abcd" {
		t.Errorf("ReadAt = %d, %v, %q", n, err, buf)
	}
	if r.Calls() != 2 {
		t.Errorf("Calls() = %d, want 2", r.Calls())
	}
}
