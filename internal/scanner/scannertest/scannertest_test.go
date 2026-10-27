package scannertest

import (
	"context"
	"testing"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
)

type fake struct {
	mutateContent, mutateMetadata bool
}

func (fake) Name() string                    { return "fake" }
func (fake) Supports(artifact.Artifact) bool { return true }
func (f fake) Scan(_ context.Context, a artifact.Artifact, content []byte) ([]finding.Finding, error) {
	if f.mutateContent {
		content[0] = 'X'
	}
	if f.mutateMetadata {
		a.Metadata["k"] = "changed"
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
	tests := []struct {
		name     string
		s        fake
		wantFail bool
	}{
		{"clean", fake{}, false},
		{"mutates content", fake{mutateContent: true}, true},
		{"mutates metadata", fake{mutateMetadata: true}, true},
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
