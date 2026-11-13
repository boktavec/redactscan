package scanner

import (
	"reflect"
	"strings"
	"testing"

	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/redactor"
)

func TestRunInvalidFindingsDroppedOneByOne(t *testing.T) {
	// Secret-shaped values are built at runtime.
	token := "gh" + "p_" + strings.Repeat("A", 36)
	label := "[GITHUB_TOKEN_1]"
	with := func(mod func(*finding.Finding)) finding.Finding {
		f := fnd("bad", finding.SeverityHigh)
		mod(&f)
		return f
	}
	tests := []struct {
		name string
		f    finding.Finding
		ok   bool
	}{
		{"valid", with(func(*finding.Finding) {}), true},
		{"invalid severity", with(func(f *finding.Finding) { f.Severity = finding.SeverityInvalid }), false},
		{"other artifact", with(func(f *finding.Finding) { f.ArtifactID = "file-2" }), false},
		{"evidence too long", with(func(f *finding.Finding) { f.Evidence = strings.Repeat("a", 257) }), false},
		{"empty id", with(func(f *finding.Finding) { f.ID = "" }), false},
		{"id at limit", with(func(f *finding.Finding) { f.ID = strings.Repeat("a", MaxIDBytes) }), true},
		{"id over limit", with(func(f *finding.Finding) { f.ID = strings.Repeat("a", MaxIDBytes+1) }), false},
		{"title at limit", with(func(f *finding.Finding) { f.Title = strings.Repeat("a", MaxTitleBytes) }), true},
		{"title over limit", with(func(f *finding.Finding) { f.Title = strings.Repeat("a", MaxTitleBytes+1) }), false},
		{"empty title", with(func(f *finding.Finding) { f.Title = "" }), true},
		{"id not UTF-8", with(func(f *finding.Finding) { f.ID = "a\xff" }), false},
		{"title not UTF-8", with(func(f *finding.Finding) { f.Title = "a\xff" }), false},
		{"file at limit", with(func(f *finding.Finding) { f.File = strings.Repeat("a", MaxFileBytes) }), true},
		{"file over limit", with(func(f *finding.Finding) { f.File = strings.Repeat("a", MaxFileBytes+1) }), false},
		{"line zero", with(func(f *finding.Finding) { f.Line = 0 }), true},
		{"negative line", with(func(f *finding.Finding) { f.Line = -1 }), false},
		{"secret in evidence", with(func(f *finding.Finding) { f.Evidence = "x " + token }), false},
		{"secret in title", with(func(f *finding.Finding) { f.Title = token }), false},
		{"secret in file", with(func(f *finding.Finding) { f.File = "dir/" + token }), false},
		{"label-like file", with(func(f *finding.Finding) { f.File = "dir/" + label }), true},
		{"non-UTF-8 file", with(func(f *finding.Finding) { f.File = "a\xffb" }), true},
		{"NUL in file", with(func(f *finding.Finding) { f.File = "a\x00b" }), false},
		{"secret in id", with(func(f *finding.Finding) { f.ID = token }), false},
		{"label-like evidence", with(func(f *finding.Finding) { f.Evidence = label }), true},
		{"NUL in evidence", with(func(f *finding.Finding) { f.Evidence = "a\x00b" }), false},
		{"NUL in title", with(func(f *finding.Finding) { f.Title = "a\x00b" }), false},

		{"id uppercase", with(func(f *finding.Finding) { f.ID = "Bad" }), false},
		{"id leading dash", with(func(f *finding.Finding) { f.ID = "-bad" }), false},
		{"id leading dot", with(func(f *finding.Finding) { f.ID = ".bad" }), false},
		{"id space", with(func(f *finding.Finding) { f.ID = "a b" }), false},
		{"id control", with(func(f *finding.Finding) { f.ID = "a\x1bb" }), false},
		{"id non-ASCII", with(func(f *finding.Finding) { f.ID = "caf\u00e9" }), false},
		{"id all punctuation after first", with(func(f *finding.Finding) { f.ID = "0a._-9" }), true},

		{"empty category", with(func(f *finding.Finding) { f.Category = "" }), true},
		{"category ok", with(func(f *finding.Finding) { f.Category = "execution.shell-1_x" }), true},
		{"category uppercase", with(func(f *finding.Finding) { f.Category = "Exec" }), false},
		{"category leading dash", with(func(f *finding.Finding) { f.Category = "-x" }), false},
		{"category space", with(func(f *finding.Finding) { f.Category = "a b" }), false},
		{"category control", with(func(f *finding.Finding) { f.Category = "a\x1b" }), false},
		{"category non-ASCII", with(func(f *finding.Finding) { f.Category = "caf\u00e9" }), false},
		{"category at limit", with(func(f *finding.Finding) { f.Category = strings.Repeat("a", MaxCategoryBytes) }), true},
		{"category over limit", with(func(f *finding.Finding) { f.Category = strings.Repeat("a", MaxCategoryBytes+1) }), false},
		{"secret in category", with(func(f *finding.Finding) { f.Category = token }), false},
		{"label-like category", with(func(f *finding.Finding) { f.Category = "a" + label }), false},

		{"description at limit", with(func(f *finding.Finding) { f.Description = strings.Repeat("a", MaxDescriptionBytes) }), true},
		{"description over limit", with(func(f *finding.Finding) { f.Description = strings.Repeat("a", MaxDescriptionBytes+1) }), false},
		{"description not UTF-8", with(func(f *finding.Finding) { f.Description = "a\xff" }), false},
		{"description prose", with(func(f *finding.Finding) { f.Description = "Downloads a script.\nRuns it." }), true},
		{"secret in description", with(func(f *finding.Finding) { f.Description = "x " + token }), false},
		{"label-like description", with(func(f *finding.Finding) { f.Description = "see " + label }), false},

		{"metadata ingest keys", with(func(f *finding.Finding) {
			f.Metadata = map[string]any{"link_kind": "x", "errno": 2, "file_type": "x", "op": "x", "depth_skipped": 1,
				"entries_capped": true, "read_errors": int64(1), "changed": false, "path_too_long": 1.5}
		}), true},
		{"metadata key at limit", with(func(f *finding.Finding) { f.Metadata = map[string]any{"a" + strings.Repeat("b", 63): 1} }), true},
		{"metadata key over limit", with(func(f *finding.Finding) { f.Metadata = map[string]any{"a" + strings.Repeat("b", 64): 1} }), false},
		{"metadata key uppercase", with(func(f *finding.Finding) { f.Metadata = map[string]any{"Key": 1} }), false},
		{"metadata key leading digit", with(func(f *finding.Finding) { f.Metadata = map[string]any{"1key": 1} }), false},
		{"metadata key leading underscore", with(func(f *finding.Finding) { f.Metadata = map[string]any{"_key": 1} }), false},
		{"metadata key dash", with(func(f *finding.Finding) { f.Metadata = map[string]any{"a-b": 1} }), false},
		{"metadata key dot", with(func(f *finding.Finding) { f.Metadata = map[string]any{"a.b": 1} }), false},
		{"metadata key space", with(func(f *finding.Finding) { f.Metadata = map[string]any{"a b": 1} }), false},
		{"metadata key control", with(func(f *finding.Finding) { f.Metadata = map[string]any{"a\x1b": 1} }), false},
		{"metadata key non-ASCII", with(func(f *finding.Finding) { f.Metadata = map[string]any{"caf\u00e9": 1} }), false},
		{"metadata empty key", with(func(f *finding.Finding) { f.Metadata = map[string]any{"": 1} }), false},
		{"secret in metadata value", with(func(f *finding.Finding) { f.Metadata = map[string]any{"k": "x " + token} }), false},
		{"secret-shaped metadata key", with(func(f *finding.Finding) { f.Metadata = map[string]any{"gh" + "p_" + strings.Repeat("a", 36): 1} }), false},
		{"label-like metadata value", with(func(f *finding.Finding) { f.Metadata = map[string]any{"k": label} }), true},
		{"non-string metadata unaffected", with(func(f *finding.Finding) { f.Metadata = map[string]any{"n": 7, "b": true, "x": 2.5} }), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sibling := fnd("sibling", finding.SeverityLow)
			s := &fake{name: "s", findings: []finding.Finding{tt.f, sibling, tt.f}}
			res := run(t, s)
			if tt.ok {
				if res.Incomplete() || len(res.Findings) != 3 {
					t.Errorf("want accepted, got failures=%v findings=%d", res.Failures, len(res.Findings))
				}
				return
			}
			assertFailures(t, res, Failure{"s", ReasonInvalidFinding}) // once, despite two bad findings
			if got := ids(res.Findings); !reflect.DeepEqual(got, []string{"sibling"}) {
				t.Errorf("findings = %v", got)
			}
			if res.Ran != 1 {
				t.Errorf("Ran = %d", res.Ran)
			}
		})
	}
}

func TestRedactorCleanUsesRedactorKinds(t *testing.T) {
	// Guards the assumption behind FR17: label-like text is the only kind
	// accepted, and the redactor reports it as KindLabelLike.
	res, err := redactor.Redact([]byte("[GITHUB_TOKEN_1]"))
	if err != nil || res.Counts[redactor.KindLabelLike] != 1 {
		t.Fatalf("redactor changed: counts=%v err=%v", res.Counts, err)
	}
	if !redactorClean("") {
		t.Error("empty string must be clean")
	}
}

func TestCheckFindingRedactorOnlyAfterCheapChecks(t *testing.T) {
	var calls int
	orig := redact
	redact = func(b []byte) (redactor.Result, error) { calls++; return orig(b) }
	t.Cleanup(func() { redact = orig })

	cheapFailure := fnd("Bad", finding.SeverityHigh) // uppercase ID
	cheapFailure.Title = "title"
	cheapFailure.Evidence = "evidence"
	cheapFailure.Description = "description"
	if checkFinding(cheapFailure, art) || calls != 0 {
		t.Errorf("cheap failure: calls = %d, want 0", calls)
	}

	badKey := fnd("ok", finding.SeverityHigh)
	badKey.Metadata = map[string]any{"Bad": "v"}
	if checkFinding(badKey, art) || calls != 0 {
		t.Errorf("bad metadata key: calls = %d, want 0", calls)
	}

	// The strict Description check fails after ID, Title, File, Evidence and
	// Category (6 calls in all) and before the Metadata keys and values.
	labelled := fnd("ok", finding.SeverityHigh)
	labelled.Category = "x"
	labelled.Description = "[GITHUB_TOKEN_1]"
	labelled.Metadata = map[string]any{"k": "v"}
	if checkFinding(labelled, art) || calls != 6 {
		t.Errorf("redactor calls = %d, want 6 (stop at Description)", calls)
	}
}
