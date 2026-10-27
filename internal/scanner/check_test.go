package scanner

import (
	"reflect"
	"strings"
	"testing"

	"github.com/boktavec/redactscan/internal/finding"
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
