package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/scanner"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// hostile holds every kind of dangerous rune, valid UTF-8 only.
const hostile = "a\x1b[31m\u009b\u202e\u2066\u200b\ufeff\u2028\U000e0041\u034f\ufe0f\U000e0100\u3164\u17b4\u007f\u0085\\ \"\r\n\ufffd z"

func hostileFinding() finding.Finding {
	return finding.Finding{
		ID: "id" + hostile, Severity: finding.SeverityHigh, Category: "cat" + hostile,
		Title: "title" + hostile, Description: "desc" + hostile,
		File: "f\xff" + hostile, Line: 7, Evidence: "ev" + hostile,
		Metadata: map[string]any{"k" + hostile: "v" + hostile, "n": 3},
	}
}

func fixtures() map[string]scanner.Result {
	mixed := func(id string, sev finding.Severity) finding.Finding {
		return finding.Finding{ID: id, Severity: sev, Title: "Title " + id}
	}
	full := mixed("full", finding.SeverityHigh)
	full.Category, full.Description, full.File, full.Line, full.Evidence =
		"execution", "Runs a script.", "./install.sh", 12, "curl | sh"
	full.Metadata = map[string]any{"s": `a"b`, "b": true, "i": 40, "i64": int64(1) << 40, "f": 0.5, "z": "last"}
	return map[string]scanner.Result{
		"empty-complete": {Ran: 1},
		"no-scanner-incomplete": {Failures: []scanner.Failure{
			{Scanner: scanner.RegistryName, Reason: scanner.ReasonNoScanner}}},
		"mixed-severities": {
			Findings: []finding.Finding{
				mixed("c", finding.SeverityCritical), full, mixed("m", finding.SeverityMedium),
				mixed("l", finding.SeverityLow), mixed("i", finding.SeverityInfo),
				{ID: "file-only", Severity: finding.SeverityInfo, Title: "T", File: "a.txt"},
			},
			Failures: []scanner.Failure{
				{Scanner: scanner.RegistryName, Reason: scanner.ReasonTooLarge},
				{Scanner: "filetype", Reason: scanner.ReasonPanic}},
			Ran: 2,
		},
		"hostile": {
			Findings: []finding.Finding{hostileFinding()},
			Failures: []scanner.Failure{{Scanner: "s" + hostile, Reason: scanner.Reason("r" + hostile)}},
		},
	}
}

func TestGolden(t *testing.T) {
	for name, res := range fixtures() {
		for ext, render := range map[string]func(*bytes.Buffer) error{
			"txt":  func(b *bytes.Buffer) error { return Text(b, res) },
			"json": func(b *bytes.Buffer) error { return JSON(b, res) },
		} {
			t.Run(name+"/"+ext, func(t *testing.T) {
				var got bytes.Buffer
				if err := render(&got); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join("testdata", name+"."+ext+".golden")
				if *update {
					if err := os.WriteFile(path, got.Bytes(), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.Bytes(), want) {
					t.Errorf("output differs from %s; run go test ./internal/report -update and review the diff\ngot:\n%s", path, got.Bytes())
				}
			})
		}
	}
}
