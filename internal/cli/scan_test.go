package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/scanner"
)

// fakeScanner is the only thing faked: the production registry is empty, so
// tests inject scanners through the defaultRegistry seam.
type fakeScanner struct {
	name     string
	findings []finding.Finding
	err      error
	panics   bool
	scanned  *[]byte
}

func (f fakeScanner) Name() string                  { return f.name }
func (fakeScanner) Supports(artifact.Artifact) bool { return true }
func (f fakeScanner) Scan(_ context.Context, a artifact.Artifact, content []byte) ([]finding.Finding, error) {
	if f.panics {
		panic("canary-panic")
	}
	if f.scanned != nil {
		*f.scanned = append([]byte(nil), content...)
	}
	return f.findings, f.err
}

// useScanners replaces the registry for one test (not parallel-safe).
func useScanners(t *testing.T, ss ...scanner.Scanner) {
	t.Helper()
	reg, err := scanner.NewRegistry(ss...)
	if err != nil {
		t.Fatal(err)
	}
	old := defaultRegistry
	defaultRegistry = func() (*scanner.Registry, error) { return reg, nil }
	t.Cleanup(func() { defaultRegistry = old })
}

func finding1(id string, sev finding.Severity, file string, line int, title string) finding.Finding {
	return finding.Finding{ID: id, Severity: sev, ArtifactID: scanArtifactID, File: file, Line: line, Title: title}
}

func TestScanUsageErrors(t *testing.T) {
	const reason = "redactscan: scan expects exactly one FILE argument (flags must come before FILE)\n"
	tests := []struct {
		name   string
		args   []string
		reason string
	}{
		{"no argument", []string{"scan"}, reason},
		{"two arguments", []string{"scan", "a", "b"}, reason},
		{"dash", []string{"scan", "-"}, reason},
		{"unknown flag", []string{"scan", "-nope", "a"}, "redactscan: invalid arguments\n"},
		{"flag after file", []string{"scan", "a", "-h"}, reason},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := run(tt.args, strings.NewReader(""))
			assertFailure(t, got, exitUsage, tt.reason+usageText)
		})
	}
}

func TestScanHelp(t *testing.T) {
	for _, flagName := range []string{"-h", "-help"} {
		got := run([]string{"scan", flagName}, strings.NewReader(""))
		if got != (result{0, usageText, ""}) {
			t.Errorf("scan %s: got code %d stderr %q", flagName, got.code, got.stderr)
		}
	}
	scanText := usageText[strings.Index(usageText, "scan reads"):]
	for _, word := range []string{"safe", "clean"} {
		if strings.Contains(scanText[:strings.Index(scanText, "Exit codes")], word) {
			t.Errorf("scan usage must not say %q", word)
		}
	}
}

func TestScanRealDefaultRegistryIsIncomplete(t *testing.T) {
	got := run([]string{"scan", writeTemp(t, "hello")}, strings.NewReader(""))
	want := "redactscan: scan incomplete: no scanner ran\nredactscan: scan incomplete: 0 findings\n"
	if got != (result{1, "", want}) {
		t.Errorf("got %+v", got)
	}
}

func TestScanRegistryErrorIsInternalError(t *testing.T) {
	old := defaultRegistry
	defaultRegistry = func() (*scanner.Registry, error) { return nil, errors.New("canary-registry") }
	t.Cleanup(func() { defaultRegistry = old })
	got := run([]string{"scan", writeTemp(t, "x")}, strings.NewReader(""))
	assertFailure(t, got, 1, "redactscan: internal error: invalid scanner registry\n", "canary-registry")
}

func TestScanCompleteExitsZeroWithFindings(t *testing.T) {
	var seen []byte
	useScanners(t, fakeScanner{name: "a", scanned: &seen, findings: []finding.Finding{
		finding1("low-id", finding.SeverityLow, "f.sh", 0, "Low one"),
		finding1("high-id", finding.SeverityHigh, "f.sh", 12, "High one"),
	}})
	got := run([]string{"scan", writeTemp(t, "content")}, strings.NewReader(""))
	want := result{0,
		`high "high-id" "f.sh":12 "High one"` + "\n" + `low "low-id" "f.sh" "Low one"` + "\n",
		"redactscan: scan complete: 2 findings\n"}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if string(seen) != "content" {
		t.Errorf("scanner saw %q", seen)
	}
}

func TestScanIncompleteKeepsOtherFindings(t *testing.T) {
	useScanners(t,
		fakeScanner{name: "boom", panics: true},
		fakeScanner{name: "bad", err: errors.New("canary-error")},
		fakeScanner{name: "good", findings: []finding.Finding{finding1("g", finding.SeverityMedium, "f", 1, "T")}},
	)
	got := run([]string{"scan", writeTemp(t, "x")}, strings.NewReader(""))
	want := result{1, `medium "g" "f":1 "T"` + "\n",
		"redactscan: scan incomplete: boom: panic\nredactscan: scan incomplete: bad: error\nredactscan: scan incomplete: 1 findings\n"}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	for _, canary := range []string{"canary-panic", "canary-error"} {
		if strings.Contains(got.stdout+got.stderr, canary) {
			t.Errorf("output contains %q", canary)
		}
	}
}

func TestScanSizeCap(t *testing.T) {
	var seen []byte
	useScanners(t, fakeScanner{name: "a", scanned: &seen})
	atCap := writeTemp(t, strings.Repeat("a", scanner.MaxContentSize))
	if got := run([]string{"scan", atCap}, strings.NewReader("")); got.code != 0 || len(seen) != scanner.MaxContentSize {
		t.Errorf("at cap: code %d, scanned %d bytes, stderr %q", got.code, len(seen), got.stderr)
	}

	seen = nil
	over := writeTemp(t, strings.Repeat("a", scanner.MaxContentSize+1))
	got := run([]string{"scan", over}, strings.NewReader(""))
	want := "redactscan: scan incomplete: file exceeds 10 MiB limit\nredactscan: scan incomplete: 0 findings\n"
	if got != (result{1, "", want}) || seen != nil {
		t.Errorf("over cap: got %+v, scanned %d bytes", got, len(seen))
	}
}

func TestScanMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	got := run([]string{"scan", path}, strings.NewReader(""))
	assertFailure(t, got, exitIO, `redactscan: cannot open "`+path+`": not found`+"\n")
}

func TestScanEscapesUntrustedFields(t *testing.T) {
	hostile := "a\x1b[31m\rb\u202ec\xff"
	hostileID := "id\x1b[31m\r\u202ex"
	useScanners(t, fakeScanner{name: "a", findings: []finding.Finding{
		finding1(hostileID, finding.SeverityLow, hostile, 3, "title \x1b\u202e"),
	}})
	got := run([]string{"scan", writeTemp(t, "x")}, strings.NewReader(""))
	want := `low "id\x1b[31m\r\u202ex" "a\x1b[31m\rb\u202ec\xff":3 "title \x1b\u202e"` + "\n"
	if got.stdout != want {
		t.Errorf("stdout = %q, want %q", got.stdout, want)
	}
	for _, bad := range []string{"\x1b", "\r", "\u202e", "\xff"} {
		if strings.Contains(got.stdout+got.stderr, bad) {
			t.Errorf("output contains raw %q", bad)
		}
	}
}

func TestScanFileIsRedactorChecked(t *testing.T) {
	token := "gh" + "p_" + strings.Repeat("A", 36) // built at runtime
	useScanners(t, fakeScanner{name: "a", findings: []finding.Finding{
		finding1("dirty", finding.SeverityHigh, "dir/"+token, 1, "T"),
		finding1("labelled", finding.SeverityLow, "dir/[GITHUB_TOKEN_1]", 2, "T"),
	}})
	got := run([]string{"scan", writeTemp(t, "x")}, strings.NewReader(""))
	want := result{1, `low "labelled" "dir/[GITHUB_TOKEN_1]":2 "T"` + "\n",
		"redactscan: scan incomplete: a: invalid finding\nredactscan: scan incomplete: 1 findings\n"}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if strings.Contains(got.stdout+got.stderr, token) {
		t.Error("secret-shaped File was printed")
	}
}

func TestScanPrintsOnlyAllowlistedFields(t *testing.T) {
	canary := func(s string) string { return "canary-" + s + "-" + strings.Repeat("z", 6) }
	f := finding1("id", finding.SeverityHigh, "f", 1, "title")
	f.Evidence = canary("evidence")
	f.Description = canary("description")
	f.Category = canary("category")
	f.Metadata = map[string]any{canary("key"): canary("value")}
	useScanners(t, fakeScanner{name: "a", findings: []finding.Finding{f}})

	got := run([]string{"scan", writeTemp(t, "x")}, strings.NewReader(""))
	if got.code != 0 || got.stdout == "" {
		t.Fatalf("got %+v", got)
	}
	if strings.Contains(got.stdout+got.stderr, "canary-") {
		t.Errorf("a canary was printed: %+v", got)
	}
}

func TestScanStdoutWriteFailure(t *testing.T) {
	good := fakeScanner{name: "a", findings: []finding.Finding{finding1("g", finding.SeverityLow, "f", 0, "T")}}
	tests := []struct {
		name    string
		ss      []scanner.Scanner
		w       io.Writer
		summary string
	}{
		{"complete, failing writer", []scanner.Scanner{good}, failWriter{}, "redactscan: scan complete: 1 findings\n"},
		{"complete, short writer", []scanner.Scanner{good}, shortWriter{}, "redactscan: scan complete: 1 findings\n"},
		{"incomplete, failing writer", []scanner.Scanner{good, fakeScanner{name: "b", panics: true}}, failWriter{},
			"redactscan: scan incomplete: b: panic\nredactscan: scan incomplete: 1 findings\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useScanners(t, tt.ss...)
			var errb strings.Builder
			code := Run([]string{"scan", writeTemp(t, "x")}, strings.NewReader(""), tt.w, &errb)
			want := tt.summary + "redactscan: cannot write output: write failed\n"
			if code != exitIO || errb.String() != want {
				t.Errorf("exit = %d, stderr = %q, want %d and %q", code, errb.String(), exitIO, want)
			}
		})
	}
}

func TestReadArtifact(t *testing.T) {
	path := writeTemp(t, "12345")
	var errb strings.Builder
	a, content, code := readArtifact(path, &errb)
	if code != exitOK || string(content) != "12345" {
		t.Fatalf("code %d content %q stderr %q", code, content, errb.String())
	}
	want := artifact.Artifact{
		ID: "file-1", Path: path, RelativePath: path, Name: filepath.Base(path), Size: 5,
		Source: artifact.SourceMetadata{Type: "file"},
	}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("artifact = %+v, want %+v", a, want)
	}
	if err := a.Validate(); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error(err)
	}
}
