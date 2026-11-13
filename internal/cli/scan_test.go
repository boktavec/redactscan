package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/report"
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
	// sawSize, when set, receives the size Scan was given.
	sawSize *int64
	// fileIsPath sets every finding's File to the artifact path.
	fileIsPath bool
}

func (f fakeScanner) Name() string                  { return f.name }
func (fakeScanner) Supports(artifact.Artifact) bool { return true }
func (f fakeScanner) Scan(_ context.Context, a artifact.Artifact, r io.ReaderAt, size int64) ([]finding.Finding, error) {
	if f.panics {
		panic("canary-panic")
	}
	if f.sawSize != nil {
		*f.sawSize = size
	}
	if f.scanned != nil {
		content, err := io.ReadAll(io.NewSectionReader(r, 0, size))
		if err != nil {
			return nil, err
		}
		*f.scanned = content
	}
	if f.fileIsPath {
		fs := append([]finding.Finding(nil), f.findings...)
		for i := range fs {
			fs[i].File = a.RelativePath
		}
		return fs, f.err
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
		{"json after file", []string{"scan", "a", "-json"}, reason},
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
	path := writeTemp(t, "hello")
	wantText := "redactscan scan report\nstatus: incomplete\n\nno findings\n\nfailures (1):\n- no scanner ran\n\n" +
		"summary: incomplete, 0 findings (critical 0, high 0, medium 0, low 0, info 0)\n"
	if got := run([]string{"scan", path}, strings.NewReader("")); got != (result{1, wantText, ""}) {
		t.Errorf("text: got %+v", got)
	}
	got := run([]string{"scan", "-json", path}, strings.NewReader(""))
	var doc struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &doc); err != nil {
		t.Fatalf("stdout is not JSON: %v (%q)", err, got.stdout)
	}
	if got.code != 1 || got.stderr != "" || doc.SchemaVersion != 1 || doc.Status != "incomplete" {
		t.Errorf("json: got %+v, doc %+v", got, doc)
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
	want := result{0, "redactscan scan report\nstatus: complete\n\n" +
		"== high (1) ==\n- high-id: High one\n  file: f.sh:12\n\n" +
		"== low (1) ==\n- low-id: Low one\n  file: f.sh\n\n" +
		"summary: complete, 2 findings (critical 0, high 1, medium 0, low 1, info 0)\n", ""}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if string(seen) != "content" {
		t.Errorf("scanner saw %q", seen)
	}

	got = run([]string{"scan", "-json", writeTemp(t, "content")}, strings.NewReader(""))
	if got.code != 0 || got.stderr != "" || !strings.HasPrefix(got.stdout, `{"schema_version":1,"status":"complete"`) ||
		!strings.Contains(got.stdout, `"id":"high-id"`) {
		t.Errorf("json: got %+v", got)
	}
}

func TestScanIncompleteKeepsOtherFindings(t *testing.T) {
	useScanners(t,
		fakeScanner{name: "boom", panics: true},
		fakeScanner{name: "bad", err: errors.New("canary-error")},
		fakeScanner{name: "good", findings: []finding.Finding{finding1("g", finding.SeverityMedium, "f", 1, "T")}},
	)
	for _, tt := range []struct {
		args     []string
		contains []string
	}{
		{[]string{"scan"}, []string{"status: incomplete", "- g: T", "- boom: panic", "- bad: error"}},
		{[]string{"scan", "-json"}, []string{`"status":"incomplete"`, `"id":"g"`,
			`{"scanner":"boom","reason":"panic"}`, `{"scanner":"bad","reason":"error"}`}},
	} {
		args := tt.args
		got := run(append(args, writeTemp(t, "x")), strings.NewReader(""))
		if got.code != 1 || got.stderr != "" {
			t.Errorf("%v: got %+v", args, got)
		}
		for _, want := range tt.contains {
			if !strings.Contains(got.stdout, want) {
				t.Errorf("%v: stdout lacks %q: %q", args, want, got.stdout)
			}
		}
		for _, canary := range []string{"canary-panic", "canary-error"} {
			if strings.Contains(got.stdout+got.stderr, canary) {
				t.Errorf("%v: output contains %q", args, canary)
			}
		}
	}
}

// sparse creates a file of the given size without writing its content.
func sparse(t *testing.T, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "big.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Skipf("file system cannot make a sparse file of %d bytes: %v", size, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanSizeCap(t *testing.T) {
	saw := int64(-1)
	useScanners(t, fakeScanner{name: "a", sawSize: &saw})

	if got := run([]string{"scan", sparse(t, scanner.MaxContentSize)}, strings.NewReader("")); got.code != 0 || saw != scanner.MaxContentSize {
		t.Errorf("at cap: code %d, scanner saw size %d, stderr %q", got.code, saw, got.stderr)
	}

	saw = -1
	got := run([]string{"scan", sparse(t, scanner.MaxContentSize+1)}, strings.NewReader(""))
	if got.code != 1 || got.stderr != "" || !strings.Contains(got.stdout, "- file exceeds 1 GiB limit\n") || saw != -1 {
		t.Errorf("over cap: got %+v, scanner saw size %d", got, saw)
	}
}

func TestScanMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	got := run([]string{"scan", path}, strings.NewReader(""))
	assertFailure(t, got, exitIO, `redactscan: cannot open "`+path+`": not found`+"\n")
}

func TestScanEscapesUntrustedFields(t *testing.T) {
	hostile := "a\x1b[31m\rb\u202ec\xff"
	useScanners(t, fakeScanner{name: "a", findings: []finding.Finding{
		finding1("id\x1b[31m\r\u202ex", finding.SeverityLow, hostile, 3, "title"), // dropped: ID is not an identifier
		finding1("ok-id", finding.SeverityLow, hostile, 3, "title \x1b\u202e"),
	}})
	got := run([]string{"scan", writeTemp(t, "x")}, strings.NewReader(""))
	for _, want := range []string{`file: a\x1b[31m\rb\u202ec\xff:3`, `- ok-id: title \x1b\u202e`, "- a: invalid finding"} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("stdout lacks %q: %q", want, got.stdout)
		}
	}
	assertNoDangerousRune(t, got.stdout+got.stderr)
}

func TestScanFileIsRedactorChecked(t *testing.T) {
	token := "gh" + "p_" + strings.Repeat("A", 36) // built at runtime
	useScanners(t, fakeScanner{name: "a", findings: []finding.Finding{
		finding1("dirty", finding.SeverityHigh, "dir/"+token, 1, "T"),
		finding1("labelled", finding.SeverityLow, "dir/[GITHUB_TOKEN_1]", 2, "T"),
	}})
	for _, args := range [][]string{{"scan"}, {"scan", "-json"}} {
		got := run(append(args, writeTemp(t, "x")), strings.NewReader(""))
		if got.code != 1 || !strings.Contains(got.stdout, "[GITHUB_TOKEN_1]") || !strings.Contains(got.stdout, "invalid finding") {
			t.Errorf("%v: got %+v", args, got)
		}
		if strings.Contains(got.stdout+got.stderr, token) {
			t.Errorf("%v: secret-shaped File was printed", args)
		}
	}
}

func TestScanPrintsEvidenceAndEmptyStderr(t *testing.T) {
	f := finding1("id", finding.SeverityHigh, "f", 1, "title")
	f.Evidence = "canary-evidence-zzzzzz"
	useScanners(t, fakeScanner{name: "a", findings: []finding.Finding{f}})
	got := run([]string{"scan", writeTemp(t, "x")}, strings.NewReader(""))
	if got.code != 0 || got.stderr != "" || !strings.Contains(got.stdout, "evidence: canary-evidence-zzzzzz") {
		t.Errorf("got %+v", got)
	}
}

func TestScanStdoutWriteFailure(t *testing.T) {
	useScanners(t, fakeScanner{name: "a", findings: []finding.Finding{finding1("g", finding.SeverityLow, "f", 0, "T")}})
	const want = "redactscan: cannot write output: write failed\n"
	for _, jsonFlag := range []bool{false, true} {
		args := []string{"scan", writeTemp(t, "x")}
		if jsonFlag {
			args = []string{"scan", "-json", args[1]}
		}
		for name, w := range map[string]io.Writer{"error": failWriter{}, "short write": shortWriter{}} {
			var errb strings.Builder
			if code := Run(args, strings.NewReader(""), w, &errb); code != exitIO || errb.String() != want {
				t.Errorf("json=%v %s: exit = %d, stderr = %q", jsonFlag, name, code, errb.String())
			}
		}
	}
}

func TestScanRendererErrors(t *testing.T) {
	useScanners(t, fakeScanner{name: "a"})
	tests := []struct {
		name   string
		err    error
		stderr string
	}{
		{"write error", report.ErrWrite, "redactscan: cannot write output: write failed\n"},
		{"wrapped write error", fmt.Errorf("x: %w", report.ErrWrite), "redactscan: cannot write output: write failed\n"},
		{"render error", report.ErrRender, "redactscan: internal error: cannot render report\n"},
		{"other error", errors.New("canary-render"), "redactscan: internal error: cannot render report\n"},
	}
	for _, tt := range tests {
		for _, args := range [][]string{{"scan"}, {"scan", "-json"}} {
			t.Run(tt.name+" "+strings.Join(args, " "), func(t *testing.T) {
				oldText, oldJSON := renderText, renderJSON
				fail := func(io.Writer, scanner.Result) error { return tt.err }
				renderText, renderJSON = fail, fail
				t.Cleanup(func() { renderText, renderJSON = oldText, oldJSON })
				got := run(append(args, writeTemp(t, "x")), strings.NewReader(""))
				assertFailure(t, got, exitIO, tt.stderr, "canary-render")
			})
		}
	}
}

func assertNoDangerousRune(t *testing.T, out string) {
	t.Helper()
	for _, r := range strings.TrimSuffix(out, "\n") {
		if r != '\n' && (!strconv.IsPrint(r) || r == utf8.RuneError) {
			t.Errorf("output contains dangerous rune %U", r)
		}
	}
}

func TestOpenArtifact(t *testing.T) {
	path := writeTemp(t, "12345")
	var errb strings.Builder
	a, f, _, code := openArtifact(path, &errb)
	if code != exitOK {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	defer func() { _ = f.Close() }()
	want := artifact.Artifact{
		ID: "file-1", Path: path, RelativePath: path, Name: filepath.Base(path), Size: 5, Mode: 0o600,
		Source: artifact.SourceMetadata{Type: "file"},
	}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("artifact = %+v, want %+v", a, want)
	}
	if err := a.Validate(); err != nil {
		t.Error(err)
	}
	// Nothing was read: the descriptor is still at offset 0.
	if got, err := io.ReadAll(f); err != nil || string(got) != "12345" {
		t.Errorf("file content = %q, %v", got, err)
	}
}

// TestOpenArtifactMode checks that Mode keeps permission bits only and comes
// from the opened file.
func TestOpenArtifactMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o755, 0o400} {
		path := writeTemp(t, "x")
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		a, f, _, code := openArtifact(path, io.Discard)
		if code != exitOK {
			t.Fatalf("mode %v: code %d", mode, code)
		}
		_ = f.Close()
		if a.Mode != mode {
			t.Errorf("Mode = %v, want %v", a.Mode, mode)
		}
	}
}

func TestOpenArtifactRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	var errb strings.Builder
	a, f, _, code := openArtifact(path, &errb)
	if code != exitIO || f != nil || !reflect.DeepEqual(a, artifact.Artifact{}) {
		t.Errorf("code %d, file %v, artifact %+v", code, f, a)
	}
	if want := `redactscan: cannot open "` + path + `": not found` + "\n"; errb.String() != want {
		t.Errorf("stderr = %q, want %q", errb.String(), want)
	}
}
