package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/scanner"
)

type renderer struct {
	name   string
	render func(*bytes.Buffer, scanner.Result) error
}

var renderers = []renderer{
	{"text", func(b *bytes.Buffer, r scanner.Result) error { return Text(b, r) }},
	{"json", func(b *bytes.Buffer, r scanner.Result) error { return JSON(b, r) }},
}

const jsonPrefix = `{"schema_version":1,"status":`

// requireSchemaFirst asserts schema_version 1 is the first key of a JSON report.
func requireSchemaFirst(t *testing.T, out []byte) {
	t.Helper()
	if !bytes.HasPrefix(out, []byte(jsonPrefix)) {
		t.Errorf("schema_version 1 is not the first key: %.60s", out)
	}
}

func TestStatusIsIncompleteIffFailures(t *testing.T) {
	t.Parallel()
	f := []finding.Finding{{ID: "x", Severity: finding.SeverityLow, Title: "t"}}
	fail := []scanner.Failure{{Scanner: "s", Reason: scanner.ReasonError}}
	tests := []scanner.Result{{}, {Findings: f}, {Failures: fail}, {Findings: f, Failures: fail}}
	for _, res := range tests {
		want := "complete"
		if len(res.Failures) > 0 {
			want = "incomplete"
		}
		for _, r := range renderers {
			var b bytes.Buffer
			if err := r.render(&b, res); err != nil {
				t.Fatal(err)
			}
			marker := "status: " + want + "\n"
			if r.name == "json" {
				requireSchemaFirst(t, b.Bytes())
				marker = `"status":"` + want + `"`
			}
			if !strings.Contains(b.String(), marker) {
				t.Errorf("%s: %d findings, %d failures: missing %q in %s", r.name, len(res.Findings), len(res.Failures), marker, b.String())
			}
		}
	}
}

func TestJSONShape(t *testing.T) {
	t.Parallel()
	res := scanner.Result{Findings: []finding.Finding{{ID: "x", Severity: finding.SeverityLow, Title: "t"}}}
	for _, r := range []scanner.Result{{}, res} {
		var b bytes.Buffer
		if err := JSON(&b, r); err != nil {
			t.Fatal(err)
		}
		requireSchemaFirst(t, b.Bytes())
		if !bytes.HasSuffix(b.Bytes(), []byte("}\n")) {
			t.Errorf("unexpected framing: %s", b.Bytes())
		}
		if bytes.Contains(b.Bytes(), []byte("null")) {
			t.Errorf("output contains null: %s", b.Bytes())
		}
		var doc map[string]any
		if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if _, ok := doc["findings"].([]any); !ok {
			t.Errorf("findings is %T", doc["findings"])
		}
		if _, ok := doc["failures"].([]any); !ok {
			t.Errorf("failures is %T", doc["failures"])
		}
		by := doc["summary"].(map[string]any)["by_severity"].(map[string]any)
		if len(by) != 5 {
			t.Errorf("by_severity = %v, want 5 keys", by)
		}
	}
}

func TestJSONRoundTripsHostileStrings(t *testing.T) {
	t.Parallel()
	f := hostileFinding()
	f.File = "f" + hostile // invalid UTF-8 cannot round trip (documented)
	res := scanner.Result{Findings: []finding.Finding{f},
		Failures: []scanner.Failure{{Scanner: "s" + hostile, Reason: scanner.Reason("r" + hostile)}}}
	var b bytes.Buffer
	if err := JSON(&b, res); err != nil {
		t.Fatal(err)
	}
	noDangerous(t, "json", b.Bytes())
	requireSchemaFirst(t, b.Bytes())
	var doc struct {
		Findings []map[string]any `json:"findings"`
		Failures []map[string]any `json:"failures"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got := doc.Findings[0]
	for key, want := range map[string]string{
		"id": f.ID, "category": f.Category, "title": f.Title, "description": f.Description,
		"file": f.File, "evidence": f.Evidence,
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q", key, got[key], want)
		}
	}
	if md := got["metadata"].(map[string]any); md["k"+hostile] != "v"+hostile || md["n"] != float64(3) {
		t.Errorf("metadata = %v", md)
	}
	if doc.Failures[0]["scanner"] != "s"+hostile || doc.Failures[0]["reason"] != "r"+hostile {
		t.Errorf("failures = %v", doc.Failures)
	}
}

func TestHostileFieldsAreEscapedInBothFormats(t *testing.T) {
	t.Parallel()
	res := fixtures()["hostile"]
	for _, r := range renderers {
		var b bytes.Buffer
		if err := r.render(&b, res); err != nil {
			t.Fatal(err)
		}
		noDangerous(t, r.name, b.Bytes())
	}
}

func TestTextDistinguishesInvalidByteFromFFFD(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	res := scanner.Result{Findings: []finding.Finding{{ID: "x", Severity: finding.SeverityLow, Title: "t", File: "a\xffb\ufffdc"}}}
	if err := Text(&b, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "  file: a\\xffb\ufffdc\n") {
		t.Errorf("got %q", b.String())
	}
}

func TestTextGroupsInvalidSeverityLast(t *testing.T) {
	t.Parallel()
	res := scanner.Result{Findings: []finding.Finding{
		{ID: "bad", Severity: 99, Title: "t"}, {ID: "info", Severity: finding.SeverityInfo, Title: "t"}}}
	var b bytes.Buffer
	if err := Text(&b, res); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if i, j := strings.Index(out, "== info (1) =="), strings.Index(out, "== invalid (1) =="); i < 0 || j < i {
		t.Errorf("groups out of order:\n%s", out)
	}
	if !strings.Contains(out, "summary: complete, 2 findings (critical 0, high 0, medium 0, low 0, info 1)") {
		t.Errorf("summary wrong:\n%s", out)
	}
}

type (
	namedFloat float64
	namedInt   int
	namedStr   string
	namedBool  bool
)

type marshaler struct{}

func (marshaler) MarshalJSON() ([]byte, error) { return []byte(`"x"`), nil }

func TestInvalidMetadataIsErrRenderInBothRenderers(t *testing.T) {
	t.Parallel()
	values := map[string]any{
		"NaN": math.NaN(), "+Inf": math.Inf(1), "-Inf": math.Inf(-1), "nil": nil,
		"bytes": []byte("x"), "slice": []string{"x"}, "map": map[string]any{"a": 1},
		"chan": make(chan int), "int32": int32(1), "named float": namedFloat(1),
		"MarshalJSON": marshaler{}, "named int": namedInt(1), "named string": namedStr("x"),
		"named bool": namedBool(true), "error": errors.New("x"), "pointer": new(int),
	}
	for name, v := range values {
		res := scanner.Result{Findings: []finding.Finding{
			{ID: "ok", Severity: finding.SeverityLow, Title: "t", Metadata: map[string]any{"a": "fine"}},
			{ID: "x", Severity: finding.SeverityLow, Title: "t", Metadata: map[string]any{"k": v}},
		}}
		for _, r := range renderers {
			var b bytes.Buffer
			if err := r.render(&b, res); !errors.Is(err, ErrRender) || b.Len() != 0 {
				t.Errorf("%s/%s: err = %v, written = %d; want ErrRender and nothing written", r.name, name, err, b.Len())
			}
		}
	}
}

type countingWriter struct {
	calls int
	short bool
	err   error
	// errAfterWrite returns n == len(p) together with err.
	errAfterWrite error
	buf           bytes.Buffer
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.err != nil {
		return 0, w.err
	}
	if w.errAfterWrite != nil {
		return len(p), w.errAfterWrite
	}
	if w.short {
		w.buf.Write(p[:len(p)-1])
		return len(p) - 1, nil
	}
	return w.buf.Write(p)
}

func TestWriteIsSingleAndFailuresAreErrWrite(t *testing.T) {
	t.Parallel()
	res := fixtures()["mixed-severities"]
	for _, r := range []struct {
		name   string
		render func(*countingWriter) error
	}{
		{"text", func(w *countingWriter) error { return Text(w, res) }},
		{"json", func(w *countingWriter) error { return JSON(w, res) }},
	} {
		ok := &countingWriter{}
		if err := r.render(ok); err != nil || ok.calls != 1 || ok.buf.Len() == 0 {
			t.Errorf("%s: err = %v, calls = %d", r.name, err, ok.calls)
		}
		for name, w := range map[string]*countingWriter{
			"error": {err: errors.New("disk full")}, "short write": {short: true},
			"full count with error": {errAfterWrite: errors.New("closed")}} {
			if err := r.render(w); err != ErrWrite {
				t.Errorf("%s %s: err = %v, want ErrWrite", r.name, name, err)
			}
		}
	}
}

func TestTooLargeTextMatchesScannerCap(t *testing.T) {
	want := fmt.Sprintf("file exceeds %d GiB limit", scanner.MaxContentSize>>30)
	if got := registryFailureText[scanner.ReasonTooLarge]; got != want || scanner.MaxContentSize%(1<<30) != 0 {
		t.Errorf("too large text = %q, want %q", got, want)
	}
}
