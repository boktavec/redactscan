package quarantine

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/scanner"
)

const (
	testHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testID   = testHash + "-0123456789abcdef"
)

func testFinding() finding.Finding {
	return finding.Finding{
		ID: "script-curl-pipe-sh", Severity: finding.SeverityHigh, Category: "script",
		Title: "t", Description: "d", ArtifactID: "a-1", File: "install.sh", Line: 12, Evidence: "e",
	}
}

func testMetadata() Metadata {
	return Metadata{
		SchemaVersion: SchemaVersion, ID: testID, SHA256: testHash, Size: 1234,
		CreatedAt: time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC),
		Source:    artifact.SourceMetadata{Type: artifact.SourceDownload, URI: "https://example.com/tool.zip"},
		Name:      "tool.zip", Decision: Block, Findings: []finding.Finding{testFinding()},
	}
}

func manyFindings(n int) []finding.Finding {
	fs := make([]finding.Finding, n)
	for i := range fs {
		fs[i] = testFinding()
	}
	return fs
}

func mustEncode(t *testing.T, m Metadata) []byte {
	t.Helper()
	data, err := encodeMetadata(m)
	if err != nil {
		t.Fatalf("encodeMetadata() = %v", err)
	}
	return data
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	typed := testFinding()
	typed.Metadata = map[string]any{
		"s": "text", "b": true, "i": 3, "big": int64(math.MaxInt64), "neg": int64(math.MinInt64),
		"f": 1.5, "whole": 3.0, "tiny": math.SmallestNonzeroFloat64, "above2^53": int64(1<<53 + 1),
	}
	many := manyFindings(scanner.MaxFindings)
	noFindings := testMetadata()
	noFindings.Findings = []finding.Finding{}
	withTyped := testMetadata()
	withTyped.Findings = []finding.Finding{typed, testFinding()}
	maxed := testMetadata()
	maxed.Findings = many
	escapes := maxed
	escapes.Name = strings.Repeat("\u202e\x07\"\\", MaxNameBytes/6)
	emptyURI := testMetadata()
	emptyURI.Source.URI = ""
	for name, m := range map[string]Metadata{
		"baseline": testMetadata(), "no findings": noFindings, "typed values": withTyped,
		"1000 findings": maxed, "escape-heavy name": escapes, "empty uri": emptyURI,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := decodeMetadata(mustEncode(t, m), testID)
			if err != nil {
				t.Fatalf("decodeMetadata() = %v", err)
			}
			if !reflect.DeepEqual(got, m) {
				t.Errorf("round trip changed the record")
			}
		})
	}
}

func TestEncodeIsDeterministicAndFindingsNeverNull(t *testing.T) {
	t.Parallel()
	f := testFinding()
	f.Metadata = map[string]any{"b": 1, "a": 2, "c": 3}
	m := testMetadata()
	m.Findings = []finding.Finding{f}
	first := mustEncode(t, m)
	for range 20 {
		if !bytes.Equal(first, mustEncode(t, m)) {
			t.Fatal("encoding is not deterministic")
		}
	}
	if ia, ib := bytes.Index(first, []byte(`"key":"a"`)), bytes.Index(first, []byte(`"key":"b"`)); ia < 0 || ia > ib {
		t.Error("finding metadata is not sorted by key")
	}
	m.Findings = nil
	if !bytes.Contains(mustEncode(t, m), []byte(`"findings":[]`)) {
		t.Error("nil findings must encode as an empty array")
	}
}

func TestEncodeSizeCap(t *testing.T) {
	t.Parallel()
	// Escape-heavy strings expand up to 6x in JSON, so 1000 findings at
	// their field maxima exceed the cap and must be refused, not written.
	f := testFinding()
	f.ID = strings.Repeat("\x01", scanner.MaxIDBytes)
	f.Title = strings.Repeat("\"", scanner.MaxTitleBytes)
	f.File = strings.Repeat("\\", scanner.MaxFileBytes)
	f.Description = strings.Repeat("\x1b", MaxDescriptionBytes)
	f.Category = strings.Repeat("\u202e", MaxCategoryBytes/3)
	f.Evidence = strings.Repeat("\x00", finding.MaxEvidenceBytes)
	m := testMetadata()
	m.Name = strings.Repeat("\u202e\x07\"\\", MaxNameBytes/6)
	m.Findings = make([]finding.Finding, scanner.MaxFindings)
	for i := range m.Findings {
		m.Findings[i] = f
	}
	if _, err := encodeMetadata(m); !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("err = %v, want ErrMetadataTooLarge", err)
	}
}

func TestDecodeRejectsOversizeBytes(t *testing.T) {
	t.Parallel()
	data := append(mustEncode(t, testMetadata()), bytes.Repeat([]byte(" "), MaxMetadataBytes)...)
	if _, err := decodeMetadata(data, testID); !errors.Is(err, ErrCorruptMetadata) {
		t.Errorf("err = %v, want ErrCorruptMetadata", err)
	}
}

// replace returns the encoded baseline with old replaced by new, failing if
// old is absent so a corruption row cannot silently become a no-op.
func replace(t *testing.T, old, new string) []byte {
	t.Helper()
	s := string(mustEncode(t, testMetadata()))
	if !strings.Contains(s, old) {
		t.Fatalf("baseline lacks %q", old)
	}
	return []byte(strings.Replace(s, old, new, 1))
}

// findingJSON is one encoded finding, to build a record with MaxFindings+1.
func findingJSON(t *testing.T) []byte {
	t.Helper()
	one := testMetadata()
	data := mustEncode(t, one)
	start := bytes.Index(data, []byte(`"findings":[`)) + len(`"findings":[`)
	return data[start : len(data)-2]
}

func TestDecodeCorruption(t *testing.T) {
	t.Parallel()
	base := string(mustEncode(t, testMetadata()))
	other := strings.Repeat("9", 64)
	typedBase := testMetadata()
	typedBase.Findings[0].Metadata = map[string]any{"k": 1}
	typed := string(mustEncode(t, typedBase))
	tooMany := testMetadata()
	tooMany.Findings = manyFindings(scanner.MaxFindings)
	manyBytes := bytes.Replace(mustEncode(t, tooMany), []byte(`"findings":[`), []byte(`"findings":[`+string(findingJSON(t))+`,`), 1)
	tests := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"truncated", base[:len(base)/2]},
		{"not json", "garbage"},
		{"null", "null"},
		{"trailing object", base + "{}"},
		{"trailing garbage", base + " x"},
		{"unknown member", strings.Replace(base, `{"schema_version"`, `{"extra":1,"schema_version"`, 1)},
		{"unknown nested member", strings.Replace(base, `"type":"download"`, `"type":"download","x":1`, 1)},
		{"duplicate decision", strings.Replace(base, `"decision":"block"`, `"decision":"block","decision":"review"`, 1)},
		{"duplicate schema", strings.Replace(base, `"schema_version":1`, `"schema_version":2,"schema_version":1`, 1)},
		{"case variant", strings.Replace(base, `"decision"`, `"Decision"`, 1)},
		{"case variant duplicate", strings.Replace(base, `"decision":"block"`, `"decision":"block","DECISION":"review"`, 1)},
		{"version 2", strings.Replace(base, `"schema_version":1`, `"schema_version":2`, 1)},
		{"version absent", strings.Replace(base, `"schema_version":1,`, ``, 1)},
		{"decision allow", strings.Replace(base, `"block"`, `"allow"`, 1)},
		{"decision case", strings.Replace(base, `"block"`, `"Block"`, 1)},
		{"decision absent", strings.Replace(base, `"decision":"block",`, ``, 1)},
		{"source type bad", strings.Replace(base, `"download"`, `"ftp"`, 1)},
		{"invalid severity name", strings.Replace(base, `"high"`, `"urgent"`, 1)},
		{"severity case", strings.Replace(base, `"high"`, `"High"`, 1)},
		{"severity invalid", strings.Replace(base, `"high"`, `"invalid"`, 1)},
		{"oversize title", strings.Replace(base, `"title":"t"`, `"title":"`+strings.Repeat("a", scanner.MaxTitleBytes+1)+`"`, 1)},
		{"oversize name", strings.Replace(base, `"name":"tool.zip"`, `"name":"`+strings.Repeat("a", MaxNameBytes+1)+`"`, 1)},
		{"negative line", strings.Replace(base, `"line":12`, `"line":-1`, 1)},
		{"id mismatch", strings.Replace(base, testID, testHash+"-fedcba9876543210", 1)},
		{"id invalid", strings.Replace(base, testID, "../x", 1)},
		{"sha mismatch", strings.Replace(base, `"sha256":"`+testHash, `"sha256":"`+other, 1)},
		{"negative size", strings.Replace(base, `"size":1234`, `"size":-1`, 1)},
		{"created_at offset", strings.Replace(base, `10:00:00Z`, `10:00:00+00:00`, 1)},
		{"created_at fraction", strings.Replace(base, `10:00:00Z`, `10:00:00.5Z`, 1)},
		{"created_at lower", strings.Replace(base, `T10`, `t10`, 1)},
		{"created_at absent", strings.Replace(base, `"created_at":"2026-10-27T10:00:00Z",`, ``, 1)},
		{"uri opaque userinfo", strings.Replace(base, `https://example.com/tool.zip`, `https:user:hunter2pass@host/x`, 1)},
		{"uri opaque ftp", strings.Replace(base, `https://example.com/tool.zip`, `ftp:alice:S3cr3tP4ss@files.example.com/a`, 1)},
		{"uri opaque file", strings.Replace(base, `https://example.com/tool.zip`, `file:user:pw@host/x`, 1)},
		{"uri no scheme", strings.Replace(base, `https://example.com/tool.zip`, `user:pw@host/x`, 1)},
		{"uri scheme not allowed", strings.Replace(base, `https://example.com`, `ftp://example.com`, 1)},
		{"uri https without host", strings.Replace(base, `https://example.com/tool.zip`, `https:///x`, 1)},
		{"uri dangling fragment", strings.Replace(base, `tool.zip"}`, `tool.zip#"}`, 1)},
		{"size absent", strings.Replace(base, `"size":1234,`, ``, 1)},
		{"size null", strings.Replace(base, `"size":1234`, `"size":null`, 1)},
		{"created_at year 10000", strings.Replace(base, `2026-10-27`, `10000-10-27`, 1)},
		{"too many findings", string(manyBytes)},
		{"uri userinfo", strings.Replace(base, `https://example.com`, `https://u:p@example.com`, 1)},
		{"uri query", strings.Replace(base, `tool.zip"}`, `tool.zip?t=1"}`, 1)},
		{"uri fragment", strings.Replace(base, `tool.zip"}`, `tool.zip#f"}`, 1)},
		{"findings null", strings.Replace(base, base[strings.Index(base, `"findings":`):len(base)-1], `"findings":null`, 1)},
		{"findings absent", base[:strings.Index(base, `,"findings"`)] + "}"},
		{"findings wrong type", strings.Replace(base, base[strings.Index(base, `"findings":`):len(base)-1], `"findings":{}`, 1)},
		{"meta unknown type", strings.Replace(typed, `"type":"int"`, `"type":"uint"`, 1)},
		{"meta type mismatch", strings.Replace(typed, `"type":"int"`, `"type":"string"`, 1)},
		{"meta int fractional", strings.Replace(typed, `"value":1`, `"value":1.5`, 1)},
		{"meta int exponent", strings.Replace(typed, `"value":1`, `"value":1e0`, 1)},
		{"meta value null", strings.Replace(typed, `"value":1`, `"value":null`, 1)},
		{"meta value absent", strings.Replace(typed, `,"value":1`, ``, 1)},
		{"meta duplicate key", strings.Replace(typed, `[{"key":"k","type":"int","value":1}]`, `[{"key":"k","type":"int","value":1},{"key":"k","type":"int","value":2}]`, 1)},
		{"meta empty key", strings.Replace(typed, `"key":"k"`, `"key":""`, 1)},
		{"meta int overflows int64", strings.Replace(strings.Replace(typed, `"type":"int"`, `"type":"int64"`, 1), `"value":1`, `"value":9223372036854775808`, 1)},
		{"invalid utf-8 name", strings.Replace(base, `tool.zip"`, "tool\xff.zip\"", 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.data == base {
				t.Fatal("corruption did not change the record")
			}
			m, err := decodeMetadata([]byte(tt.data), testID)
			if !errors.Is(err, ErrCorruptMetadata) {
				t.Fatalf("err = %v, want ErrCorruptMetadata", err)
			}
			if !reflect.DeepEqual(m, Metadata{}) {
				t.Error("returned Metadata is not zero")
			}
		})
	}
}

func TestDecodeErrorTextHasNoContent(t *testing.T) {
	t.Parallel()
	marker := "MARKERNAME"
	data := replace(t, "tool.zip", marker)
	data = append(data, '{')
	_, err := decodeMetadata(data, testID)
	if err == nil || strings.Contains(err.Error(), marker) || errors.Unwrap(err) != nil {
		t.Errorf("err = %v, want fixed text without wrapped parser error", err)
	}
}

// TestJSONv2Strictness pins the library behaviours the store relies on
// (ADR 0006 Verified behavior): if a Go release changes any of them, or the
// decoder is switched to v1, this fails.
func TestJSONv2Strictness(t *testing.T) {
	t.Parallel()
	type rec struct {
		A int `json:"a"`
	}
	for name, in := range map[string]string{
		"duplicate member": `{"a":1,"a":2}`,
		"case variant":     `{"A":1}`,
		"unknown member":   `{"a":1,"b":2}`,
		"trailing data":    `{"a":1} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var r rec
			if err := json.Unmarshal([]byte(in), &r, json.RejectUnknownMembers(true)); err == nil {
				t.Errorf("json/v2 accepted %s", in)
			}
		})
	}
}

func TestEncodeRejectsInvalidRecord(t *testing.T) {
	t.Parallel()
	badSeverity := testMetadata()
	badSeverity.Findings[0].Severity = finding.SeverityInvalid
	tooMany := testMetadata()
	tooMany.Findings = manyFindings(scanner.MaxFindings + 1)
	farFuture := testMetadata()
	farFuture.CreatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	preEra := testMetadata()
	preEra.CreatedAt = time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC)
	for name, m := range map[string]Metadata{
		"invalid severity": badSeverity, "too many findings": tooMany,
		"created_at year 10000": farFuture, "created_at year -1": preEra,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := encodeMetadata(m); !errors.Is(err, ErrInvalidInput) {
				t.Errorf("err = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestDecodeRequiresValidRecordID(t *testing.T) {
	t.Parallel()
	// id and dirID agree but are not a valid ID, so only ValidID can refuse it.
	data := replace(t, testID, "x")
	if _, err := decodeMetadata(data, "x"); !errors.Is(err, ErrCorruptMetadata) {
		t.Errorf("err = %v, want ErrCorruptMetadata", err)
	}
}

func TestValidateInput(t *testing.T) {
	t.Parallel()
	key := strings.Join([]string{"AK", "IA"}, "") + "IOSFODNN7EXAMPLE"
	in := func(mod func(*Input)) Input {
		i := Input{
			Source: artifact.SourceMetadata{Type: artifact.SourceFile, URI: "https://example.com/a"},
			Name:   "a.sh", Decision: Review, Findings: []finding.Finding{testFinding()},
		}
		mod(&i)
		return i
	}
	tests := []struct {
		name string
		in   Input
		want error
	}{
		{"valid", in(func(*Input) {}), nil},
		{"valid label-like name", in(func(i *Input) { i.Name = "[GITHUB_TOKEN_1]" }), nil},
		{"empty uri and name", in(func(i *Input) { i.Source.URI, i.Name = "", "" }), nil},
		{"name at limit", in(func(i *Input) { i.Name = strings.Repeat("a", MaxNameBytes) }), nil},
		{"uri at limit", in(func(i *Input) { i.Source.URI = "https://e.com/" + strings.Repeat("a", MaxURIBytes-14) }), nil},
		{"name secret", in(func(i *Input) { i.Name = key }), ErrSensitiveInput},
		{"name secret inside", in(func(i *Input) { i.Name = "x " + key + ".sh" }), ErrSensitiveInput},
		{"uri secret in path", in(func(i *Input) { i.Source.URI = "https://example.com/" + key }), ErrSensitiveInput},
		{"name too long", in(func(i *Input) { i.Name = strings.Repeat("a", MaxNameBytes+1) }), ErrInvalidInput},
		{"uri too long", in(func(i *Input) { i.Source.URI = "https://e.com/" + strings.Repeat("a", MaxURIBytes) }), ErrInvalidInput},
		{"name not utf-8", in(func(i *Input) { i.Name = "a\xff" }), ErrInvalidInput},
		{"uri not utf-8", in(func(i *Input) { i.Source.URI = "https://e.com/\xff" }), ErrInvalidInput},
		{"uri userinfo", in(func(i *Input) { i.Source.URI = "https://user:pw@host/x" }), ErrInvalidInput},
		{"uri empty userinfo", in(func(i *Input) { i.Source.URI = "https://@host/x" }), ErrInvalidInput},
		{"uri query", in(func(i *Input) { i.Source.URI = "https://host/x?token=1" }), ErrInvalidInput},
		{"uri bare query", in(func(i *Input) { i.Source.URI = "https://host/x?" }), ErrInvalidInput},
		{"uri fragment", in(func(i *Input) { i.Source.URI = "https://host/x#frag" }), ErrInvalidInput},
		{"uri opaque userinfo", in(func(i *Input) { i.Source.URI = "https:user:hunter2pass@host/x" }), ErrInvalidInput},
		{"uri opaque no scheme", in(func(i *Input) { i.Source.URI = "user:pw@host/x" }), ErrInvalidInput},
		{"uri opaque ftp", in(func(i *Input) { i.Source.URI = "ftp:alice:S3cr3tP4ss@files.example.com/a" }), ErrInvalidInput},
		{"uri opaque escaped slashes", in(func(i *Input) { i.Source.URI = "https:%2F%2Fuser:pw@host" }), ErrInvalidInput},
		{"uri scheme not allowed", in(func(i *Input) { i.Source.URI = "ftp://host/x" }), ErrInvalidInput},
		{"uri no scheme", in(func(i *Input) { i.Source.URI = "//host/x" }), ErrInvalidInput},
		{"uri relative path", in(func(i *Input) { i.Source.URI = "/tmp/x" }), ErrInvalidInput},
		{"uri https without host", in(func(i *Input) { i.Source.URI = "https:///x" }), ErrInvalidInput},
		{"uri dangling fragment", in(func(i *Input) { i.Source.URI = "https://host/x#" }), ErrInvalidInput},
		{"valid file uri", in(func(i *Input) { i.Source.URI = "file:///tmp/x" }), nil},
		{"uri opaque file", in(func(i *Input) { i.Source.URI = "file:user:pw@host/x" }), ErrInvalidInput},
		{"uri unparsable", in(func(i *Input) { i.Source.URI = "http://[::1" }), ErrInvalidInput},
		{"bad decision", in(func(i *Input) { i.Decision = "allow" }), ErrInvalidInput},
		{"empty decision", in(func(i *Input) { i.Decision = "" }), ErrInvalidInput},
		{"bad source type", in(func(i *Input) { i.Source.Type = "" }), ErrInvalidInput},
		{"too many findings", in(func(i *Input) { i.Findings = manyFindings(scanner.MaxFindings + 1) }), ErrInvalidInput},
		{"finding invalid severity", in(func(i *Input) { i.Findings[0].Severity = 0 }), ErrInvalidInput},
		{"finding empty id", in(func(i *Input) { i.Findings[0].ID = "" }), ErrInvalidInput},
		{"finding id too long", in(func(i *Input) { i.Findings[0].ID = strings.Repeat("a", scanner.MaxIDBytes+1) }), ErrInvalidInput},
		{"finding title too long", in(func(i *Input) { i.Findings[0].Title = strings.Repeat("a", scanner.MaxTitleBytes+1) }), ErrInvalidInput},
		{"finding file too long", in(func(i *Input) { i.Findings[0].File = strings.Repeat("a", scanner.MaxFileBytes+1) }), ErrInvalidInput},
		{"finding category too long", in(func(i *Input) { i.Findings[0].Category = strings.Repeat("a", MaxCategoryBytes+1) }), ErrInvalidInput},
		{"finding description too long", in(func(i *Input) { i.Findings[0].Description = strings.Repeat("a", MaxDescriptionBytes+1) }), ErrInvalidInput},
		{"finding artifact id too long", in(func(i *Input) { i.Findings[0].ArtifactID = strings.Repeat("a", scanner.MaxIDBytes+1) }), ErrInvalidInput},
		{"finding title not utf-8", in(func(i *Input) { i.Findings[0].Title = "a\xff" }), ErrInvalidInput},
		{"finding negative line", in(func(i *Input) { i.Findings[0].Line = -1 }), ErrInvalidInput},
		{"finding bad metadata", in(func(i *Input) { i.Findings[0].Metadata = map[string]any{"k": []byte("x")} }), ErrInvalidInput},
		{"structural error wins over sensitive", in(func(i *Input) { i.Name, i.Decision = key, "allow" }), ErrInvalidInput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateInput(tt.in)
			if !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
				t.Fatalf("validateInput() = %v, want %v", err, tt.want)
			}
			if err != nil && strings.Contains(fmt.Sprint(err), key) {
				t.Error("error echoes input")
			}
		})
	}
}
