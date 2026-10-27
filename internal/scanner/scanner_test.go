package scanner

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
)

type panicMode int

const (
	noPanic panicMode = iota
	panicString
	panicNil
	panicError
	goexit
)

// fake is a configurable Scanner. Hooks run inside Scan.
type fake struct {
	name        string
	unsupported bool
	findings    []finding.Finding
	err         error
	supportsBad panicMode
	scanBad     panicMode
	onScan      func(ctx context.Context, content []byte)

	scans    int
	nameCall int
	order    *[]string
}

func (f *fake) Name() string { f.nameCall++; return f.name }

func (f *fake) Supports(artifact.Artifact) bool {
	misbehave(f.supportsBad)
	return !f.unsupported
}

func (f *fake) Scan(ctx context.Context, _ artifact.Artifact, content []byte) ([]finding.Finding, error) {
	f.scans++
	if f.order != nil {
		*f.order = append(*f.order, f.name)
	}
	if f.onScan != nil {
		f.onScan(ctx, content)
	}
	misbehave(f.scanBad)
	return f.findings, f.err
}

func misbehave(m panicMode) {
	switch m {
	case panicString:
		panic("canary-panic")
	case panicNil:
		panic(nil)
	case panicError:
		panic(errors.New("canary-panic-error"))
	case goexit:
		runtime.Goexit()
	}
}

var _ Scanner = (*fake)(nil)

var art = artifact.Artifact{ID: "file-1", Path: "p", RelativePath: "p", Name: "p"}

func fnd(id string, sev finding.Severity) finding.Finding {
	return finding.Finding{ID: id, Severity: sev, ArtifactID: art.ID, Title: "t " + id}
}

func newReg(t *testing.T, ss ...Scanner) *Registry {
	t.Helper()
	r, err := NewRegistry(ss...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func run(t *testing.T, ss ...Scanner) Result {
	t.Helper()
	return newReg(t, ss...).Run(context.Background(), art, []byte("content"))
}

func ids(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func assertFailures(t *testing.T, got Result, want ...Failure) {
	t.Helper()
	if !reflect.DeepEqual(got.Failures, want) {
		t.Errorf("failures = %v, want %v", got.Failures, want)
	}
	if got.Incomplete() != (len(want) > 0) {
		t.Errorf("Incomplete() = %v", got.Incomplete())
	}
}

func TestNewRegistryValidation(t *testing.T) {
	tests := []struct {
		name string
		ss   []Scanner
		want string // error suffix, empty for success
	}{
		{"none", nil, ""},
		{"valid", []Scanner{&fake{name: "a"}, &fake{name: "b-2"}, &fake{name: "0x"}}, ""},
		{"max length", []Scanner{&fake{name: strings.Repeat("a", 32)}}, ""},
		{"nil", []Scanner{&fake{name: "a"}, nil}, "scanner 1: nil scanner"},
		{"empty", []Scanner{&fake{name: ""}}, "scanner 0: invalid name"},
		{"too long", []Scanner{&fake{name: strings.Repeat("a", 33)}}, "scanner 0: invalid name"},
		{"upper", []Scanner{&fake{name: "Abc"}}, "scanner 0: invalid name"},
		{"leading dash", []Scanner{&fake{name: "-a"}}, "scanner 0: invalid name"},
		{"underscore", []Scanner{&fake{name: "a_b"}}, "scanner 0: invalid name"},
		{"newline", []Scanner{&fake{name: "a\n"}}, "scanner 0: invalid name"},
		{"non-ASCII", []Scanner{&fake{name: "é"}}, "scanner 0: invalid name"},
		{"reserved", []Scanner{&fake{name: "registry"}}, "scanner 0: reserved name"},
		{"duplicate", []Scanner{&fake{name: "a"}, &fake{name: "b"}, &fake{name: "a"}}, "scanner 2: duplicate name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRegistry(tt.ss...)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidRegistry) {
				t.Fatalf("err = %v, want ErrInvalidRegistry", err)
			}
			if want := "scanner: invalid registry: " + tt.want; err.Error() != want {
				t.Errorf("err = %q, want %q", err, want)
			}
		})
	}
}

func TestNewRegistryCapturesNameOnce(t *testing.T) {
	f := &changingName{}
	r := newReg(t, f)
	res := r.Run(context.Background(), art, nil)
	if f.calls != 1 {
		t.Errorf("Name called %d times, want 1", f.calls)
	}
	assertFailures(t, res, Failure{RegistryName, ReasonNoScanner}) // Supports is false
	f.supports = true
	f.err = errors.New("x")
	res = r.Run(context.Background(), art, nil)
	assertFailures(t, res, Failure{"first", ReasonError}, Failure{RegistryName, ReasonNoScanner})
}

// changingName returns a valid name first and an invalid one afterwards.
type changingName struct {
	calls    int
	supports bool
	err      error
}

func (c *changingName) Name() string {
	c.calls++
	if c.calls == 1 {
		return "first"
	}
	return "Bad Name"
}
func (c *changingName) Supports(artifact.Artifact) bool { return c.supports }
func (c *changingName) Scan(context.Context, artifact.Artifact, []byte) ([]finding.Finding, error) {
	return nil, c.err
}

func TestDefault(t *testing.T) {
	r, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	assertFailures(t, r.Run(context.Background(), art, nil), Failure{RegistryName, ReasonNoScanner})
}

func TestRunOrderAndSupports(t *testing.T) {
	var order []string
	a := &fake{name: "a", order: &order, findings: []finding.Finding{fnd("a", finding.SeverityLow)}}
	b := &fake{name: "b", order: &order, unsupported: true}
	c := &fake{name: "c", order: &order, findings: []finding.Finding{fnd("c", finding.SeverityLow)}}
	res := run(t, a, b, c)
	if !reflect.DeepEqual(order, []string{"a", "c"}) {
		t.Errorf("scan order = %v", order)
	}
	if b.scans != 0 || res.Ran != 2 || res.Incomplete() {
		t.Errorf("scans=%d ran=%d failures=%v", b.scans, res.Ran, res.Failures)
	}
}

func TestRunNoScannerRan(t *testing.T) {
	noScanner := Failure{RegistryName, ReasonNoScanner}
	tests := []struct {
		name string
		ss   []Scanner
		want []Failure
	}{
		{"empty", nil, []Failure{noScanner}},
		{"all unsupported", []Scanner{&fake{name: "a", unsupported: true}}, []Failure{noScanner}},
		{"all failing", []Scanner{&fake{name: "a", err: errors.New("x")}, &fake{name: "b", scanBad: panicString}},
			[]Failure{{"a", ReasonError}, {"b", ReasonPanic}, noScanner}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := run(t, tt.ss...)
			assertFailures(t, res, tt.want...)
			if res.Ran != 0 {
				t.Errorf("Ran = %d", res.Ran)
			}
		})
	}
}

func TestRunSizeCap(t *testing.T) {
	f := &fake{name: "a", findings: []finding.Finding{fnd("a", finding.SeverityLow)}}
	r := newReg(t, f)

	res := r.Run(context.Background(), art, make([]byte, MaxContentSize))
	if f.scans != 1 || res.Incomplete() || len(res.Findings) != 1 {
		t.Errorf("at cap: scans=%d result=%+v", f.scans, res)
	}

	res = r.Run(context.Background(), art, make([]byte, MaxContentSize+1))
	if f.scans != 1 || len(res.Findings) != 0 {
		t.Errorf("over cap: scans=%d findings=%d", f.scans, len(res.Findings))
	}
	assertFailures(t, res, Failure{RegistryName, ReasonTooLarge})
}

func TestRunInvalidArtifact(t *testing.T) {
	f := &fake{name: "a"}
	bad := art
	bad.Metadata = map[string]any{"k": func() {}}
	res := newReg(t, f).Run(context.Background(), bad, nil)
	if f.scans != 0 {
		t.Error("scanner ran for an invalid artifact")
	}
	assertFailures(t, res, Failure{RegistryName, ReasonInvalidArtifact})
}

func TestRunContext(t *testing.T) {
	t.Run("canceled before Run", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		a, b := &fake{name: "a"}, &fake{name: "b"}
		res := newReg(t, a, b).Run(ctx, art, nil)
		if a.scans+b.scans != 0 {
			t.Error("a scanner ran after cancel")
		}
		assertFailures(t, res, Failure{"a", ReasonCanceled}, Failure{"b", ReasonCanceled}, Failure{RegistryName, ReasonNoScanner})
	})

	t.Run("canceled inside the first scanner", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		a := &fake{name: "a", findings: []finding.Finding{fnd("a", finding.SeverityLow)},
			onScan: func(context.Context, []byte) { cancel() }}
		b, c := &fake{name: "b"}, &fake{name: "c"}
		res := newReg(t, a, b, c).Run(ctx, art, nil)
		if b.scans+c.scans != 0 {
			t.Error("a scanner ran after cancel")
		}
		assertFailures(t, res, Failure{"b", ReasonCanceled}, Failure{"c", ReasonCanceled})
		if res.Ran != 1 || len(res.Findings) != 1 {
			t.Errorf("ran=%d findings=%d", res.Ran, len(res.Findings))
		}
	})

	t.Run("error after cancel is canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		a := &fake{name: "a", err: errors.New("x"), onScan: func(context.Context, []byte) { cancel() }}
		res := newReg(t, a).Run(ctx, art, nil)
		assertFailures(t, res, Failure{"a", ReasonCanceled}, Failure{RegistryName, ReasonNoScanner})
	})
}

// stringsOf collects every string reachable from v, so tests can prove a
// canary is absent from a Result.
func stringsOf(v reflect.Value, out *[]string) {
	switch v.Kind() {
	case reflect.String:
		*out = append(*out, v.String())
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			stringsOf(v.Index(i), out)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			stringsOf(v.Field(i), out)
		}
	}
}

func assertNoCanary(t *testing.T, res Result, canary string) {
	t.Helper()
	var all []string
	stringsOf(reflect.ValueOf(res), &all)
	for _, s := range all {
		if strings.Contains(s, canary) {
			t.Errorf("canary %q found in result string %q", canary, s)
		}
	}
}

func TestRunReturnedErrorIsIsolated(t *testing.T) {
	canary := "canary-" + strings.Repeat("e", 8)
	bad := &fake{name: "bad", err: errors.New(canary), findings: []finding.Finding{fnd("lost", finding.SeverityHigh)}}
	good := &fake{name: "good", findings: []finding.Finding{fnd("kept", finding.SeverityLow)}}
	res := run(t, bad, good)
	assertFailures(t, res, Failure{"bad", ReasonError})
	if got := ids(res.Findings); !reflect.DeepEqual(got, []string{"kept"}) {
		t.Errorf("findings = %v", got)
	}
	assertNoCanary(t, res, canary)
}

func TestRunPanicIsolation(t *testing.T) {
	modes := map[string]panicMode{"panic string": panicString, "panic nil": panicNil, "panic error": panicError, "goexit": goexit}
	for name, mode := range modes {
		for _, where := range []string{"Supports", "Scan"} {
			t.Run(name+" in "+where, func(t *testing.T) {
				bad := &fake{name: "bad", findings: []finding.Finding{fnd("lost", finding.SeverityHigh)}}
				if where == "Supports" {
					bad.supportsBad = mode
				} else {
					bad.scanBad = mode
				}
				good := &fake{name: "good", findings: []finding.Finding{fnd("kept", finding.SeverityLow)}}
				res := run(t, bad, good)
				assertFailures(t, res, Failure{"bad", ReasonPanic})
				if where == "Supports" && bad.scans != 0 {
					t.Error("Scan called after Supports panicked")
				}
				if good.scans != 1 || !reflect.DeepEqual(ids(res.Findings), []string{"kept"}) || res.Ran != 1 {
					t.Errorf("following scanner: scans=%d result=%+v", good.scans, res)
				}
				assertNoCanary(t, res, "canary")
			})
		}
	}
}

func TestRunDropsInvalidFindingsOneByOne(t *testing.T) {
	badSeverity := fnd("bad1", finding.SeverityInvalid)
	otherArtifact := fnd("bad2", finding.SeverityHigh)
	otherArtifact.ArtifactID = "file-2"
	s := &fake{name: "s", findings: []finding.Finding{badSeverity, fnd("kept", finding.SeverityLow), otherArtifact}}
	res := run(t, s)
	assertFailures(t, res, Failure{"s", ReasonInvalidFinding}) // once for two bad findings
	if got := ids(res.Findings); !reflect.DeepEqual(got, []string{"kept"}) {
		t.Errorf("findings = %v", got)
	}
}

func TestRunSortIsDeterministic(t *testing.T) {
	mk := func(id string, sev finding.Severity, file string, line int) finding.Finding {
		f := fnd(id, sev)
		f.File, f.Line = file, line
		return f
	}
	a := &fake{name: "a", findings: []finding.Finding{
		mk("z", finding.SeverityLow, "f", 1),
		mk("b", finding.SeverityCritical, "g", 2),
		mk("a", finding.SeverityLow, "f", 1),
	}}
	b := &fake{name: "b", findings: []finding.Finding{
		mk("c", finding.SeverityLow, "e", 9),
		mk("d", finding.SeverityLow, "f", 0),
		mk("e", finding.SeverityHigh, "a", 1),
	}}
	want := []string{"b", "e", "c", "d", "a", "z"}
	for i := 0; i < 50; i++ {
		first, second := run(t, a, b), run(t, b, a)
		if !reflect.DeepEqual(first.Findings, second.Findings) {
			t.Fatalf("run %d: order depends on registry order", i)
		}
		if got := ids(first.Findings); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d: order = %v, want %v", i, got, want)
		}
	}
}

func TestSortFindingsKeys(t *testing.T) {
	base := fnd("x", finding.SeverityLow)
	vary := func(mod func(*finding.Finding)) finding.Finding { f := base; mod(&f); return f }
	// Each element must sort before the next, differing in one key only.
	ordered := []finding.Finding{
		vary(func(f *finding.Finding) { f.Severity = finding.SeverityHigh }),
		base,
		vary(func(f *finding.Finding) { f.File = "b" }),
		vary(func(f *finding.Finding) { f.File, f.Line = "b", 2 }),
		vary(func(f *finding.Finding) { f.File, f.Line, f.ID = "b", 2, "y" }),
		vary(func(f *finding.Finding) { f.File, f.Line, f.ID, f.Category = "b", 2, "y", "c" }),
		vary(func(f *finding.Finding) { f.File, f.Line, f.ID, f.Category, f.Title = "b", 2, "y", "c", "u" }),
		vary(func(f *finding.Finding) {
			f.File, f.Line, f.ID, f.Category, f.Title, f.Evidence = "b", 2, "y", "c", "u", "e"
		}),
	}
	shuffled := make([]finding.Finding, len(ordered))
	for i, f := range ordered {
		shuffled[len(ordered)-1-i] = f
	}
	sortFindings(shuffled)
	if !reflect.DeepEqual(shuffled, ordered) {
		t.Errorf("sort keys out of order:\n got %+v\nwant %+v", shuffled, ordered)
	}
}
