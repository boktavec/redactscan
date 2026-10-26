package finding

import (
	"errors"
	"math"
	"strings"
	"testing"
)

var (
	validSeverities   = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	invalidSeverities = []Severity{SeverityInvalid, -1, 6, 99, math.MinInt, math.MaxInt}
)

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func TestSeverityConstants(t *testing.T) {
	t.Parallel()
	want := map[Severity]int{SeverityInvalid: 0, SeverityInfo: 1, SeverityLow: 2, SeverityMedium: 3, SeverityHigh: 4, SeverityCritical: 5}
	for s, n := range want {
		if int(s) != n {
			t.Errorf("%v = %d, want %d", s, int(s), n)
		}
	}
}

func TestSeverityValid(t *testing.T) {
	t.Parallel()
	for _, s := range validSeverities {
		if !s.Valid() {
			t.Errorf("Severity(%d).Valid() = false", int(s))
		}
	}
	for _, s := range invalidSeverities {
		if s.Valid() {
			t.Errorf("Severity(%d).Valid() = true", int(s))
		}
	}
}

func TestSeverityString(t *testing.T) {
	t.Parallel()
	want := map[Severity]string{SeverityInfo: "info", SeverityLow: "low", SeverityMedium: "medium", SeverityHigh: "high", SeverityCritical: "critical"}
	for s, name := range want {
		if got := s.String(); got != name {
			t.Errorf("Severity(%d).String() = %q, want %q", int(s), got, name)
		}
		if got, err := ParseSeverity(s.String()); err != nil || got != s {
			t.Errorf("round trip %q = %v, %v", name, got, err)
		}
	}
	for _, s := range invalidSeverities {
		if got := s.String(); got != "invalid" {
			t.Errorf("Severity(%d).String() = %q, want invalid", int(s), got)
		}
	}
}

func TestSeverityCompare(t *testing.T) {
	t.Parallel()
	for _, a := range validSeverities {
		for _, b := range validSeverities {
			if got, want := a.Compare(b), sign(int(a)-int(b)); got != want {
				t.Errorf("%v.Compare(%v) = %d, want %d", a, b, got, want)
			}
		}
	}
	for _, inv := range invalidSeverities {
		for _, v := range validSeverities {
			if got := inv.Compare(v); got != 1 {
				t.Errorf("Severity(%d).Compare(%v) = %d, want 1", int(inv), v, got)
			}
			if got := v.Compare(inv); got != -1 {
				t.Errorf("%v.Compare(Severity(%d)) = %d, want -1", v, int(inv), got)
			}
		}
		for _, other := range invalidSeverities {
			if got := inv.Compare(other); got != 0 {
				t.Errorf("Severity(%d).Compare(Severity(%d)) = %d, want 0", int(inv), int(other), got)
			}
		}
	}
	if got := SeverityCritical.Compare(SeverityInvalid); got != -1 {
		t.Errorf("Critical.Compare(Invalid) = %d, want -1", got)
	}
}

func TestSeverityAtMostAtLeast(t *testing.T) {
	t.Parallel()
	for _, s := range validSeverities {
		for _, limit := range validSeverities {
			if got, want := s.AtMost(limit), s <= limit; got != want {
				t.Errorf("%v.AtMost(%v) = %v, want %v", s, limit, got, want)
			}
			if got, want := s.AtLeast(limit), s >= limit; got != want {
				t.Errorf("%v.AtLeast(%v) = %v, want %v", s, limit, got, want)
			}
		}
	}
	if SeverityCritical.AtMost(SeverityInvalid) {
		t.Error("Critical.AtMost(Invalid) = true, want false")
	}
	if !SeverityInfo.AtLeast(SeverityInvalid) {
		t.Error("Info.AtLeast(Invalid) = false, want true")
	}

	all := append(append([]Severity{}, validSeverities...), invalidSeverities...)
	for _, s := range invalidSeverities {
		for _, limit := range all {
			if s.AtMost(limit) {
				t.Errorf("Severity(%d).AtMost(Severity(%d)) = true, want false", int(s), int(limit))
			}
			if !s.AtLeast(limit) {
				t.Errorf("Severity(%d).AtLeast(Severity(%d)) = false, want true", int(s), int(limit))
			}
		}
	}
	for _, s := range validSeverities {
		for _, limit := range invalidSeverities {
			if s.AtMost(limit) {
				t.Errorf("%v.AtMost(Severity(%d)) = true, want false", s, int(limit))
			}
			if !s.AtLeast(limit) {
				t.Errorf("%v.AtLeast(Severity(%d)) = false, want true", s, int(limit))
			}
		}
	}
}

func TestParseSeverityAccepts(t *testing.T) {
	t.Parallel()
	for _, s := range validSeverities {
		name := s.String()
		inputs := []string{
			name,
			strings.ToUpper(name),
			strings.ToUpper(name[:1]) + name[1:],
			" " + name,
			name + " ",
			"\t" + name + "\n",
			" \t\r\n\v\f" + name + "\f\v\n\r\t ",
		}
		for _, in := range inputs {
			got, err := ParseSeverity(in)
			if err != nil || got != s {
				t.Errorf("ParseSeverity(%q) = %v, %v; want %v", in, got, err, s)
			}
		}
	}
	if got, err := ParseSeverity(" High\n"); err != nil || got != SeverityHigh {
		t.Errorf("ParseSeverity(\" High\\n\") = %v, %v", got, err)
	}
}

func TestParseSeverityRejects(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"empty":            "",
		"whitespace only":  " \t\n",
		"invalid name":     "invalid",
		"unknown":          "unknown",
		"prefix":           "crit",
		"digit zero":       "0",
		"digit three":      "3",
		"inner space":      "hi gh",
		"trailing NUL":     "high\x00",
		"invalid UTF-8":    "\xff",
		"dotted capital I": "HİGH",
		"leading NBSP":     "\u00a0high",
		"trailing NBSP":    "high\u00a0",
		"full-width":       "ｈｉｇｈ",
		"65 bytes":         strings.Repeat("a", 65),
	}
	for name, in := range tests {
		got, err := ParseSeverity(in)
		if got != SeverityInvalid {
			t.Errorf("%s: got %v, want SeverityInvalid", name, got)
		}
		if !errors.Is(err, ErrInvalidSeverity) {
			t.Errorf("%s: err = %v, want ErrInvalidSeverity", name, err)
		}
	}
}

func TestParseSeverityLengthCap(t *testing.T) {
	t.Parallel()
	// Padding is trimmed before the cap applies; the name itself is short.
	if got, err := ParseSeverity(strings.Repeat(" ", 100) + "high"); err != nil || got != SeverityHigh {
		t.Errorf("padded input = %v, %v", got, err)
	}
	if _, err := ParseSeverity(strings.Repeat("a", 64)); !errors.Is(err, ErrInvalidSeverity) {
		t.Errorf("64 bytes of junk = %v, want ErrInvalidSeverity", err)
	}
}

func TestParseSeverityErrorIsBounded(t *testing.T) {
	t.Parallel()
	_, err := ParseSeverity(strings.Repeat("x", 10*1024))
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if len(msg) >= 100 {
		t.Errorf("error is %d bytes, want < 100", len(msg))
	}
	want := `finding: invalid severity "` + strings.Repeat("x", 32) + `"...`
	if msg != want {
		t.Errorf("error = %q, want %q", msg, want)
	}

	_, err = ParseSeverity("a\x1b[31mb")
	if err == nil || strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("ESC must be escaped in error, got %q", err)
	}
	if !strings.Contains(err.Error(), `\x1b`) {
		t.Errorf("error %q lacks escaped ESC", err)
	}

	_, err = ParseSeverity("nope")
	if err == nil || err.Error() != `finding: invalid severity "nope"` {
		t.Errorf("short input error = %v", err)
	}

	// The error quotes the raw input, not the trimmed form.
	_, err = ParseSeverity(" nope\t")
	if err == nil || err.Error() != `finding: invalid severity " nope\t"` {
		t.Errorf("padded input error = %v", err)
	}
}
