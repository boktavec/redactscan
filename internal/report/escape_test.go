package report

import (
	"encoding/json"
	"testing"
	"unicode/utf8"
)

// noDangerous fails if b has an invalid byte or a dangerous rune other than
// the newlines the renderers write.
func noDangerous(t *testing.T, label string, b []byte) {
	t.Helper()
	if !utf8.Valid(b) {
		t.Fatalf("%s: invalid UTF-8 in %q", label, b)
	}
	for _, r := range string(b) {
		if r != '\n' && isDangerous(r) {
			t.Fatalf("%s: dangerous rune %U in %q", label, r, b)
		}
	}
}

func TestAppendText(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in, want string }{
		{"plain", "curl -s https://[HOST_1]/i.sh é", "curl -s https://[HOST_1]/i.sh é"},
		{"ANSI CSI", "x\x1b[31m", `x\x1b[31m`},
		{"8-bit CSI", "\u009b", `\u009b`},
		{"DEL and NEL", "\x7f\u0085", `\x7f\u0085`},
		{"bidi", "\u202e\u2066", `\u202e\u2066`},
		{"zero width and BOM", "\u200b\ufeff", `\u200b\ufeff`},
		{"separator and tag", "\u2028\U000e0041", `\u2028\U000e0041`},
		{"invisible fillers", "\u034f\u3164\u17b4", `\u034f\u3164\u17b4`},
		{"selectors", "\ufe0f\U000e0100", `\ufe0f\U000e0100`},
		{"newline and CR", "a\r\nb", `a\r\nb`},
		{"backslash", `a\x1b`, `a\\x1b`},
		{"quote unchanged", `a"b`, `a"b`},
		{"invalid byte vs real U+FFFD", "\xff\ufffd", `\xff` + "\ufffd"},
		{"truncated sequence", "\xe2\x82", `\xe2\x82`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := appendText(nil, tt.in)
			if string(got) != tt.want {
				t.Errorf("appendText(%q) = %q, want %q", tt.in, got, tt.want)
			}
			noDangerous(t, tt.name, got)
		})
	}
}

func TestAppendQuotedText(t *testing.T) {
	t.Parallel()
	if got, want := string(appendQuotedText(nil, "a\"b\\\x1b")), `"a\"b\\\x1b"`; got != want {
		t.Errorf("appendQuotedText = %s, want %s", got, want)
	}
}

// TestEveryRuneIsNeutralised pins both renderers' escaping for every Unicode
// scalar value, so a toolchain table change shows up here.
func TestEveryRuneIsNeutralised(t *testing.T) {
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		s := "a" + string(r) + "b"
		noDangerous(t, "text", appendText(nil, s))

		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		out, err := escapeJSON(raw)
		if err != nil {
			t.Fatalf("U+%04X: %v", r, err)
		}
		noDangerous(t, "json", out)
		var back string
		if err := json.Unmarshal(out, &back); err != nil || back != s {
			t.Fatalf("U+%04X: round trip = %q, %v", r, back, err)
		}
	}
}

func TestEscapeJSONRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()
	out, err := escapeJSON([]byte("{\"a\":\"\xff\"}"))
	if err != ErrRender || out != nil {
		t.Errorf("escapeJSON = %q, %v; want nil, ErrRender", out, err)
	}
}

// TestAstralBoundaryRunes pins the surrogate-pair arithmetic and the printable
// astral pass-through in both renderers.
func TestAstralBoundaryRunes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		r        rune
		wantText string
		wantJSON string
	}{
		{"variation selector U+E0100", 0xe0100, `\U000e0100`, `\udb40\udd00`},
		{"language tag U+E0001", 0xe0001, `\U000e0001`, `\udb40\udc01`},
		{"last code point U+10FFFF", 0x10ffff, `\U0010ffff`, `\udbff\udfff`},
		{"printable U+10000 stays raw", 0x10000, "\U00010000", "\U00010000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := "a" + string(tt.r) + "b"
			if got, want := string(appendText(nil, s)), "a"+tt.wantText+"b"; got != want {
				t.Errorf("appendText = %q, want %q", got, want)
			}
			raw, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			out, err := escapeJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			if want := `"a` + tt.wantJSON + `b"`; string(out) != want {
				t.Errorf("escapeJSON = %s, want %s", out, want)
			}
		})
	}
}
