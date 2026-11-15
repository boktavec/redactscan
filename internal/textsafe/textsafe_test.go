package textsafe

import (
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

func TestIsDangerous(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    rune
		want bool
	}{
		{"letter", 'a', false},
		{"printable non-ASCII", 'é', false},
		{"Kelvin sign", 0x212A, false}, // printable: not this rule's job
		{"Cyrillic homoglyph", 0x0445, false},
		{"space", ' ', false},
		{"NUL", 0, true},
		{"ESC", 0x1b, true},
		{"newline", '\n', true},
		{"DEL", 0x7f, true},
		{"C1 CSI", 0x9b, true},
		{"NEL", 0x85, true},
		{"bidi override", 0x202e, true},
		{"bidi isolate", 0x2066, true},
		{"zero width space", 0x200b, true},
		{"BOM", 0xfeff, true},
		{"line separator", 0x2028, true},
		{"tag character", 0xe0041, true},
		{"combining grapheme joiner", 0x034f, true},
		{"hangul filler", 0x3164, true},
		{"khmer inherent vowel", 0x17b4, true},
		{"variation selector 16", 0xfe0f, true},
		{"variation selector supplement", 0xe0100, true},
		{"non-ASCII space", 0x00a0, true},
		{"unassigned", 0x0378, true},
	}
	for _, tt := range tests {
		if got := IsDangerous(tt.r); got != tt.want {
			t.Errorf("IsDangerous(%U) = %v, want %v (%s)", tt.r, got, tt.want, tt.name)
		}
	}
}

// TestImportsArePure keeps the package to pure computation.
func TestImportsArePure(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "textsafe.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if path != "strconv" && path != "unicode" {
			t.Errorf("imports %q", path)
		}
	}
}
