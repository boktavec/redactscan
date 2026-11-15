package report

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// allowedImports is the FR9 allowlist. fmt, os, net and log are absent on
// purpose: widening it takes a reviewed edit.
var allowedImports = []string{
	"bytes", "encoding/json", "errors", "io", "math", "slices", "strconv", "unicode/utf8",
	"github.com/boktavec/redactscan/internal/finding",
	"github.com/boktavec/redactscan/internal/scanner",
	"github.com/boktavec/redactscan/internal/textsafe",
}

func disallowedImports(t *testing.T, filename string, src any) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filename, src, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(allowedImports, path) {
			bad = append(bad, path)
		}
	}
	return bad
}

func TestPackageImportsAreAllowed(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		if bad := disallowedImports(t, path, nil); len(bad) > 0 {
			t.Errorf("%s imports %q outside the allowlist", path, bad)
		}
	}
}

func TestDisallowedImportsDetectsFmt(t *testing.T) {
	got := disallowedImports(t, "x.go", "package x\nimport (\"fmt\"; \"io\"; \"os\")")
	if want := []string{"fmt", "os"}; !slices.Equal(got, want) {
		t.Errorf("disallowed = %q, want %q", got, want)
	}
}
