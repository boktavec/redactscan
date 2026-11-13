package scanner

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// allowedImports is the FR21 allowlist. Widening it takes a reviewed edit.
var allowedImports = []string{
	"cmp", "context", "errors", "fmt", "io", "slices", "sort", "strings", "unicode/utf8",
	"github.com/boktavec/redactscan/internal/artifact",
	"github.com/boktavec/redactscan/internal/finding",
	"github.com/boktavec/redactscan/internal/redactor",
}

const forbiddenNote = "explicitly forbidden: os, os/exec, syscall, net and net/..., plugin, unsafe, log and log/..., internal/safefs"

// disallowedImports parses src and returns its imports outside the allowlist.
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
	visited := map[string]bool{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (path == "scannertest" || path == "builtin") {
			return filepath.SkipDir // builtin has its own allowlist test; match the exact paths
		}
		if d.IsDir() {
			return nil
		}
		if foreignSource(path) {
			t.Errorf("%s: only Go source is allowed (assembly, cgo and similar files bypass the import check)", path)
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		visited[path] = true
		if bad := disallowedImports(t, path, nil); len(bad) > 0 {
			t.Errorf("%s imports %q outside the allowlist; %s", path, bad, forbiddenNote)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"scanner.go", "run.go", "registry.go", "check.go"} {
		if !visited[want] {
			t.Errorf("%s was not checked", want)
		}
	}
}

// foreignSource reports whether path is a compiled or linked source file that
// is not Go, which the import allowlist cannot see.
func foreignSource(path string) bool {
	return slices.Contains([]string{".s", ".S", ".syso", ".c", ".h", ".cc", ".cpp", ".cxx", ".m", ".f", ".swig"}, filepath.Ext(path))
}

func TestForeignSourceIsDetected(t *testing.T) {
	for _, name := range []string{"x.s", "x.S", "x.syso", "x.c", "x.h", "x.cc", "x.cpp", "x.cxx", "x.m", "x.f", "x.swig"} {
		if !foreignSource(name) {
			t.Errorf("%s not detected", name)
		}
	}
	if foreignSource("x.go") || foreignSource("x_test.go") {
		t.Error("Go source flagged")
	}
}

func TestDisallowedImportsDetectsBadImports(t *testing.T) {
	const src = `package x
import (
	"fmt"
	"os"
	"os/exec"
	"net/http"
	"github.com/boktavec/redactscan/internal/safefs"
)`
	got := disallowedImports(t, "x.go", src)
	want := []string{"os", "os/exec", "net/http", "github.com/boktavec/redactscan/internal/safefs"}
	if !slices.Equal(got, want) {
		t.Errorf("disallowed = %q, want %q", got, want)
	}
}
