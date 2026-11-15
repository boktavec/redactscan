package builtin

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

// allowedImports is the allowlist for non-test files. It deliberately lacks
// os, os/exec, syscall, io/fs, net, plugin, unsafe, reflect, log, debug/*,
// archive/*, compress/* and internal/safefs: scanners parse untrusted bytes and
// must not touch the filesystem. Later scanners widen it by a reviewed edit.
var allowedImports = []string{
	"context", "crypto/sha256", "encoding/binary", "encoding/hex", "errors", "io", "strings", "unicode/utf8",
	"github.com/boktavec/redactscan/internal/artifact",
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
	visited := map[string]bool{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if foreignSource(path) {
			t.Errorf("%s: only Go source is allowed (assembly, cgo and similar files bypass the import check)", path)
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		visited[path] = true
		if bad := disallowedImports(t, path, nil); len(bad) > 0 {
			t.Errorf("%s imports %q outside the allowlist", path, bad)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"hash.go", "read.go", "builtin.go"} {
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
	"context"
	"os"
	"io/fs"
	"syscall"
	"unsafe"
	"reflect"
	"debug/elf"
	"github.com/boktavec/redactscan/internal/safefs"
)`
	got := disallowedImports(t, "x.go", src)
	want := []string{"os", "io/fs", "syscall", "unsafe", "reflect", "debug/elf", "github.com/boktavec/redactscan/internal/safefs"}
	if !slices.Equal(got, want) {
		t.Errorf("disallowed = %q, want %q", got, want)
	}
}
