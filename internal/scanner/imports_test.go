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
	"cmp", "context", "errors", "fmt", "slices", "sort", "strings", "unicode/utf8",
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
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "scannertest" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if bad := disallowedImports(t, path, nil); len(bad) > 0 {
			t.Errorf("%s imports %q outside the allowlist; %s", path, bad, forbiddenNote)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
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
