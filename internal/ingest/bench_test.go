//go:build darwin || linux

package ingest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkWalk10kFiles reports allocations for a 10,000-file tree; divide by
// 10,000 for the cost per Artifact.
func BenchmarkWalk10kFiles(b *testing.B) {
	root, err := filepath.EvalSymlinks(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	for i := range 10_000 {
		dir := filepath.Join(root, fmt.Sprintf("d%02d", i%100))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%05d", i)), nil, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		res, err := Walk(root, Limits{})
		if err != nil || len(res.Artifacts) != 10_000 {
			b.Fatalf("err = %v, artifacts = %d", err, len(res.Artifacts))
		}
	}
}

// BenchmarkWalkLongPaths walks 1,000 files whose Path is the longest accepted
// (1015 bytes), the per-Artifact worst case.
func BenchmarkWalkLongPaths(b *testing.B) {
	root, err := filepath.EvalSymlinks(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		b.Fatal(err)
	}
	remaining := maxPath - (len(root) + 1)
	for remaining > 255 { // leave a file name of at most 255 bytes
		dir := strings.Repeat("d", 100)
		if err := r.Mkdir(dir, 0o700); err != nil {
			b.Fatal(err)
		}
		next, err := r.OpenRoot(dir)
		if err != nil {
			b.Fatal(err)
		}
		_ = r.Close()
		r = next
		remaining -= len(dir) + 1
	}
	for i := range 1000 {
		f, err := r.Create(fmt.Sprintf("%04d", i) + strings.Repeat("f", remaining-4))
		if err != nil {
			b.Fatal(err)
		}
		_ = f.Close()
	}
	_ = r.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		res, err := Walk(root, Limits{})
		if err != nil || len(res.Artifacts) != 1000 || len(res.Artifacts[0].Path) != maxPath {
			b.Fatalf("err = %v, artifacts = %d", err, len(res.Artifacts))
		}
	}
}
