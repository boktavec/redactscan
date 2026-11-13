package builtin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/scanner"
	"github.com/boktavec/redactscan/internal/scanner/scannertest"
)

// newArtifact gives Path and RelativePath different values, so a scanner that
// uses the wrong one is caught.
func newArtifact(name string, size int64) artifact.Artifact {
	return artifact.Artifact{ID: "file-1", Path: "/abs/dir/" + name, RelativePath: name, Name: name, Size: size}
}

func runWith(t *testing.T, reg func() (*scanner.Registry, error), a artifact.Artifact, r io.ReaderAt, size int64) scanner.Result {
	t.Helper()
	reg1, err := reg()
	if err != nil {
		t.Fatal(err)
	}
	return reg1.Run(context.Background(), a, r, size)
}

// runHash runs only the hash scanner; runAll runs the production registry.
func runHash(t *testing.T, a artifact.Artifact, r io.ReaderAt, size int64) scanner.Result {
	t.Helper()
	return runWith(t, func() (*scanner.Registry, error) { return scanner.NewRegistry(Hash{}) }, a, r, size)
}

func runAll(t *testing.T, a artifact.Artifact, r io.ReaderAt, size int64) scanner.Result {
	t.Helper()
	return runWith(t, Default, a, r, size)
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestHashVectors(t *testing.T) {
	tests := []struct{ name, content, want string }{
		{"empty", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runHash(t, newArtifact("f.bin", int64(len(tt.content))), strings.NewReader(tt.content), int64(len(tt.content)))
			if res.Incomplete() || len(res.Findings) != 1 {
				t.Fatalf("result = %+v", res)
			}
			f := res.Findings[0]
			if f.ID != "hash.sha256" || f.Severity != finding.SeverityInfo || f.Category != "hash" ||
				f.ArtifactID != "file-1" || f.File != "f.bin" {
				t.Errorf("finding = %+v", f)
			}
			if got := f.Metadata["sha256"]; got != tt.want || !sha256Pattern.MatchString(got.(string)) {
				t.Errorf("sha256 = %v, want %s", got, tt.want)
			}
			if got, ok := f.Metadata["size"].(int64); !ok || got != int64(len(tt.content)) {
				t.Errorf("size = %#v, want int64(%d)", f.Metadata["size"], len(tt.content))
			}
		})
	}
}

// TestHashChunkBoundaries covers sizes around the 64 KiB buffer.
func TestHashChunkBoundaries(t *testing.T) {
	for _, n := range []int{1, hashChunkSize - 1, hashChunkSize, hashChunkSize + 1, 3*hashChunkSize + 7} {
		content := bytes.Repeat([]byte("xyz"), n/3+1)[:n]
		res := runHash(t, newArtifact("f", int64(n)), bytes.NewReader(content), int64(n))
		if res.Incomplete() || res.Findings[0].Metadata["sha256"] != sum(content) {
			t.Errorf("n=%d: result = %+v", n, res)
		}
	}
}

func TestHashOnlyReadsSizeBytes(t *testing.T) {
	// The reader holds more than size bytes; only the first size are hashed.
	res := runHash(t, newArtifact("f", 3), strings.NewReader("abcdef"), 3)
	if got := res.Findings[0].Metadata["sha256"]; got != sum([]byte("abc")) {
		t.Errorf("sha256 = %v", got)
	}
}

// TestHashFailsClosedWhenContentIsShort covers a file truncated during the
// scan and sysfs-style files whose fstat size exceeds their content.
func TestHashFailsClosedWhenContentIsShort(t *testing.T) {
	for _, tt := range []struct {
		name          string
		have, claimed int
	}{
		{"truncated in the first chunk", 10, 100},
		{"truncated after a full chunk", hashChunkSize + 5, 2 * hashChunkSize},
		{"empty but claimed non-empty", 0, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := runHash(t, newArtifact("f", int64(tt.claimed)), bytes.NewReader(make([]byte, tt.have)), int64(tt.claimed))
			if len(res.Findings) != 0 || !res.Incomplete() || res.Failures[0] != (scanner.Failure{Scanner: "hash", Reason: scanner.ReasonError}) {
				t.Errorf("result = %+v", res)
			}
		})
	}
}

func TestHashHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reg, err := scanner.NewRegistry(Hash{})
	if err != nil {
		t.Fatal(err)
	}
	r := scannertest.NewReader([]byte("abc"))
	res := reg.Run(ctx, newArtifact("f", 3), r, 3)
	if len(res.Failures) == 0 || res.Failures[0] != (scanner.Failure{Scanner: "hash", Reason: scanner.ReasonCanceled}) || r.Calls() != 0 {
		t.Errorf("result = %+v, reads = %d", res, r.Calls())
	}
}

// TestHashCancelBetweenChunks cancels while the first chunk is read.
func TestHashCancelBetweenChunks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &cancelReader{cancel: cancel, size: 3 * hashChunkSize}
	_, err := Hash{}.Scan(ctx, newArtifact("f", r.size), r, r.size)
	if err == nil || r.calls != 1 {
		t.Errorf("err = %v after %d reads, want an error after 1", err, r.calls)
	}
}

type cancelReader struct {
	cancel context.CancelFunc
	size   int64
	calls  int
}

func (c *cancelReader) ReadAt(p []byte, _ int64) (int, error) {
	c.calls++
	c.cancel()
	return len(p), nil
}

func TestHashScannerContract(t *testing.T) {
	content := []byte("some content")
	scannertest.AssertNoMutation(t, Hash{}, newArtifact("f", int64(len(content))), content)
}

// TestHashFindingTextIsConstant runs hostile names through Registry.Run.
func TestHashFindingTextIsConstant(t *testing.T) {
	names := []string{
		"plain.txt",
		"a\x1b[31mred\x1b[0m",
		"rtl" + string(rune(0x202e)) + "fdp.exe",
		"[GITHUB_TOKEN_1]",
		"\xff\xfe",
	}
	for _, name := range names {
		res := runHash(t, newArtifact(name, 3), strings.NewReader("abc"), 3)
		for _, f := range res.Findings {
			if f.Title != hashTitle || f.Description != hashDescription || f.Category != hashCategory {
				t.Errorf("name %q: finding text varies: %+v", name, f)
			}
		}
	}
}

// TestHashSecretShapedPathFailsClosed: the registry drops a finding whose File
// looks like a secret, so the scan is incomplete and no digest is reported.
func TestHashSecretShapedPathFailsClosed(t *testing.T) {
	name := "gh" + "p_" + strings.Repeat("A", 36) // built at runtime
	res := runHash(t, newArtifact(name, 3), strings.NewReader("abc"), 3)
	if len(res.Findings) != 0 || len(res.Failures) != 1 ||
		res.Failures[0] != (scanner.Failure{Scanner: "hash", Reason: scanner.ReasonInvalidFinding}) {
		t.Errorf("result = %+v", res)
	}
}

// sparseFile returns an os.File of the given size without writing content.
func sparseFile(t *testing.T, size int64) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "sparse.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Truncate(size); err != nil {
		t.Skipf("file system cannot make a sparse file: %v", err)
	}
	return f
}

// totalAlloc returns the bytes allocated while fn runs. Tests that use it
// must not run in parallel.
func totalAlloc(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestHashLargeFileIsHashedWithoutBufferingIt(t *testing.T) {
	if testing.Short() {
		t.Skip("hashes 512 MiB")
	}
	const small, large = 1 << 20, 512 << 20
	var smallRes, largeRes scanner.Result
	sf, lf := sparseFile(t, small), sparseFile(t, large)
	smallAlloc := totalAlloc(func() { smallRes = runHash(t, newArtifact("s", small), sf, small) })
	largeAlloc := totalAlloc(func() { largeRes = runHash(t, newArtifact("l", large), lf, large) })

	ref := sha256.New()
	if _, err := io.Copy(ref, io.NewSectionReader(lf, 0, large)); err != nil {
		t.Fatal(err)
	}
	if got, want := largeRes.Findings[0].Metadata["sha256"], hex.EncodeToString(ref.Sum(nil)); got != want {
		t.Errorf("sha256 = %v, want %s", got, want)
	}
	if smallRes.Incomplete() || largeRes.Incomplete() {
		t.Fatalf("incomplete: %v %v", smallRes.Failures, largeRes.Failures)
	}
	// Memory must not grow with size: 512x the input, same allocations.
	if largeAlloc > smallAlloc+(256<<10) {
		t.Errorf("allocated %d bytes for 512 MiB but %d for 1 MiB", largeAlloc, smallAlloc)
	}
}

func BenchmarkHash(b *testing.B) {
	const size = 64 << 20
	content := make([]byte, size)
	a := newArtifact("f", size)
	r := bytes.NewReader(content)
	b.SetBytes(size)
	for b.Loop() {
		if _, err := (Hash{}).Scan(context.Background(), a, r, size); err != nil {
			b.Fatal(err)
		}
	}
}
