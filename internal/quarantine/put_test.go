//go:build darwin || linux

package quarantine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/scanner"
)

// Put tests swap package seams, so none of them run in parallel.

func swap[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

func validInput() Input {
	return Input{
		Source: artifact.SourceMetadata{Type: artifact.SourceDownload, URI: "https://example.com/tool.zip"},
		Name:   "tool.zip", Decision: Block, Findings: []finding.Finding{testFinding()},
	}
}

// openSource writes data to a temp file with the given mode and opens it.
func openSource(t *testing.T, data []byte, perm fs.FileMode) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func src(t *testing.T, data string) *os.File { return openSource(t, []byte(data), 0o600) }

func qdirOf(base string) string { return filepath.Join(base, dirQuarantine) }

// listing returns the sorted names under dir, recursively, as relative paths.
func listing(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != dir {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

func assertNothingCreated(t *testing.T, base string) {
	t.Helper()
	if l := listing(t, qdirOf(base)); len(l) != 0 {
		t.Errorf("quarantine not empty: %v", l)
	}
}

func put(t *testing.T, s *Store, data string) string {
	t.Helper()
	id, err := s.Put(src(t, data), validInput())
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return id
}

func TestPutStoresEntry(t *testing.T) {
	base := newBase(t)
	s := openStore(t, base)
	data := "payload\x00\xff bytes"
	id, err := s.Put(src(t, data), validInput())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(data))
	if !ValidID(id) || id[:idHashLen] != hex.EncodeToString(sum[:]) {
		t.Fatalf("id = %q, want sha256 prefix", id)
	}
	entry := filepath.Join(qdirOf(base), id)
	if got := listing(t, entry); !slices.Equal(got, []string{contentName, metadataName}) {
		t.Fatalf("entry files = %v", got)
	}
	if got, _ := os.ReadFile(filepath.Join(entry, contentName)); string(got) != data {
		t.Error("stored content differs from source")
	}
	if m := mode(t, entry); m&(permBits|fs.ModeDir) != 0o700|fs.ModeDir {
		t.Errorf("entry mode = %v", m)
	}
	for _, name := range []string{contentName, metadataName} {
		fi, err := os.Lstat(filepath.Join(entry, name))
		if err != nil || fi.Mode() != 0o600 || !ownedByEUID(fi) {
			t.Errorf("%s: mode/owner wrong (%v, %v)", name, fi, err)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(entry, metadataName))
	m, err := decodeMetadata(raw, id)
	if err != nil {
		t.Fatalf("stored metadata does not decode: %v", err)
	}
	if m.Size != int64(len(data)) || m.Name != "tool.zip" || m.Decision != Block || len(m.Findings) != 1 {
		t.Errorf("metadata = %+v", m)
	}
	if got := listing(t, qdirOf(base)); len(got) != 3 {
		t.Errorf("leftovers in quarantine: %v", got)
	}
}

func TestPutEmptySource(t *testing.T) {
	s := openStore(t, newBase(t))
	if id := put(t, s, ""); id[:idHashLen] != hex.EncodeToString(sha256.New().Sum(nil)) {
		t.Errorf("empty content hash prefix wrong: %s", id)
	}
}

func TestPutStripsSourceModeAndIgnoresUmask(t *testing.T) {
	for _, perm := range []fs.FileMode{0o755, 0o777 | fs.ModeSetuid, 0o755 | fs.ModeSetgid, 0o755 | fs.ModeSticky} {
		t.Run(perm.String(), func(t *testing.T) {
			base := newBase(t)
			s := openStore(t, base)
			in := openSource(t, []byte("x"), perm)
			withUmask(t, 0o277) // would leave 0400 files and 0500 directories without fchmod
			id, err := s.Put(in, validInput())
			if err != nil {
				t.Fatal(err)
			}
			entry := filepath.Join(qdirOf(base), id)
			if m := mode(t, entry); m&(permBits|fs.ModeDir) != 0o700|fs.ModeDir {
				t.Errorf("entry mode = %v", m)
			}
			for _, name := range []string{contentName, metadataName} {
				if m := mode(t, filepath.Join(entry, name)); m != 0o600 {
					t.Errorf("%s mode = %v, want -rw-------", name, m)
				}
			}
		})
	}
}

func TestPutTempFileIs0600(t *testing.T) {
	base := newBase(t)
	s := openStore(t, base)
	in := src(t, "x")
	withUmask(t, 0o277)
	swap(t, &afterStep, func(step string) error {
		if step != "copied" {
			return nil
		}
		for _, p := range listing(t, qdirOf(base)) {
			if m := mode(t, filepath.Join(qdirOf(base), p)); !strings.HasPrefix(p, tempPrefix) || m != 0o600 {
				t.Errorf("%s mode = %v, want a 0600 temp", p, m)
			}
		}
		return nil
	})
	if _, err := s.Put(in, validInput()); err != nil {
		t.Fatal(err)
	}
}

func TestPutSameContentTwiceGivesTwoEntries(t *testing.T) {
	s := openStore(t, newBase(t))
	a, b := put(t, s, "same"), put(t, s, "same")
	if a == b || a[:idHashLen] != b[:idHashLen] {
		t.Errorf("ids %s and %s: want distinct with the same hash prefix", a, b)
	}
}

func TestPutRefusesBeforeCreatingAnything(t *testing.T) {
	key := strings.Join([]string{"AK", "IA"}, "") + "IOSFODNN7EXAMPLE"
	dir := t.TempDir()
	notRegular, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = notRegular.Close() }()
	tests := []struct {
		name string
		opts Options
		src  *os.File
		mod  func(*Input)
		want error
	}{
		{"bad decision", Options{}, src(t, "x"), func(i *Input) { i.Decision = "allow" }, ErrInvalidInput},
		{"sensitive name", Options{}, src(t, "x"), func(i *Input) { i.Name = key }, ErrSensitiveInput},
		{"uri userinfo", Options{}, src(t, "x"), func(i *Input) { i.Source.URI = "https://u:p@h/x" }, ErrInvalidInput},
		{"nil source", Options{}, nil, func(*Input) {}, ErrInvalidInput},
		{"directory source", Options{}, notRegular, func(*Input) {}, ErrInvalidInput},
		{"over entry size", Options{MaxEntrySize: 3}, src(t, "four"), func(*Input) {}, ErrTooLarge},
		{"metadata too large", Options{}, src(t, "x"), func(i *Input) {
			f := testFinding()
			f.Title = strings.Repeat("\"", scanner.MaxTitleBytes)
			f.File = strings.Repeat("\\", scanner.MaxFileBytes)
			f.Description = strings.Repeat("\x1b", MaxDescriptionBytes)
			f.Evidence = strings.Repeat("\x00", finding.MaxEvidenceBytes)
			i.Findings = slices.Repeat([]finding.Finding{f}, scanner.MaxFindings)
		}, ErrMetadataTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := newBase(t)
			o := tt.opts
			o.AllowRoot = testOpts().AllowRoot
			s, err := Open(base, o)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			in := validInput()
			tt.mod(&in)
			// A refusal must precede the copy, not be undone by cleanup.
			swap(t, &afterStep, func(step string) error {
				t.Errorf("Put reached step %q before refusing", step)
				return nil
			})
			id, err := s.Put(tt.src, in)
			if !errors.Is(err, tt.want) || id != "" {
				t.Fatalf("Put = (%q, %v), want %v", id, err, tt.want)
			}
			assertNothingCreated(t, base)
		})
	}
}

func TestPutEntrySizeBoundary(t *testing.T) {
	s, err := Open(newBase(t), Options{MaxEntrySize: 4, AllowRoot: testOpts().AllowRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	put(t, s, "four")
	if _, err := s.Put(src(t, "fives"), validInput()); !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

// metaLen is the metadata.json size of validInput, measured on a scratch store.
func metaLen(t *testing.T) int64 {
	t.Helper()
	base := newBase(t)
	s := openStore(t, base)
	id := put(t, s, "x")
	fi, err := os.Lstat(filepath.Join(qdirOf(base), id, metadataName))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func TestPutBudget(t *testing.T) {
	m := metaLen(t)
	open := func(t *testing.T, o Options) (*Store, string) {
		base := newBase(t)
		o.AllowRoot = testOpts().AllowRoot
		s, err := Open(base, o)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s, base
	}
	full := func(t *testing.T, s *Store, base, data string) {
		t.Helper()
		before := listing(t, qdirOf(base))
		if _, err := s.Put(src(t, data), validInput()); !errors.Is(err, ErrStoreFull) {
			t.Fatalf("err = %v, want ErrStoreFull", err)
		}
		if after := listing(t, qdirOf(base)); !slices.Equal(before, after) {
			t.Errorf("store changed: %v -> %v", before, after)
		}
	}
	t.Run("entry count", func(t *testing.T) {
		s, base := open(t, Options{MaxEntries: 2})
		put(t, s, "a")
		put(t, s, "b")
		full(t, s, base, "c")
	})
	t.Run("bytes", func(t *testing.T) {
		s, base := open(t, Options{MaxStoreBytes: 10 + 2*m})
		put(t, s, "123456")
		full(t, s, base, "12345")
		put(t, s, "1234") // exactly the remaining budget, metadata included
	})
	t.Run("existing and incoming metadata count", func(t *testing.T) {
		// One byte short of "123456" plus "1234", both with metadata: refused
		// only if both the stored and the new metadata.json are counted.
		s, base := open(t, Options{MaxStoreBytes: 10 + 2*m - 1})
		put(t, s, "123456")
		full(t, s, base, "1234")
	})
	t.Run("orphan temp counts", func(t *testing.T) {
		// Without the orphan "123" fits exactly (3 + m <= 10 + m - 7).
		s, base := open(t, Options{MaxStoreBytes: 10 + m})
		orphan := filepath.Join(qdirOf(base), tempPrefix+"orphan")
		if err := os.WriteFile(orphan, []byte("12345678"), 0o600); err != nil {
			t.Fatal(err)
		}
		full(t, s, base, "123")
		if err := os.Remove(orphan); err != nil {
			t.Fatal(err)
		}
		put(t, s, "123")
	})
	t.Run("unknown names are ignored", func(t *testing.T) {
		s, base := open(t, Options{MaxEntries: 1, MaxStoreBytes: 2 + m + 50})
		if err := os.WriteFile(filepath.Join(qdirOf(base), "notes"), bytes.Repeat([]byte("x"), 100), 0o600); err != nil {
			t.Fatal(err)
		}
		put(t, s, "ok")
	})
	t.Run("incomplete entry counts as an entry", func(t *testing.T) {
		s, base := open(t, Options{MaxEntries: 1})
		if err := os.Mkdir(filepath.Join(qdirOf(base), testID), 0o700); err != nil {
			t.Fatal(err)
		}
		full(t, s, base, "x")
	})
	t.Run("more entries than one read batch", func(t *testing.T) {
		s, base := open(t, Options{MaxEntries: readdirBatch + 50})
		for i := range readdirBatch + 50 {
			name := strings.Repeat("0", idHashLen-4) + string(rune('a'+i%6)) + string(rune('a'+i/6%6)) + string(rune('a'+i/36%6)) + string(rune('a'+i/216%6)) + "-0000000000000000"
			if err := os.Mkdir(filepath.Join(qdirOf(base), name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		full(t, s, base, "x")
	})
}

func TestPutReadsSourceFromOffsetZero(t *testing.T) {
	base := newBase(t)
	s := openStore(t, base)
	f := src(t, "already scanned")
	if _, err := io.ReadAll(f); err != nil { // caller's scan advanced the offset
		t.Fatal(err)
	}
	id, err := s.Put(f, validInput())
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(qdirOf(base), id, contentName)); string(got) != "already scanned" {
		t.Errorf("stored content = %q", got)
	}
}

// appendOnFirstRead grows the real file behind r on disk through a separate
// O_APPEND handle at the first Read, then delegates unchanged.
type appendOnFirstRead struct {
	r    io.Reader
	path string
	add  int
	done bool
	t    *testing.T
}

func (a *appendOnFirstRead) Read(p []byte) (int, error) {
	if !a.done {
		a.done = true
		f, err := os.OpenFile(a.path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			a.t.Fatal(err)
		}
		_, err = f.Write(bytes.Repeat([]byte("x"), a.add))
		_ = f.Close()
		if err != nil {
			a.t.Fatal(err)
		}
	}
	return a.r.Read(p)
}

func TestPutSourceChangedRemovesTemp(t *testing.T) {
	shrink := func(r io.Reader) io.Reader { return io.LimitReader(r, 3) }
	check := func(t *testing.T, f *os.File) {
		base := newBase(t)
		s := openStore(t, base)
		if _, err := s.Put(f, validInput()); !errors.Is(err, ErrSourceChanged) {
			t.Fatalf("err = %v, want ErrSourceChanged", err)
		}
		assertNothingCreated(t, base)
	}
	t.Run("shrank", func(t *testing.T) {
		swap(t, &sourceReader, shrink)
		check(t, src(t, "12345"))
	})
	for _, add := range []int{1, 4096} {
		t.Run("real file grew "+strconv.Itoa(add), func(t *testing.T) {
			f := src(t, "12345")
			swap(t, &sourceReader, func(r io.Reader) io.Reader {
				return &appendOnFirstRead{r: r, path: f.Name(), add: add, t: t}
			})
			check(t, f)
		})
	}
}

func TestPutReadErrorRemovesTemp(t *testing.T) {
	base := newBase(t)
	s := openStore(t, base)
	swap(t, &sourceReader, func(io.Reader) io.Reader {
		return errReader{&fs.PathError{Op: "read", Path: marker, Err: syscall.EIO}}
	})
	_, err := s.Put(src(t, "12345"), validInput())
	assertSafePutError(t, err, syscall.EIO)
	assertNothingCreated(t, base)
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// seqSuffix makes randSuffix return the queued values, then real random ones.
func seqSuffix(t *testing.T, vals ...string) {
	t.Helper()
	real := randSuffix
	swap(t, &randSuffix, func() string {
		if len(vals) == 0 {
			return real()
		}
		v := vals[0]
		vals = vals[1:]
		return v
	})
}

const (
	suffixA = "aaaaaaaaaaaaaaaa"
	suffixB = "bbbbbbbbbbbbbbbb"
	suffixC = "cccccccccccccccc"
)

func TestPutRetriesIDCollision(t *testing.T) {
	base := newBase(t)
	s := openStore(t, base)
	// Put 1: temp, id. Put 2: temp, colliding id, then a free one.
	seqSuffix(t, suffixA, suffixA, suffixB, suffixA, suffixC)
	first := put(t, s, "same")
	second := put(t, s, "same")
	if !strings.HasSuffix(first, "-"+suffixA) || !strings.HasSuffix(second, "-"+suffixC) {
		t.Errorf("ids = %s, %s", first, second)
	}
}

func TestPutIDExhaustedLeavesNoStrayFiles(t *testing.T) {
	base := newBase(t)
	s := openStore(t, base)
	seqSuffix(t, suffixA, suffixA) // temp, id
	put(t, s, "same")
	content := filepath.Join(qdirOf(base), firstEntry(t, qdirOf(base)), contentName)
	before := listing(t, qdirOf(base))
	// temp, then every id try collides with the first entry.
	seqSuffix(t, append([]string{suffixB}, slices.Repeat([]string{suffixA}, maxNameTries)...)...)
	if _, err := s.Put(src(t, "same"), validInput()); !errors.Is(err, ErrIDExhausted) {
		t.Fatalf("err = %v, want ErrIDExhausted", err)
	}
	if after := listing(t, qdirOf(base)); !slices.Equal(before, after) {
		t.Errorf("stray files: %v -> %v", before, after)
	}
	if got, _ := os.ReadFile(content); string(got) != "same" {
		t.Error("existing entry modified")
	}
}

func TestPutTempNameExhaustionKeepsExistingFile(t *testing.T) {
	base := newBase(t)
	s := openStore(t, base)
	planted := filepath.Join(qdirOf(base), tempPrefix+suffixA)
	if err := os.WriteFile(planted, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	swap(t, &randSuffix, func() string { return suffixA })
	if _, err := s.Put(src(t, "x"), validInput()); !errors.Is(err, ErrIDExhausted) {
		t.Fatalf("err = %v, want ErrIDExhausted", err)
	}
	if got, _ := os.ReadFile(planted); string(got) != "planted" {
		t.Error("pre-existing temp file was modified")
	}
}

// TestPutNeverReplacesPlantedFiles pins the no-replace Link behaviour (run on
// darwin and in the non-root Linux container): a content or metadata.json
// that appears in the entry directory is refused and left byte for byte.
func TestPutNeverReplacesPlantedFiles(t *testing.T) {
	for _, target := range []struct{ name, step string }{
		{contentName, "reserved"},
		{metadataName, "content-placed"},
	} {
		t.Run(target.name, func(t *testing.T) {
			base := newBase(t)
			s := openStore(t, base)
			var planted string
			swap(t, &afterStep, func(step string) error {
				if step == target.step {
					l := listing(t, qdirOf(base))
					for _, p := range l {
						if ValidID(p) {
							planted = filepath.Join(qdirOf(base), p, target.name)
						}
					}
					return os.WriteFile(planted, []byte("planted"), 0o600)
				}
				return nil
			})
			if _, err := s.Put(src(t, "real"), validInput()); !errors.Is(err, ErrEntryExists) {
				t.Fatalf("err = %v, want ErrEntryExists", err)
			}
			if got, _ := os.ReadFile(planted); string(got) != "planted" {
				t.Errorf("planted %s modified: %q", target.name, got)
			}
			var left []string
			for _, p := range listing(t, qdirOf(base)) {
				if !ValidID(p) {
					left = append(left, filepath.Base(p))
				}
			}
			if !slices.Equal(left, []string{target.name}) {
				t.Errorf("leftovers = %v, want only the planted %s", left, target.name)
			}
		})
	}
}

var putSteps = []string{"copied", "reserved", "content-placed", "metadata-written", "published"}

func TestPutStepOrder(t *testing.T) {
	s := openStore(t, newBase(t))
	var got []string
	swap(t, &afterStep, func(step string) error { got = append(got, step); return nil })
	put(t, s, "x")
	if !slices.Equal(got, putSteps) {
		t.Errorf("steps = %v, want %v", got, putSteps)
	}
}

// TestPutFailureAtEveryStepLeavesNoEntry simulates an OS failure after each
// step: no entry with metadata.json may remain and, since cleanup works here,
// nothing at all.
func TestPutFailureAtEveryStepLeavesNoEntry(t *testing.T) {
	for _, failAt := range putSteps {
		t.Run(failAt, func(t *testing.T) {
			base := newBase(t)
			s := openStore(t, base)
			swap(t, &afterStep, func(step string) error {
				if step == failAt {
					return &fs.PathError{Op: "x", Path: marker, Err: syscall.EIO}
				}
				return nil
			})
			id, err := s.Put(src(t, "x"), validInput())
			if id != "" {
				t.Errorf("id = %q on failure", id)
			}
			assertSafePutError(t, err, syscall.EIO)
			assertNothingCreated(t, base)
		})
	}
}

// assertSafePutError is the FR21 check: fixed text, no marker, and the OS
// error is a bare Errno.
func assertSafePutError(t *testing.T, err error, want syscall.Errno) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error")
	}
	assertSafeText(t, err)
	if !errors.Is(err, want) {
		t.Errorf("error %v does not unwrap to %v", err, want)
	}
	if un := errors.Unwrap(err); un != want {
		t.Errorf("Unwrap = %#v, want bare %v", un, want)
	}
}

func assertSafeText(t *testing.T, err error) {
	t.Helper()
	var pe *fs.PathError
	var le *os.LinkError
	if errors.As(err, &pe) || errors.As(err, &le) || strings.Contains(err.Error(), marker) ||
		strings.Contains(err.Error(), os.TempDir()) {
		t.Errorf("unsafe error text or chain: %q", err.Error())
	}
}

// TestPutErrorTextHasNoContent covers every non-OS failure path with the
// marker in every untrusted string and in the store path (FR21).
func TestPutErrorTextHasNoContent(t *testing.T) {
	base := filepath.Join(t.TempDir(), marker)
	s, err := Open(base, Options{MaxEntries: 1, AllowRoot: testOpts().AllowRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	marked := func(mod func(*Input)) Input {
		in := validInput()
		in.Name, in.Source.URI = marker, "https://"+marker+".example/"+marker
		in.Findings[0].Title, in.Findings[0].File = marker, marker
		mod(&in)
		return in
	}
	tests := map[string]struct {
		in   Input
		data string
		pre  func(*testing.T)
	}{
		"invalid":   {in: marked(func(i *Input) { i.Decision = "allow" })},
		"sensitive": {in: marked(func(i *Input) { i.Name = marker + strings.Join([]string{"AK", "IA"}, "") + "IOSFODNN7EXAMPLE" })},
		"too large": {in: marked(func(*Input) {}), pre: func(t *testing.T) { s.opts.MaxEntrySize = 1 }, data: "xx"},
		"too big metadata": {in: marked(func(i *Input) {
			f := i.Findings[0]
			f.Title = strings.Repeat("\"", scanner.MaxTitleBytes)
			f.File = strings.Repeat("\\", scanner.MaxFileBytes)
			f.Description = strings.Repeat("\x1b", MaxDescriptionBytes)
			f.Evidence = strings.Repeat("\x00", finding.MaxEvidenceBytes)
			i.Findings = slices.Repeat([]finding.Finding{f}, scanner.MaxFindings)
		})},
		"changed": {in: marked(func(*Input) {}), pre: func(t *testing.T) {
			swap(t, &sourceReader, func(r io.Reader) io.Reader { return io.LimitReader(r, 1) })
		}, data: "xx"},
		"exists": {in: marked(func(*Input) {}), pre: func(t *testing.T) {
			swap(t, &afterStep, func(step string) error {
				if step == "reserved" {
					return os.WriteFile(filepath.Join(qdirOf(base), firstEntry(t, qdirOf(base)), contentName), nil, 0o600)
				}
				return nil
			})
		}},
		"exhausted": {in: marked(func(*Input) {}), pre: func(t *testing.T) {
			swap(t, &randSuffix, func() string { return suffixA })
			_ = os.WriteFile(filepath.Join(qdirOf(base), tempPrefix+suffixA), nil, 0o600)
		}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s.opts.MaxEntrySize = DefaultMaxEntrySize
			if tt.pre != nil {
				tt.pre(t)
			}
			data := tt.data
			if data == "" {
				data = "x"
			}
			_, err := s.Put(src(t, data), tt.in)
			if err == nil {
				t.Fatal("want an error")
			}
			assertSafeText(t, err)
			if strings.Contains(err.Error(), base) {
				t.Errorf("error contains the base path: %q", err)
			}
			// Clean the store for the next case: entries and temps.
			ents, _ := os.ReadDir(qdirOf(base))
			for _, e := range ents {
				_ = os.RemoveAll(filepath.Join(qdirOf(base), e.Name()))
			}
		})
	}
	t.Run("store full", func(t *testing.T) {
		put(t, s, "a")
		_, err := s.Put(src(t, "b"), marked(func(*Input) {}))
		if !errors.Is(err, ErrStoreFull) {
			t.Fatalf("err = %v", err)
		}
		assertSafeText(t, err)
	})
}

func firstEntry(t *testing.T, dir string) string {
	t.Helper()
	for _, p := range listing(t, dir) {
		if ValidID(p) {
			return p
		}
	}
	t.Fatal("no entry directory")
	return ""
}
