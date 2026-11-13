//go:build darwin || linux

package quarantine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Read tests swap package seams, so none of them run in parallel.

const payload = "payload\x00\xff bytes"

func newEntry(t *testing.T) (s *Store, entryDir, id string) {
	t.Helper()
	base := newBase(t)
	s = openStore(t, base)
	id, err := s.Put(src(t, payload), validInput())
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return s, filepath.Join(qdirOf(base), id), id
}

// both runs fn for Read and Verify: they share the entry and metadata checks.
func both(t *testing.T, fn func(t *testing.T, op func(*Store, string) error)) {
	t.Helper()
	ops := map[string]func(*Store, string) error{
		"Read":   func(s *Store, id string) error { _, err := s.Read(id); return err },
		"Verify": func(s *Store, id string) error { return s.Verify(id) },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) { fn(t, op) })
	}
}

func chmod(t *testing.T, path string, m fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, m); err != nil {
		t.Fatal(err)
	}
}

func rewrite(t *testing.T, path string, mod func([]byte) []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, mod(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func replaceIn(old, new string) func([]byte) []byte {
	return func(b []byte) []byte { return bytes.Replace(b, []byte(old), []byte(new), 1) }
}

// flipAfter changes the hex digit off bytes after the first occurrence of
// key, keeping the value well-formed so only the consistency check can fail.
func flipAfter(key string, off int) func([]byte) []byte {
	return func(b []byte) []byte {
		i := bytes.Index(b, []byte(key)) + len(key) + off
		if b[i] == 'f' {
			b[i] = '0'
		} else {
			b[i] = 'f'
		}
		return b
	}
}

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// nonOwnerAfter makes geteuid report a foreign user from call number n on.
func nonOwnerAfter(t *testing.T, n int) {
	t.Helper()
	calls := 0
	swap(t, &geteuid, func() int {
		calls++
		if calls >= n {
			return os.Geteuid() + 1
		}
		return os.Geteuid()
	})
}

func TestReadReturnsPutMetadata(t *testing.T) {
	s, _, id := newEntry(t)
	m, err := s.Read(id)
	if err != nil {
		t.Fatal(err)
	}
	want := validInput()
	sum := sha256.Sum256([]byte(payload))
	if m.ID != id || m.SHA256 != hex.EncodeToString(sum[:]) || m.Size != int64(len(payload)) ||
		m.SchemaVersion != SchemaVersion || m.Name != want.Name || m.Decision != want.Decision ||
		m.Source != want.Source || len(m.Findings) != 1 || m.Findings[0].ID != want.Findings[0].ID {
		t.Errorf("metadata = %+v", m)
	}
	if err := s.Verify(id); err != nil {
		t.Errorf("Verify of an untouched entry: %v", err)
	}
}

// A closed store fails every filesystem call, so an invalid ID that still
// reports ErrInvalidID proves no filesystem call was made (FR8).
func TestInvalidIDMakesNoFilesystemCall(t *testing.T) {
	s, _, id := newEntry(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	both(t, func(t *testing.T, op func(*Store, string) error) {
		if err := op(s, id); err == nil || errors.Is(err, ErrInvalidID) {
			t.Fatalf("control: a valid id on a closed store must reach the filesystem, got %v", err)
		}
		for _, bad := range []string{"", "../x", "/abs", "a/b", strings.ToUpper(id), id[:len(id)-1], id + "0", id + "\n", id + "\x00", ".", "..", id[:64]} {
			if err := op(s, bad); !errors.Is(err, ErrInvalidID) {
				t.Errorf("id %q: err = %v, want ErrInvalidID", bad, err)
			}
		}
	})
}

func TestReadVerifyNotFound(t *testing.T) {
	s, _, id := newEntry(t)
	other := id[:idHashLen+1] + strings.Repeat("0", idSuffixLen)
	both(t, func(t *testing.T, op func(*Store, string) error) {
		if err := op(s, other); !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
}

func TestReadVerifyRefuseUnsafeEntryDirNeverRepair(t *testing.T) {
	for _, m := range []fs.FileMode{0o750, 0o755, 0o701, 0o300, fs.ModeSticky | 0o700, fs.ModeSetgid | 0o700, fs.ModeSetuid | 0o700} {
		both(t, func(t *testing.T, op func(*Store, string) error) {
			s, dir, id := newEntry(t)
			chmod(t, dir, m)
			if err := op(s, id); !errors.Is(err, ErrUnsafeDir) {
				t.Errorf("mode %v: err = %v, want ErrUnsafeDir", m, err)
			}
			if got := mode(t, dir); got&permBits != m&permBits {
				t.Errorf("mode %v was repaired to %v", m, got)
			}
			chmod(t, dir, 0o700) // let t.TempDir clean up
		})
	}
}

func TestReadVerifyRefuseEntrySymlinkOrFile(t *testing.T) {
	both(t, func(t *testing.T, op func(*Store, string) error) {
		s, dir, id := newEntry(t)
		moved := dir + ".real"
		if err := os.Rename(dir, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, dir); err != nil {
			t.Fatal(err)
		}
		if err := op(s, id); !errors.Is(err, ErrUnsafeDir) {
			t.Errorf("symlink: err = %v", err)
		}
		_ = os.Remove(dir)
		if err := os.WriteFile(dir, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := op(s, id); !errors.Is(err, ErrUnsafeDir) {
			t.Errorf("regular file: err = %v", err)
		}
	})
}

func TestReadVerifyRefuseForeignOwnerEntryDir(t *testing.T) {
	both(t, func(t *testing.T, op func(*Store, string) error) {
		s, _, id := newEntry(t)
		nonOwnerAfter(t, 1)
		if err := op(s, id); !errors.Is(err, ErrUnsafeDir) {
			t.Errorf("err = %v, want ErrUnsafeDir", err)
		}
	})
}

func TestReadVerifyMapEntrySwapToUnsafeDir(t *testing.T) {
	both(t, func(t *testing.T, op func(*Store, string) error) {
		s, dir, id := newEntry(t)
		swap(t, &afterDirLstat, func(name string) {
			if name != id {
				return
			}
			if err := os.Rename(dir, dir+".real"); err != nil {
				t.Error(err)
			}
			if err := os.Symlink(dir+".real", dir); err != nil {
				t.Error(err)
			}
		})
		if err := op(s, id); !errors.Is(err, ErrUnsafeDir) {
			t.Errorf("err = %v, want ErrUnsafeDir", err)
		}
	})
}

func TestReadVerifyMissingMetadataIsIncomplete(t *testing.T) {
	both(t, func(t *testing.T, op func(*Store, string) error) {
		s, dir, id := newEntry(t)
		if err := os.Remove(filepath.Join(dir, metadataName)); err != nil {
			t.Fatal(err)
		}
		if err := op(s, id); !errors.Is(err, ErrIncomplete) {
			t.Errorf("err = %v, want ErrIncomplete", err)
		}
	})
}

func TestReadContentChecksAreIncomplete(t *testing.T) {
	tests := map[string]func(t *testing.T, content string){
		"missing":   func(t *testing.T, c string) { _ = os.Remove(c) },
		"mode 0644": func(t *testing.T, c string) { chmod(t, c, 0o644) },
		"mode 0400": func(t *testing.T, c string) { chmod(t, c, 0o400) },
		"mode 4600": func(t *testing.T, c string) { chmod(t, c, fs.ModeSetuid|0o600) },
		"truncated": func(t *testing.T, c string) { rewrite(t, c, func(b []byte) []byte { return b[:len(b)-1] }) },
		"extended":  func(t *testing.T, c string) { rewrite(t, c, func(b []byte) []byte { return append(b, 'x') }) },
		"symlink": func(t *testing.T, c string) {
			_ = os.Remove(c)
			if err := os.Symlink(filepath.Join(filepath.Dir(c), metadataName), c); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, c string) { _ = os.Remove(c); mkfifo(t, c) },
		"directory": func(t *testing.T, c string) {
			_ = os.Remove(c)
			if err := os.Mkdir(c, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			s, dir, id := newEntry(t)
			corrupt(t, filepath.Join(dir, contentName))
			m, err := s.Read(id)
			if !errors.Is(err, ErrIncomplete) {
				t.Errorf("err = %v, want ErrIncomplete", err)
			}
			if m.ID != "" {
				t.Error("Read returned metadata alongside an error")
			}
		})
	}
}

func TestReadRefusesForeignOwnerContent(t *testing.T) {
	s, _, id := newEntry(t)
	nonOwnerAfter(t, 2) // call 1 is the entry directory
	if _, err := s.Read(id); !errors.Is(err, ErrIncomplete) {
		t.Errorf("err = %v, want ErrIncomplete", err)
	}
}

func TestReadVerifyCorruptMetadata(t *testing.T) {
	tests := map[string]func(t *testing.T, meta string){
		"truncated":      func(t *testing.T, p string) { rewrite(t, p, func(b []byte) []byte { return b[:len(b)/2] }) },
		"trailing data":  func(t *testing.T, p string) { rewrite(t, p, func(b []byte) []byte { return append(b, "{}"...) }) },
		"unknown member": func(t *testing.T, p string) { rewrite(t, p, replaceIn(`"name"`, `"extra":1,"name"`)) },
		"duplicate": func(t *testing.T, p string) {
			rewrite(t, p, replaceIn(`"decision":"block"`, `"decision":"block","decision":"review"`))
		},
		"case variant":   func(t *testing.T, p string) { rewrite(t, p, replaceIn(`"decision"`, `"Decision"`)) },
		"version 2":      func(t *testing.T, p string) { rewrite(t, p, replaceIn(`"schema_version":1`, `"schema_version":2`)) },
		"decision allow": func(t *testing.T, p string) { rewrite(t, p, replaceIn(`"block"`, `"allow"`)) },
		"id mismatch":    func(t *testing.T, p string) { rewrite(t, p, flipAfter(`"id":"`, idHashLen+1)) },
		"sha mismatch":   func(t *testing.T, p string) { rewrite(t, p, flipAfter(`"sha256":"`, 0)) },
		"mode 0644":      func(t *testing.T, p string) { chmod(t, p, 0o644) },
		"mode 0400":      func(t *testing.T, p string) { chmod(t, p, 0o400) },
		"mode setuid":    func(t *testing.T, p string) { chmod(t, p, fs.ModeSetuid|0o600) },
		"empty":          func(t *testing.T, p string) { rewrite(t, p, func([]byte) []byte { return nil }) },
		"over cap": func(t *testing.T, p string) {
			rewrite(t, p, func([]byte) []byte { return make([]byte, MaxMetadataBytes+1) })
		},
		"fifo":      func(t *testing.T, p string) { _ = os.Remove(p); mkfifo(t, p) },
		"directory": func(t *testing.T, p string) { _ = os.Remove(p); _ = os.Mkdir(p, 0o700) },
		"symlink to self": func(t *testing.T, p string) {
			_ = os.Remove(p)
			_ = os.Symlink(filepath.Join(filepath.Dir(p), contentName), p)
		},
	}
	for name, corrupt := range tests {
		both(t, func(t *testing.T, op func(*Store, string) error) {
			s, dir, id := newEntry(t)
			corrupt(t, filepath.Join(dir, metadataName))
			done := make(chan error, 1)
			go func() { done <- op(s, id) }() // a FIFO must not block
			select {
			case err := <-done:
				if !errors.Is(err, ErrCorruptMetadata) {
					t.Errorf("%s: err = %v, want ErrCorruptMetadata", name, err)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: blocked", name)
			}
		})
	}
}

func TestReadMetadataExactlyAtCapIsDecodedNotRefusedBySize(t *testing.T) {
	s, dir, id := newEntry(t)
	// Valid JSON padded with trailing whitespace to exactly the cap: size is
	// accepted, and the strict decoder (not the size check) decides.
	rewrite(t, filepath.Join(dir, metadataName), func(b []byte) []byte {
		return append(b, bytes.Repeat([]byte(" "), MaxMetadataBytes-len(b))...)
	})
	if _, err := s.Read(id); err != nil {
		t.Errorf("metadata of exactly MaxMetadataBytes: %v", err)
	}
}

func TestVerifyDetectsContentTampering(t *testing.T) {
	tests := map[string]func(t *testing.T, content string){
		"flip one byte": func(t *testing.T, c string) {
			rewrite(t, c, func(b []byte) []byte { b[0] ^= 1; return b })
		},
		"append one byte": func(t *testing.T, c string) { rewrite(t, c, func(b []byte) []byte { return append(b, 0) }) },
		"truncate":        func(t *testing.T, c string) { rewrite(t, c, func(b []byte) []byte { return b[:len(b)-1] }) },
		"missing":         func(t *testing.T, c string) { _ = os.Remove(c) },
		"mode 0644":       func(t *testing.T, c string) { chmod(t, c, 0o644) },
	}
	for name, tamper := range tests {
		t.Run(name, func(t *testing.T) {
			s, dir, id := newEntry(t)
			tamper(t, filepath.Join(dir, contentName))
			if err := s.Verify(id); !errors.Is(err, ErrVerifyFailed) {
				t.Errorf("err = %v, want ErrVerifyFailed", err)
			}
		})
	}
}

func TestVerifyRefusesForeignOwnerContent(t *testing.T) {
	s, _, id := newEntry(t)
	nonOwnerAfter(t, 2) // call 1 is the entry directory
	if err := s.Verify(id); !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("err = %v, want ErrVerifyFailed", err)
	}
}

// Content swapped after the metadata was accepted: every substitute is
// refused without blocking (mirrors safefs TestOpenChildDirDetectsSwap).
func TestVerifyDetectsContentSwap(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(t *testing.T, dir string){
		"fifo":            func(t *testing.T, d string) { mkfifo(t, filepath.Join(d, contentName)) },
		"symlink outside": func(t *testing.T, d string) { symlink(t, outside, filepath.Join(d, contentName)) },
		"in-root symlink": func(t *testing.T, d string) { symlink(t, metadataName, filepath.Join(d, contentName)) },
		"other regular file": func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, contentName), strings.ToUpper(payload), 0o600)
		},
		"same bytes mode 644": func(t *testing.T, d string) { writeFile(t, filepath.Join(d, contentName), payload, 0o644) },
		"directory":           func(t *testing.T, d string) { _ = os.Mkdir(filepath.Join(d, contentName), 0o700) },
	}
	for name, replace := range tests {
		t.Run(name, func(t *testing.T) {
			s, dir, id := newEntry(t)
			swap(t, &afterMetadataRead, func() {
				_ = os.Remove(filepath.Join(dir, contentName))
				replace(t, dir)
			})
			done := make(chan error, 1)
			go func() { done <- s.Verify(id) }()
			select {
			case err := <-done:
				if !errors.Is(err, ErrVerifyFailed) {
					t.Errorf("err = %v, want ErrVerifyFailed", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Verify blocked")
			}
		})
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, data string, perm fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), perm); err != nil {
		t.Fatal(err)
	}
	chmod(t, path, perm)
}

// FR21: marker in the store path, no path or OS text in any Read/Verify error.
func TestReadVerifyErrorTextHasNoPathOrMarker(t *testing.T) {
	base := filepath.Join(t.TempDir(), marker)
	s := openStore(t, base)
	id, err := s.Put(src(t, payload), validInput())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(qdirOf(base), id)
	meta, content := filepath.Join(dir, metadataName), filepath.Join(dir, contentName)
	origMeta, _ := os.ReadFile(meta)
	reset := func() {
		_ = os.RemoveAll(meta)
		_ = os.RemoveAll(content)
		chmod(t, dir, 0o700)
		writeFile(t, meta, string(origMeta), 0o600)
		writeFile(t, content, payload, 0o600)
	}
	tests := map[string]struct {
		prep func(t *testing.T)
		id   func() string
		want error
	}{
		"invalid id":     {id: func() string { return "../" + marker }, want: ErrInvalidID},
		"not found":      {id: func() string { return strings.Repeat("0", idHashLen) + "-" + strings.Repeat("0", idSuffixLen) }, want: ErrNotFound},
		"unsafe dir":     {prep: func(t *testing.T) { chmod(t, dir, 0o750) }, want: ErrUnsafeDir},
		"incomplete":     {prep: func(t *testing.T) { _ = os.Remove(meta) }, want: ErrIncomplete},
		"corrupt":        {prep: func(t *testing.T) { rewrite(t, meta, func(b []byte) []byte { return b[:5] }) }, want: ErrCorruptMetadata},
		"corrupt marker": {prep: func(t *testing.T) { rewrite(t, meta, replaceIn(`"decision":"block"`, `"decision":"`+marker+`"`)) }, want: ErrCorruptMetadata},
	}
	for name, tt := range tests {
		both(t, func(t *testing.T, op func(*Store, string) error) {
			reset()
			if tt.prep != nil {
				tt.prep(t)
			}
			use := id
			if tt.id != nil {
				use = tt.id()
			}
			err := op(s, use)
			if !errors.Is(err, tt.want) {
				t.Fatalf("%s: err = %v, want %v", name, err, tt.want)
			}
			assertSafeText(t, err)
			if strings.Contains(err.Error(), base) || errors.Unwrap(err) != nil {
				t.Errorf("%s: error text or chain leaks: %q", name, err)
			}
		})
	}
	reset()
	// Incomplete content and verification failures.
	chmod(t, content, 0o644)
	_, err = s.Read(id)
	assertSafeText(t, err)
	err = s.Verify(id)
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("Verify err = %v", err)
	}
	assertSafeText(t, err)
	if strings.Contains(err.Error(), id) {
		t.Errorf("error contains the id: %q", err)
	}
	reset()

	// Unreadable or tampered modes are state errors, not raw EACCES.
	chmod(t, meta, 0o000)
	for _, op := range []func() error{
		func() error { _, err := s.Read(id); return err },
		func() error { return s.Verify(id) },
	} {
		err := op()
		if !errors.Is(err, ErrCorruptMetadata) {
			t.Fatalf("metadata 0000: err = %v, want ErrCorruptMetadata", err)
		}
		assertSafeText(t, err)
	}
	reset()
	chmod(t, content, 0o000)
	err = s.Verify(id)
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("content 0000: err = %v, want ErrVerifyFailed", err)
	}
	assertSafeText(t, err)
	if _, err := s.Read(id); !errors.Is(err, ErrIncomplete) {
		t.Errorf("Read content 0000: err = %v, want ErrIncomplete", err)
	}
	reset()

	// A genuinely unexpected OS error keeps fixed text and a bare error.
	both(t, func(t *testing.T, op func(*Store, string) error) {
		closed := openStore(t, base)
		_ = closed.Close()
		err := op(closed, id)
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("closed store: err = %v", err)
		}
		assertSafeText(t, err)
		if errors.Unwrap(err) != os.ErrClosed {
			t.Errorf("Unwrap = %v, want bare os.ErrClosed", errors.Unwrap(err))
		}
	})
}

func TestMetadataModeStateErrorsWithoutRawErrno(t *testing.T) {
	both(t, func(t *testing.T, op func(*Store, string) error) {
		for _, m := range []fs.FileMode{0o000, 0o200} {
			s, dir, id := newEntry(t)
			chmod(t, filepath.Join(dir, metadataName), m)
			if err := op(s, id); !errors.Is(err, ErrCorruptMetadata) {
				t.Errorf("mode %v: err = %v, want ErrCorruptMetadata", m, err)
			}
		}
	})
}

// verifyContent reads with ReadAt from offset 0, so a descriptor whose offset
// has moved (or one a caller will copy from afterwards) still verifies, and
// the offset is left alone.
func TestVerifyContentIsOffsetIndependent(t *testing.T) {
	sum := sha256.Sum256([]byte(payload))
	m := Metadata{Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
	f := openSource(t, []byte(payload), 0o600)
	if _, err := f.Seek(5, 0); err != nil {
		t.Fatal(err)
	}
	if err := verifyContent(f, m); err != nil {
		t.Fatalf("advanced offset: %v", err)
	}
	if pos, _ := f.Seek(0, 1); pos != 5 {
		t.Errorf("offset moved to %d", pos)
	}
}

// With empty content a FIFO has the right size (0), so only the regular-file
// check can refuse it.
func TestReadRefusesFIFOWhereEmptyContentBelongs(t *testing.T) {
	base := newBase(t)
	s := openStore(t, base)
	id, err := s.Put(src(t, ""), validInput())
	if err != nil {
		t.Fatal(err)
	}
	content := filepath.Join(qdirOf(base), id, contentName)
	if err := os.Remove(content); err != nil {
		t.Fatal(err)
	}
	mkfifo(t, content)
	if _, err := s.Read(id); !errors.Is(err, ErrIncomplete) {
		t.Errorf("err = %v, want ErrIncomplete", err)
	}
}
