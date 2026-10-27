//go:build darwin || linux

package logs

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/boktavec/redactscan/internal/safefs"
)

// rotate renames path to path+suffix and creates a fresh file at path.
func rotate(t *testing.T, path, suffix, content string) {
	t.Helper()
	if err := os.Rename(path, path+suffix); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, content)
}

// appendTo is appendFile for goroutines other than the test's.
func appendTo(path, content string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(content)
	return errors.Join(werr, f.Close())
}

// setAfterRotationDetected installs the seam for the test's duration.
func setAfterRotationDetected(t *testing.T, fn func()) {
	t.Helper()
	orig := afterRotationDetected
	afterRotationDetected = fn
	t.Cleanup(func() { afterRotationDetected = orig })
}

func TestRotationDeliversBothFilesInOrderWithoutDuplicates(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "old1\n")
	s := startRead(t, newSource(t, path), Query{FromStart: true})
	s.wantLine("old1")

	appendFile(t, path, "old2\n")
	rotate(t, path, ".1", "new1\n")
	s.wantLine("old2")
	s.wantLine("new1")

	appendFile(t, path, "new2\n")
	s.wantLine("new2")
	appendFile(t, path, "new3\n")
	s.wantLine("new3")

	rotate(t, path, ".2", "third1\n") // a second rotation works too
	s.wantLine("third1")
	appendFile(t, path, "third2\n")
	s.wantLine("third2")
}

func TestRotationCutsPendingPartialLineWithMarker(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "one\nhalf")
	s := startRead(t, newSource(t, path), Query{FromStart: true})
	s.wantLine("one")

	rotate(t, path, ".1", "new\n")

	s.wantMarker(int64(len("half")))
	s.wantLine("new")
}

func TestRotationDrainIsBoundedBySizeAtDetection(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "one\n")
	var mu sync.Mutex
	calls := 0
	real := fstat
	fstat = func(f *os.File) (fs.FileInfo, error) {
		st, err := real(f)
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 2 { // the first tick: the file is rotated just after its size was read
			if err := errors.Join(
				appendTo(path, "late\n"),
				os.Rename(path, path+".1"),
				os.WriteFile(path, []byte("sentinel\n"), 0o600),
			); err != nil {
				t.Error(err)
			}
		}
		return st, err
	}
	t.Cleanup(func() { fstat = real })
	s := startRead(t, newSource(t, path), Query{FromStart: true})

	s.wantLine("one")
	s.wantLine("sentinel") // "late" arriving first would fail here
}

func TestRotationPathRemovedKeepsReadingHeldFile(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "one\n")
	writer, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()
	s := startRead(t, newSource(t, path), Query{FromStart: true})
	s.wantLine("one")

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString("after removal\n"); err != nil {
		t.Fatal(err)
	}

	s.wantLine("after removal")
}

func TestRotationWaitsWhenPathVanishesDuringReopen(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "one\n")
	detected := make(chan struct{})
	var once sync.Once
	setAfterRotationDetected(t, func() {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		once.Do(func() { close(detected) })
	})
	s := startRead(t, newSource(t, path), Query{FromStart: true})
	s.wantLine("one")

	rotate(t, path, ".1", "placeholder\n")
	<-detected // the source now has no descriptor and the path is gone
	writeFile(t, path, "later\n")

	s.wantLine("later")
}

// swapAtRotation rotates the file and, between detection and reopen, replaces
// what is at path with whatever swap creates. It returns the final error.
func swapAtRotation(t *testing.T, path string, swap func()) error {
	t.Helper()
	writeFile(t, path, "one\n")
	setAfterRotationDetected(t, func() {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		swap()
	})
	fds, routines := openFDs(t), goroutines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := newSource(t, path).Read(ctx, Query{FromStart: true})
	if err != nil {
		t.Fatal(err)
	}
	s := &stream{t: t, ch: ch}
	s.wantLine("one")

	rotate(t, path, ".1", "placeholder\n")
	got := s.wantErrThenClose()

	assertNoErrorLeaks(t, got, path, "app")
	assertNoLeaks(t, fds, routines)
	return got
}

func TestRotationRefusesHostileReplacement(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "app.log")
	other := filepath.Join(dir, "other.log")
	writeFile(t, other, markerString+"\n")

	tests := []struct {
		name string
		swap func()
		want error
	}{
		{"symlink", func() { mustNil(t, os.Symlink(other, path)) }, safefs.ErrSymlink},
		{"fifo", func() { mustNil(t, syscall.Mkfifo(path, 0o600)) }, safefs.ErrNotRegular},
		{"directory", func() { mustNil(t, os.Mkdir(path, 0o700)) }, safefs.ErrNotRegular},
		{"hard link to another file", func() { mustNil(t, os.Link(other, path)) }, ErrReopenRefused},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.RemoveAll(path)
			_ = os.Remove(path + ".1")
			if got := swapAtRotation(t, path, tc.swap); !errors.Is(got, tc.want) {
				t.Errorf("err = %v, want %v", got, tc.want)
			}
		})
	}
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Error(err)
	}
}

// otherOwner reports a different uid than the real file has.
type otherOwner struct{ fs.FileInfo }

func (o otherOwner) Sys() any {
	st := *o.FileInfo.Sys().(*syscall.Stat_t)
	st.Uid++
	return &st
}

func TestRotationRefusesFileWithDifferentOwner(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "one\n")
	var detected atomic.Bool
	setAfterRotationDetected(t, func() { detected.Store(true) })
	real := fstat
	// A different owner cannot be created without root, so the reopened file's
	// stat is faked.
	fstat = func(f *os.File) (fs.FileInfo, error) {
		st, err := real(f)
		if err == nil && detected.Load() {
			return otherOwner{st}, nil
		}
		return st, err
	}
	t.Cleanup(func() { fstat = real })
	fds, routines := openFDs(t), goroutines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := newSource(t, path).Read(ctx, Query{FromStart: true})
	if err != nil {
		t.Fatal(err)
	}
	s := &stream{t: t, ch: ch}
	s.wantLine("one")

	rotate(t, path, ".1", markerString+"\n")
	got := s.wantErrThenClose()

	if !errors.Is(got, ErrReopenRefused) {
		t.Errorf("err = %v, want ErrReopenRefused", got)
	}
	assertNoErrorLeaks(t, got, path, "app")
	assertNoLeaks(t, fds, routines)
}

func TestRotationFailsClosedOnLstatError(t *testing.T) {
	dir := tempDir(t)
	sub := filepath.Join(dir, "sub")
	mustNil(t, os.Mkdir(sub, 0o700))
	path := filepath.Join(sub, "app.log")
	writeFile(t, path, "one\n")
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	fds, routines := openFDs(t), goroutines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := newSource(t, path).Read(ctx, Query{FromStart: true})
	if err != nil {
		t.Fatal(err)
	}
	s := &stream{t: t, ch: ch}
	s.wantLine("one")

	if err := os.Chmod(sub, 0); err != nil { // Lstat now fails with EACCES
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })
	got := s.wantErrThenClose()

	if !errors.Is(got, fs.ErrPermission) {
		t.Errorf("err = %v, want a permission error", got)
	}
	assertNoErrorLeaks(t, got, path, "app")
	assertNoLeaks(t, fds, routines)
}
