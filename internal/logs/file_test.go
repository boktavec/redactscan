//go:build darwin || linux

package logs

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/boktavec/redactscan/internal/safefs"
)

func TestReadStartsAtEndOfFileByDefault(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "old one\nold two\n")
	s := startRead(t, newSource(t, path), Query{})

	appendFile(t, path, "new\n")

	s.wantLine("new")
}

func TestReadFromStartEmitsExistingLines(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "one\ntwo\n\nthree\r\n")
	s := startRead(t, newSource(t, path), Query{FromStart: true})

	s.wantLine("one")
	s.wantLine("two")
	s.wantLine("")
	s.wantLine("three\r")
}

func TestReadFollowsAppendedLines(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "")
	s := startRead(t, newSource(t, path), Query{})

	appendFile(t, path, "first\nsec")
	s.wantLine("first")
	appendFile(t, path, "ond\n")
	s.wantLine("second")
}

func TestReadSkipsFragmentWhenFileDoesNotEndInNewline(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "complete\nhalf a li")
	s := startRead(t, newSource(t, path), Query{})

	appendFile(t, path, "ne\nnext\n")

	s.wantMarker(int64(len("ne\n")))
	s.wantLine("next")
}

func TestReadKeepsFirstLineWhenFileEndsInNewline(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "complete\n")
	s := startRead(t, newSource(t, path), Query{})

	appendFile(t, path, "next\n")

	s.wantLine("next")
}

func TestReadOverCapLineGivesOneMarkerAndNoContent(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	src, err := NewFileSource("app", path, FileOptions{PollInterval: testPoll, MaxLineBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, "")
	s := startRead(t, src, Query{})

	appendFile(t, path, "0123456789abcdef\n") // exactly the cap
	s.wantLine("0123456789abcdef")
	appendFile(t, path, strings.Repeat("x", 100)+"\nafter\n")

	e := s.next()
	if !e.Truncated || e.Line != nil || e.Dropped < 17 {
		t.Fatalf("entry = %+v, want one marker with Dropped >= 17", e)
	}
	s.wantLine("after")
}

func TestReadHugeLineKeepsHeapBoundedAndGivesOneMarker(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	const chunk, chunks = 64 << 10, 160 // 10 MiB without a newline
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	block := []byte(strings.Repeat("y", chunk))
	for range chunks {
		if _, err := f.Write(block); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.WriteString("\nend\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc
	var peak uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			peak = max(peak, m.HeapAlloc)
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()

	s := startRead(t, newSource(t, path), Query{FromStart: true})
	e := s.next()
	s.wantLine("end")
	close(stop)
	<-done

	if !e.Truncated || e.Line != nil {
		t.Fatalf("first entry = %+v, want a marker", e)
	}
	if e.Dropped <= DefaultMaxLineBytes || e.Dropped > DefaultMaxLineBytes+readBufferSize {
		t.Errorf("Dropped = %d, want in (%d, %d]", e.Dropped, DefaultMaxLineBytes, DefaultMaxLineBytes+readBufferSize)
	}
	if growth := int64(peak) - int64(base); growth > DefaultMaxLineBytes+1<<20 {
		t.Errorf("heap grew by %d bytes, want < %d", growth, DefaultMaxLineBytes+1<<20)
	}
}

func TestReadContextAlreadyDone(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "x\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fds := openFDs(t)

	ch, err := newSource(t, path).Read(ctx, Query{})

	if !errors.Is(err, context.Canceled) || ch != nil {
		t.Fatalf("Read = %v, %v, want nil channel and context.Canceled", ch, err)
	}
	if got := openFDs(t); got != fds {
		t.Errorf("open fds = %d, want %d", got, fds)
	}
}

func TestReadCancellationClosesChannelAndReleasesResources(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "one\n")
	fds, routines := openFDs(t), goroutines()
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := newSource(t, path).Read(ctx, Query{FromStart: true})
	if err != nil {
		t.Fatal(err)
	}
	s := &stream{t: t, ch: ch}

	s.wantLine("one")
	cancel()
	s.wantClosed()

	assertNoLeaks(t, fds, routines)
}

func TestReadCancellationWhileSendBlocked(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "one\ntwo\nthree\n")
	fds, routines := openFDs(t), goroutines()
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := newSource(t, path).Read(ctx, Query{FromStart: true}); err != nil {
		t.Fatal(err)
	}

	cancel() // nobody ever receives: the goroutine is blocked in a send

	assertNoLeaks(t, fds, routines)
}

func TestReadRefusesUnsafeFirstOpen(t *testing.T) {
	dir := tempDir(t)
	regular := filepath.Join(dir, "real.log")
	writeFile(t, regular, "x\n")

	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(dir, "realdir")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(realDir, "app.log"), "x\n")
	linkedDir := filepath.Join(dir, "linkdir")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo.log")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	unreadable := filepath.Join(dir, "secret.log")
	writeFile(t, unreadable, "x\n")
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
		want error
	}{
		{"symlink final component", link, safefs.ErrSymlink},
		{"symlinked parent", filepath.Join(linkedDir, "app.log"), safefs.ErrSymlink},
		{"fifo", fifo, safefs.ErrNotRegular},
		{"directory", realDir, safefs.ErrNotRegular},
		{"missing", filepath.Join(dir, "missing.log"), fs.ErrNotExist},
	}
	if os.Geteuid() != 0 {
		tests = append(tests, struct {
			name string
			path string
			want error
		}{"permission denied", unreadable, fs.ErrPermission})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fds, routines := openFDs(t), goroutines()
			start := time.Now()

			ch, err := newSource(t, tc.path).Read(context.Background(), Query{})

			if ch != nil || !errors.Is(err, tc.want) {
				t.Fatalf("Read = %v, %v, want nil channel and %v", ch, err, tc.want)
			}
			if time.Since(start) > waitTimeout {
				t.Error("Read took too long")
			}
			assertNoErrorLeaks(t, err, tc.path, "app")
			assertNoLeaks(t, fds, routines)
		})
	}
}

// assertNoErrorLeaks checks that err's text has none of the given strings nor
// the marker string.
func assertNoErrorLeaks(t *testing.T, err error, leaks ...string) {
	t.Helper()
	for _, leak := range append(leaks, markerString) {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error text %q contains %q", err.Error(), leak)
		}
	}
}

func TestReadTruncationRestartsFromStart(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "one\nhalf")
	s := startRead(t, newSource(t, path), Query{FromStart: true})
	s.wantLine("one")

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path, "new\n")

	s.wantMarker(int64(len("half")))
	s.wantLine("new")
}

func TestReadTruncationWithoutPendingBytesGivesNoMarker(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "one\ntwo\n")
	s := startRead(t, newSource(t, path), Query{FromStart: true})
	s.wantLine("one")
	s.wantLine("two")

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path, "new\n")

	s.wantLine("new")
}

func TestReadFailsClosedOnStatError(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, markerString+"\n")
	var mu sync.Mutex
	calls := 0
	real := fstat
	fstat = func(f *os.File) (fs.FileInfo, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 { // the first call is the open
			return real(f)
		}
		return nil, &fs.PathError{Op: "fstat", Path: path, Err: syscall.EIO}
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

	s.wantLine(markerString)
	// The goroutine is now blocked sending the Err entry (nobody receives yet).
	// The descriptor must already be closed.
	deadline := time.Now().Add(waitTimeout)
	for openFDs(t) != fds && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := openFDs(t); got != fds {
		t.Errorf("open fds while the Err entry is undelivered = %d, want %d", got, fds)
	}
	e := s.next()
	s.wantClosed()

	got := e.Err
	if !errors.Is(got, syscall.EIO) {
		t.Errorf("err = %v, want it to unwrap to EIO", got)
	}
	assertNoErrorLeaks(t, got, path, "app")
	assertNoLeaks(t, fds, routines)
}

func TestReadFailsClosedOnStatErrorAtOpen(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, markerString+"\n")
	real := fstat
	fstat = func(*os.File) (fs.FileInfo, error) {
		return nil, &fs.PathError{Op: "fstat", Path: path, Err: syscall.EIO}
	}
	t.Cleanup(func() { fstat = real })
	fds := openFDs(t)

	ch, err := newSource(t, path).Read(context.Background(), Query{})

	if ch != nil || !errors.Is(err, syscall.EIO) {
		t.Fatalf("Read = %v, %v, want nil channel and EIO", ch, err)
	}
	assertNoErrorLeaks(t, err, path, "app")
	if got := openFDs(t); got != fds {
		t.Errorf("open fds = %d, want %d", got, fds)
	}
}

func TestReadConcurrentCallsAreIndependent(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "")
	src := newSource(t, path)
	a := startRead(t, src, Query{})
	b := startRead(t, src, Query{})

	appendFile(t, path, "shared\n")

	a.wantLine("shared")
	b.wantLine("shared")
}

func TestReadCancellationDuringOverCapSkip(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "x\n")
	fds, routines := openFDs(t), goroutines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := newSource(t, path).Read(ctx, Query{})
	if err != nil {
		t.Fatal(err)
	}
	s := &stream{t: t, ch: ch}

	// A huge newline-free region appears: the reader skips it without ever
	// emitting a line, so only an explicit ctx check can stop it.
	if err := os.Truncate(path, 1<<50); err != nil {
		t.Skipf("filesystem refuses a sparse 1 PiB file: %v", err)
	}
	e := s.next()
	if !e.Truncated {
		t.Fatalf("entry = %+v, want a marker", e)
	}
	cancel()
	s.wantClosed()

	assertNoLeaks(t, fds, routines)
}

func TestReadFromStartOfHugeSparseFileCancelsPromptly(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "")
	if err := os.Truncate(path, 1<<40); err != nil {
		t.Skipf("filesystem refuses a sparse 1 TiB file: %v", err)
	}
	fds, routines := openFDs(t), goroutines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := newSource(t, path).Read(ctx, Query{FromStart: true})
	if err != nil {
		t.Fatal(err)
	}
	s := &stream{t: t, ch: ch}
	if e := s.next(); !e.Truncated {
		t.Fatalf("entry = %+v, want a marker", e)
	}

	cancel()
	start := time.Now()
	s.wantClosed()

	if d := time.Since(start); d > time.Second {
		t.Errorf("close took %v, want well under a second", d)
	}
	assertNoLeaks(t, fds, routines)
}

func TestReadStartsFromBeginningWhenFileShrinksAfterStat(t *testing.T) {
	path := filepath.Join(tempDir(t), "app.log")
	writeFile(t, path, "old line\n")
	real := fstat
	calls := 0
	fstat = func(f *os.File) (fs.FileInfo, error) {
		st, err := real(f)
		calls++
		if calls == 1 { // Read's own stat: the file is truncated right after it
			if terr := os.Truncate(path, 0); terr != nil {
				t.Error(terr)
			}
		}
		return st, err
	}
	t.Cleanup(func() { fstat = real })
	fds, routines := openFDs(t), goroutines()
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := newSource(t, path).Read(ctx, Query{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	s := &stream{t: t, ch: ch}

	appendFile(t, path, "new\n")

	s.wantLine("new") // whole line, no marker, no error
	cancel()
	s.wantClosed()
	assertNoLeaks(t, fds, routines)
}
