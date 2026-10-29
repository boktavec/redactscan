//go:build darwin || linux

package logs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const (
	waitTimeout  = 2 * time.Second
	testPoll     = MinPollInterval
	markerString = "MARKER-line-content-7d2f" // must never appear in error text
)

// tempDir returns a symlink-free temp directory (macOS TempDir lives under the
// /var symlink).
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func newSource(t *testing.T, path string) *FileSource {
	t.Helper()
	src, err := NewFileSource("app", path, FileOptions{PollInterval: testPoll})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// openFDs counts this process's open descriptors.
func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// goroutines returns the baseline to compare with after a stream ends.
func goroutines() int { return runtime.NumGoroutine() }

// assertNoLeaks waits for the goroutine count to fall back and checks the fd
// count. Call it after the stream's channel has closed.
func assertNoLeaks(t *testing.T, fds, routines int) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for goroutines() > routines && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := goroutines(); got > routines {
		t.Errorf("goroutines = %d, want <= %d", got, routines)
	}
	if got := openFDs(t); got != fds {
		t.Errorf("open fds = %d, want %d", got, fds)
	}
}

// stream is a running Read with a cancel that is also called on cleanup.
type stream struct {
	t      *testing.T
	ch     <-chan LogEntry
	cancel context.CancelFunc
}

// startRead starts Read and registers cleanup that cancels and waits for close,
// so seams can be restored safely afterwards.
func startRead(t *testing.T, src *FileSource, q Query) *stream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := src.Read(ctx, q)
	if err != nil {
		cancel()
		t.Fatalf("Read: %v", err)
	}
	s := &stream{t: t, ch: ch, cancel: cancel}
	t.Cleanup(func() {
		cancel()
		s.drain()
	})
	return s
}

// drain discards entries until the channel closes.
func (s *stream) drain() {
	deadline := time.After(waitTimeout)
	for {
		select {
		case _, ok := <-s.ch:
			if !ok {
				return
			}
		case <-deadline:
			s.t.Error("channel did not close")
			return
		}
	}
}

func (s *stream) next() LogEntry {
	s.t.Helper()
	select {
	case e, ok := <-s.ch:
		if !ok {
			s.t.Fatal("channel closed, want an entry")
		}
		return e
	case <-time.After(waitTimeout):
		s.t.Fatal("timed out waiting for an entry")
	}
	panic("unreachable")
}

func (s *stream) wantLine(want string) {
	s.t.Helper()
	e := s.next()
	if e.Err != nil || e.Truncated || e.Line == nil || !bytes.Equal(e.Line, []byte(want)) {
		s.t.Fatalf("entry = %+v (line %q), want line %q", e, e.Line, want)
	}
	if e.Source != "app" {
		s.t.Errorf("Source = %q, want app", e.Source)
	}
}

func (s *stream) wantMarker(dropped int64) {
	s.t.Helper()
	e := s.next()
	if !e.Truncated || e.Line != nil || e.Err != nil || e.Dropped != dropped {
		s.t.Fatalf("entry = %+v, want marker with Dropped %d", e, dropped)
	}
}

func (s *stream) wantErrThenClose() error {
	s.t.Helper()
	e := s.next()
	if e.Err == nil || e.Line != nil || e.Truncated || e.Dropped != 0 {
		s.t.Fatalf("entry = %+v, want only Err set", e)
	}
	select {
	case extra, ok := <-s.ch:
		if ok {
			s.t.Fatalf("entry after Err: %+v", extra)
		}
	case <-time.After(waitTimeout):
		s.t.Fatal("channel not closed after Err")
	}
	return e.Err
}

func (s *stream) wantClosed() {
	s.t.Helper()
	select {
	case e, ok := <-s.ch:
		if ok {
			s.t.Fatalf("entry %+v, want closed channel", e)
		}
	case <-time.After(waitTimeout):
		s.t.Fatal("channel not closed")
	}
}
