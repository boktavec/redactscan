package logs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"time"

	"github.com/boktavec/redactscan/internal/safefs"
)

// readBufferSize is the fixed size of the per-Read buffer.
const readBufferSize = 32 << 10

// fstat is a test seam: tests in this package replace it to inject a stat
// failure. Production never changes it.
var fstat = func(f *os.File) (fs.FileInfo, error) { return f.Stat() }

// afterRotationDetected runs after the old descriptor is closed and before the
// path is reopened. Tests replace it to swap what is at the path; production
// never changes it.
var afterRotationDetected = func() {}

var _ LogSource = (*FileSource)(nil)

// FileSource follows one log file like tail -F. It is immutable and safe for
// concurrent Read calls; each Read has its own descriptor, goroutine and state.
type FileSource struct {
	name string
	path string
	opts FileOptions
}

// NewFileSource validates its arguments and does no I/O. name is a label for
// Name and LogEntry.Source; the path is never exposed.
func NewFileSource(name, path string, opts FileOptions) (*FileSource, error) {
	opts, err := opts.withDefaults()
	if err != nil || !validLabel(name) || !validPath(path) {
		return nil, ErrInvalidOptions
	}
	return &FileSource{name: name, path: path, opts: opts}, nil
}

// Name returns the label, never the path.
func (s *FileSource) Name() string { return s.name }

// Read opens the file through safefs.OpenRegular and follows it until ctx is
// done or a fatal error occurs. Opening problems are returned here; later ones
// arrive as the final entry. See the package documentation for the contract.
func (s *FileSource) Read(ctx context.Context, q Query) (<-chan LogEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := safefs.OpenRegular(s.path)
	if err != nil {
		return nil, err
	}
	r := &reader{
		ctx: ctx,
		src: s,
		ch:  make(chan LogEntry),
		f:   f,
		asm: newLineAssembler(s.name, s.opts.MaxLineBytes),
		buf: make([]byte, readBufferSize),
	}
	if err := r.start(q); err != nil {
		_ = f.Close()
		return nil, err
	}
	go r.loop()
	return r.ch, nil
}

// reader is the state of one Read, owned by its goroutine after start.
type reader struct {
	ctx context.Context
	src *FileSource
	ch  chan LogEntry
	f   *os.File // the held descriptor; nil while waiting for the path to reappear
	off int64    // next byte of f to read

	owner uint32 // uid of the first file; a rotated file must match
	asm   *lineAssembler
	buf   []byte
}

// start positions the reader: offset 0 for FromStart, otherwise the current
// end, skipping the rest of a line already in progress there.
func (r *reader) start(q Query) error {
	st, err := fstat(r.f)
	if err != nil {
		return newOpError("stat", err)
	}
	owner, _, ok := ownerAndLinks(st)
	if !ok {
		return newOpError("stat", errors.ErrUnsupported)
	}
	r.owner = owner
	if q.FromStart || st.Size() == 0 {
		return nil
	}
	r.off = st.Size()
	var last [1]byte
	if n, err := r.f.ReadAt(last[:], r.off-1); n != 1 {
		if errors.Is(err, io.EOF) { // truncated since the stat: start from the beginning
			r.off = 0
			return nil
		}
		return newOpError("read", err)
	}
	if last[0] != '\n' {
		r.asm.skipFragment()
	}
	return nil
}

func (r *reader) loop() {
	defer close(r.ch)
	defer func() {
		if r.f != nil {
			_ = r.f.Close()
		}
	}()
	ticker := time.NewTicker(r.src.opts.PollInterval)
	defer ticker.Stop()
	for {
		if r.f != nil && !r.readUpTo(math.MaxInt64) {
			return
		}
		select {
		case <-ticker.C:
		case <-r.ctx.Done():
			return
		}
		var ok bool
		if r.f == nil {
			ok = r.reopen()
		} else {
			ok = r.checkFile()
		}
		if !ok {
			return
		}
	}
}

// readUpTo feeds the assembler from off until the end of the file or limit,
// whichever comes first. It returns false when the stream is over (cancelled
// or failed).
func (r *reader) readUpTo(limit int64) bool {
	for r.off < limit {
		// A region without newlines produces no entries, so send never sees ctx.
		if r.ctx.Err() != nil {
			return false
		}
		buf := r.buf
		if remaining := limit - r.off; remaining < int64(len(buf)) {
			buf = buf[:remaining]
		}
		n, err := r.f.ReadAt(buf, r.off)
		r.off += int64(n)
		if !r.asm.write(buf[:n], r.send) {
			return false
		}
		if errors.Is(err, io.EOF) {
			return true
		}
		if err != nil {
			return r.fail(newOpError("read", err))
		}
	}
	return true
}

// checkFile runs on each tick while a descriptor is held. A file shorter than
// what was read was truncated: restart from offset 0, with a marker for any
// unfinished line. A path that no longer names the held file was rotated.
func (r *reader) checkFile() bool {
	// The reference identity is always the held descriptor, never an earlier Lstat.
	st, err := fstat(r.f)
	if err != nil {
		return r.fail(newOpError("stat", err))
	}
	if st.Size() < r.off {
		r.off = 0
		if !r.asm.cut(r.send) {
			return false
		}
	}
	li, err := os.Lstat(r.src.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true // removed, not rotated: keep reading what we hold
	case err != nil:
		return r.fail(newOpError("lstat", err))
	case os.SameFile(li, st):
		return true
	}
	return r.rotate(st.Size())
}

// rotate finishes the old file up to size (the size when the rotation was
// noticed; later appends are lost, so an attacker's writer cannot keep the
// drain going), then reopens the path.
func (r *reader) rotate(size int64) bool {
	if !r.readUpTo(size) || !r.asm.cut(r.send) {
		return false
	}
	_ = r.f.Close()
	r.f = nil
	afterRotationDetected()
	return r.reopen()
}

// reopen opens the path again through safefs. A missing path is not fatal: the
// source holds no descriptor and retries on the next tick. A file with another
// owner or more than one hard link is refused.
func (r *reader) reopen() bool {
	f, err := safefs.OpenRegular(r.src.path)
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if err != nil {
		return r.fail(err)
	}
	st, err := fstat(f)
	if err != nil {
		_ = f.Close()
		return r.fail(newOpError("stat", err))
	}
	if uid, links, ok := ownerAndLinks(st); !ok || uid != r.owner || links != 1 {
		_ = f.Close()
		return r.fail(ErrReopenRefused)
	}
	r.f, r.off = f, 0
	return true
}

// send delivers e unless ctx is done first.
func (r *reader) send(e LogEntry) bool {
	select {
	case r.ch <- e:
		return true
	case <-r.ctx.Done():
		return false
	}
}

// fail sends the final error entry. It always returns false so callers can
// end the loop with `return r.fail(err)`.
func (r *reader) fail(err error) bool {
	if r.f != nil { // the descriptor is closed before the consumer sees the error
		_ = r.f.Close()
		r.f = nil
	}
	r.send(LogEntry{Source: r.src.name, Err: err})
	return false
}
