package scanner

import (
	"context"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
)

// countingReader counts ReadAt calls and serves zero bytes, so a test can
// claim a huge size without allocating it.
type countingReader struct{ calls int }

func (c *countingReader) ReadAt(p []byte, _ int64) (int, error) {
	c.calls++
	clear(p)
	return len(p), nil
}

func TestRunPreChecksReadNothing(t *testing.T) {
	sized := func(n int64) artifact.Artifact { a := art; a.Size = n; return a }
	badMeta := art
	badMeta.Metadata = map[string]any{"k": func() {}}

	tests := []struct {
		name string
		a    artifact.Artifact
		size int64
		want Reason
	}{
		{"invalid artifact", badMeta, art.Size, ReasonInvalidArtifact},
		{"negative size", sized(-1), -1, ReasonInvalidArtifact},
		{"size mismatch, artifact smaller", sized(1), 2, ReasonInvalidArtifact},
		{"size mismatch, artifact larger", sized(2), 1, ReasonInvalidArtifact},
		{"over cap", sized(MaxContentSize + 1), MaxContentSize + 1, ReasonTooLarge},
		{"far over cap", sized(1 << 62), 1 << 62, ReasonTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fake{name: "a"}
			r := &countingReader{}
			res := newReg(t, f).Run(context.Background(), tt.a, r, tt.size)
			assertFailures(t, res, Failure{RegistryName, tt.want})
			if r.calls != 0 || f.scans != 0 {
				t.Errorf("reads = %d, scans = %d, want none", r.calls, f.scans)
			}
		})
	}

	t.Run("nil reader", func(t *testing.T) {
		f := &fake{name: "a"}
		res := newReg(t, f).Run(context.Background(), art, nil, art.Size)
		assertFailures(t, res, Failure{RegistryName, ReasonInvalidArtifact})
		if f.scans != 0 {
			t.Error("scanner ran with a nil reader")
		}
	})

	t.Run("check order: invalid artifact wins over too large", func(t *testing.T) {
		bad := badMeta
		bad.Size = MaxContentSize + 1
		res := newReg(t, &fake{name: "a"}).Run(context.Background(), bad, &countingReader{}, bad.Size)
		assertFailures(t, res, Failure{RegistryName, ReasonInvalidArtifact})
	})
}

func TestRunSizeCap(t *testing.T) {
	f := &fake{name: "a", findings: []finding.Finding{fnd("a", finding.SeverityLow)}}
	a := art
	a.Size = MaxContentSize
	res := newReg(t, f).Run(context.Background(), a, &countingReader{}, MaxContentSize)
	if f.scans != 1 || res.Incomplete() || len(res.Findings) != 1 {
		t.Errorf("at cap: scans=%d result=%+v", f.scans, res)
	}
}

// readReporter reads one byte and returns the read error it got.
type readReporter struct{ readErr error }

func (*readReporter) Name() string                    { return "a" }
func (*readReporter) Supports(artifact.Artifact) bool { return true }
func (s *readReporter) Scan(_ context.Context, _ artifact.Artifact, r io.ReaderAt, _ int64) ([]finding.Finding, error) {
	_, s.readErr = r.ReadAt(make([]byte, 1), 0)
	return nil, s.readErr
}

func TestRunTypedNilFileIsIncomplete(t *testing.T) {
	var nilFile *os.File
	s := &readReporter{}
	res := newReg(t, s).Run(context.Background(), art, nilFile, art.Size) // must not panic
	if s.readErr != errReadFailed {
		t.Errorf("read error = %v, want errReadFailed", s.readErr)
	}
	assertFailures(t, res, Failure{"a", ReasonError}, Failure{RegistryName, ReasonNoScanner})
}

// TestScannerGetsOpaqueReader checks that a scanner cannot reach the file
// behind the reader it is handed.
func TestScannerGetsOpaqueReader(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	var got io.ReaderAt
	f := &fake{name: "a", onScan: func(_ context.Context, r io.ReaderAt) { got = r }}
	newReg(t, f).Run(context.Background(), art, io.NewSectionReader(file, 0, art.Size), art.Size)

	if got == nil {
		t.Fatal("scanner did not run")
	}
	if _, ok := got.(interface{ Chmod(fs.FileMode) error }); ok {
		t.Error("reader exposes Chmod")
	}
	if _, ok := got.(interface{ Name() string }); ok {
		t.Error("reader exposes Name")
	}
	if _, ok := got.(interface{ Fd() uintptr }); ok {
		t.Error("reader exposes Fd")
	}
	if _, ok := got.(interface {
		Outer() (io.ReaderAt, int64, int64)
	}); ok {
		t.Error("reader exposes Outer")
	}
	if _, ok := got.(*io.SectionReader); ok {
		t.Error("scanner received the caller's *io.SectionReader")
	}
}

func TestRunContentIsReadThroughReader(t *testing.T) {
	buf := make([]byte, len(body))
	f := &fake{name: "a", onScan: func(_ context.Context, r io.ReaderAt) {
		_, _ = r.ReadAt(buf, 0)
	}}
	res := newReg(t, f).Run(context.Background(), art, content(), art.Size)
	if res.Incomplete() || string(buf) != body {
		t.Errorf("buf = %q, failures = %v", buf, res.Failures)
	}
}
