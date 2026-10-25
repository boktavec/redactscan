package safefs

import (
	"errors"
	"io/fs"
	"syscall"
	"testing"
)

func TestNotRegularErrorMatchesSentinel(t *testing.T) {
	err := error(&NotRegularError{Type: TypeFIFO})
	if !errors.Is(err, ErrNotRegular) {
		t.Error("NotRegularError does not match ErrNotRegular")
	}
	if errors.Is(err, ErrSymlink) {
		t.Error("NotRegularError matches ErrSymlink")
	}
	if got, want := err.Error(), "safefs: not a regular file (fifo)"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestOpErrorTextIsFixedAndUnwrapsToErrno(t *testing.T) {
	pathErr := &fs.PathError{Op: "open", Path: "/secret/path", Err: syscall.ENOENT}
	err := newOpError("open", pathErr)
	if got, want := err.Error(), "safefs: open failed"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Error("error does not match fs.ErrNotExist")
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		t.Error("error still exposes *fs.PathError")
	}
}

func TestFileType(t *testing.T) {
	tests := []struct {
		mode fs.FileMode
		want FileType
	}{
		{fs.ModeDir, TypeDirectory},
		{fs.ModeNamedPipe, TypeFIFO},
		{fs.ModeDevice, TypeDevice},
		{fs.ModeDevice | fs.ModeCharDevice, TypeDevice},
		{fs.ModeSocket, TypeSocket},
		{fs.ModeIrregular, TypeIrregular},
	}
	for _, tt := range tests {
		if got := fileType(tt.mode); got != tt.want {
			t.Errorf("fileType(%v) = %q, want %q", tt.mode, got, tt.want)
		}
	}
}
