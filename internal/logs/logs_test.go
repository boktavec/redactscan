package logs

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestOpErrorHasFixedTextAndUnwrapsToErrno(t *testing.T) {
	const secretPath = "/home/someone/private.log"
	pathErr := &fs.PathError{Op: "lstat", Path: secretPath, Err: syscall.ENOENT}

	err := newOpError("lstat", pathErr)

	if got, want := err.Error(), "logs: lstat failed"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if strings.Contains(err.Error(), secretPath) {
		t.Error("error text contains the path")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Error("errors.Is(err, fs.ErrNotExist) = false, want true")
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		t.Error("error unwraps to a *fs.PathError, which carries the path")
	}
	if !errors.Is(newOpError("read", os.NewSyscallError("read", syscall.EACCES)), fs.ErrPermission) {
		t.Error("errors.Is(err, fs.ErrPermission) = false, want true")
	}
}
