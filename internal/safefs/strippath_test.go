package safefs

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

func TestStripPath(t *testing.T) {
	const secretPath = "/very/private/path"
	tests := []struct {
		name string
		in   error
		want error
	}{
		{"nil", nil, nil},
		{"path error", &fs.PathError{Op: "open", Path: secretPath, Err: syscall.ENOENT}, syscall.ENOENT},
		{"link error", &os.LinkError{Op: "link", Old: secretPath, New: secretPath, Err: syscall.EEXIST}, syscall.EEXIST},
		{"syscall error", os.NewSyscallError("read", syscall.EIO), syscall.EIO},
		{"bare errno", syscall.EACCES, syscall.EACCES},
		{"other error", ErrChanged, ErrChanged},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := StripPath(tc.in); got != tc.want {
				t.Errorf("StripPath(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestStripPathUnwrapsWrapped(t *testing.T) {
	inner := &fs.PathError{Op: "open", Path: "/p", Err: syscall.ENOENT}
	wrapped := errors.Join(errors.New("ctx"), inner)
	if got := StripPath(wrapped); got != syscall.ENOENT {
		t.Errorf("got %v, want ENOENT", got)
	}
}
