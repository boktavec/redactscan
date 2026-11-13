package builtin

import (
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"
)

// stubReader returns fixed ReadAt results.
type stubReader struct {
	n   int
	err error
}

func (s stubReader) ReadAt([]byte, int64) (int, error) { return s.n, s.err }

func TestReadFull(t *testing.T) {
	const path = "/home/user/secret-name.txt"
	pathErr := &fs.PathError{Op: "read", Path: path, Err: errors.New("EIO")}
	tests := []struct {
		name    string
		r       stubReader
		wantErr bool
	}{
		{"full read", stubReader{4, nil}, false},
		{"full read with EOF", stubReader{4, io.EOF}, false},
		{"short read, no error", stubReader{2, nil}, true},
		{"short read, EOF", stubReader{2, io.EOF}, true},
		{"short read, I/O error", stubReader{2, pathErr}, true},
		{"empty read, EOF", stubReader{0, io.EOF}, true},
		{"full read, I/O error", stubReader{4, pathErr}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := readFull(tt.r, make([]byte, 4), 0)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				return
			}
			var pe *fs.PathError
			if err != errTruncated || errors.As(err, &pe) || strings.Contains(err.Error(), path) {
				t.Errorf("error is not the fixed errTruncated: %v", err)
			}
		})
	}
}

func TestReadFullZeroLength(t *testing.T) {
	if err := readFull(stubReader{0, io.EOF}, nil, 0); err != nil {
		t.Errorf("zero-length read: %v", err)
	}
}
