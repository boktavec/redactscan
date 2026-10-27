//go:build !darwin && !linux

package safefs

import (
	"io/fs"
	"os"
)

// OpenDirRoot always refuses on platforms without a symlink-safe open.
func OpenDirRoot(string) (*os.File, *os.Root, error) { return nil, nil, ErrUnsupportedPlatform }

// OpenChildDir always refuses on platforms without a symlink-safe open.
func OpenChildDir(*os.Root, string, fs.FileInfo) (*os.File, *os.Root, error) {
	return nil, nil, ErrUnsupportedPlatform
}
