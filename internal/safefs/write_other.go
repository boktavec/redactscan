//go:build !darwin && !linux

package safefs

import "io/fs"

// WriteSibling always refuses on platforms without a symlink-safe open.
func WriteSibling(string, fs.FileInfo, string, []byte, bool) (bool, error) {
	return false, ErrUnsupportedPlatform
}
