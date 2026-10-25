//go:build !darwin && !linux

package safefs

import "os"

// OpenRegular always refuses on platforms without a symlink-safe open.
func OpenRegular(string) (*os.File, error) { return nil, ErrUnsupportedPlatform }
