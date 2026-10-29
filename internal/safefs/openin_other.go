//go:build !darwin && !linux

package safefs

import "os"

// OpenRegularIn always refuses on platforms without a symlink-safe open.
func OpenRegularIn(*os.Root, string) (*os.File, error) { return nil, ErrUnsupportedPlatform }
