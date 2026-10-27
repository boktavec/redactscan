//go:build !darwin && !linux

package quarantine

import "os"

// Store is not usable on this platform.
type Store struct{}

// Open always refuses on platforms without a symlink-safe open.
func Open(string, Options) (*Store, error) { return nil, ErrUnsupportedPlatform }

func (*Store) Close() error       { return nil }
func (*Store) Repaired() []string { return nil }

func (*Store) Put(*os.File, Input) (string, error) { return "", ErrUnsupportedPlatform }
