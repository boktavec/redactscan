//go:build !darwin

package quarantine

import "os"

func markNoIndex(*os.Root) {}
