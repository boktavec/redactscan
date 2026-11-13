//go:build !darwin && !linux

package cli

import "io/fs"

// ctimeNS is unavailable here, so checkUnchanged treats every file as changed
// (fail closed). safefs.OpenRegular already refuses these platforms.
func ctimeNS(fs.FileInfo) (ns int64, ok bool) { return 0, false }
