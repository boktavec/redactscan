//go:build !darwin && !linux

package logs

import "io/fs"

// ownerAndLinks always reports ok=false. It is never reached in practice:
// safefs.OpenRegular refuses first on these platforms.
func ownerAndLinks(fs.FileInfo) (uid uint32, nlink uint64, ok bool) { return 0, 0, false }
