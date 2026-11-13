//go:build darwin || linux

package logs

import (
	"io/fs"
	"syscall"
)

// ownerAndLinks reads the owner uid and hard link count from fi. ok is false
// when fi has no *syscall.Stat_t, which callers must treat as a refusal. Nlink
// has a different integer type per platform, hence the conversion.
func ownerAndLinks(fi fs.FileInfo) (uid uint32, nlink uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Uid, uint64(st.Nlink), true
}
