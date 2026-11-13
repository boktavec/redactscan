package cli

import (
	"io/fs"
	"syscall"
)

// ctimeNS returns the inode change time in nanoseconds. User space cannot set
// it, which is why it backs the change check. ok is false if fi has no
// syscall.Stat_t.
func ctimeNS(fi fs.FileInfo) (ns int64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Ctimespec.Nano(), true
}
