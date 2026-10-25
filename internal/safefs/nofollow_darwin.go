package safefs

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// oNofollowAny is O_NOFOLLOW_ANY: no symlinks allowed anywhere in path
// (macOS 11+). It is in the macOS SDK sys/fcntl.h but not exported by
// package syscall.
const oNofollowAny = 0x20000000

// systemLinks are the root-owned links in / that macOS ships, each to
// "private/"+name. $TMPDIR and t.TempDir() live under /var/folders.
var systemLinks = []string{"tmp", "var", "etc"}

// openNoFollow opens path with flags, refusing a symlink in any component.
// For a relative path the kernel resolves the current directory without
// re-checking it. O_NOFOLLOW_ANY supersedes O_NOFOLLOW; passing both fails
// with EINVAL (Verified on macOS 26), so O_NOFOLLOW is cleared.
func openNoFollow(path string, flags int) (*os.File, error) {
	return os.OpenFile(path, flags&^syscall.O_NOFOLLOW|oNofollowAny, 0) // #nosec G304 -- path is validated by Lstat, O_NOFOLLOW_ANY and the Fstat identity check
}

// fdDir holds one entry per open descriptor on macOS; WriteSibling opens its
// root through it. If it is missing, the root open fails closed.
const fdDir = "/dev/fd"

// normalizePath rewrites a leading /tmp, /var or /etc to /private/... when
// that link is verified at run time; any other path is returned unchanged.
func normalizePath(path string) string { return systemPath(path, trustedSystemLink) }

// systemPath rewrites only the literal prefixes "/tmp/", "/var/" and "/etc/"
// (no Clean, no other spelling) and only when check(name) passes. Otherwise
// the path is returned unchanged and the open refuses the symlink.
func systemPath(path string, check func(name string) bool) string {
	for _, name := range systemLinks {
		prefix := "/" + name + "/"
		if strings.HasPrefix(path, prefix) && check(name) {
			return "/private" + path
		}
	}
	return path
}

// trustedSystemLink reports whether "/"+name is a root-owned symlink to
// exactly "private/"+name. Entries in / are writable only by root, so a link
// made by a user or a cloned repo cannot satisfy this.
func trustedSystemLink(name string) bool { return isTrustedLink("/", name, 0) }

// isTrustedLink reports whether dir/name is a symlink owned by uid whose
// target is exactly "private/"+name. dir and uid are parameters only so tests
// can exercise the refusals without root.
func isTrustedLink(dir, name string, uid uint32) bool {
	link := filepath.Join(dir, name)
	fi, err := os.Lstat(link)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid {
		return false
	}
	target, err := os.Readlink(link)
	return err == nil && target == "private/"+name
}
