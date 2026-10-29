package quarantine

import (
	"os"
)

// markNoIndex asks Spotlight to skip the store. Best effort: whether current
// macOS honours the marker outside a volume root is Assumed, and a failure
// must not fail Open.
func markNoIndex(base *os.Root) {
	f, err := base.OpenFile(".metadata_never_index", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return
	}
	_ = f.Chmod(0o600)
	_ = f.Close()
}
