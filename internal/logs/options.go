package logs

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	DefaultPollInterval = 250 * time.Millisecond
	MinPollInterval     = 10 * time.Millisecond
	MaxPollInterval     = time.Minute
	DefaultMaxLineBytes = 64 << 10
	MaxMaxLineBytes     = 1 << 20
	MaxNameBytes        = 128
)

// FileOptions tunes a FileSource. The zero value selects the defaults.
type FileOptions struct {
	PollInterval time.Duration // 0 = DefaultPollInterval
	MaxLineBytes int           // 0 = DefaultMaxLineBytes
}

// withDefaults validates o and fills in zero values.
func (o FileOptions) withDefaults() (FileOptions, error) {
	if o.PollInterval == 0 {
		o.PollInterval = DefaultPollInterval
	}
	if o.MaxLineBytes == 0 {
		o.MaxLineBytes = DefaultMaxLineBytes
	}
	if o.PollInterval < MinPollInterval || o.PollInterval > MaxPollInterval ||
		o.MaxLineBytes < 0 || o.MaxLineBytes > MaxMaxLineBytes {
		return FileOptions{}, ErrInvalidOptions
	}
	return o, nil
}

// validLabel reports whether name is safe to show and to pass to later
// consumers: non-empty, bounded, valid UTF-8, no control, format (bidi) or
// line and paragraph separator characters.
func validLabel(name string) bool {
	if name == "" || len(name) > MaxNameBytes || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

func validPath(path string) bool {
	return path != "" && !strings.ContainsRune(path, 0)
}
