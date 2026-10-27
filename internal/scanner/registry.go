package scanner

import (
	"errors"
	"fmt"
)

// RegistryName is the Failure.Scanner value for failures not tied to a
// scanner. NewRegistry reserves it.
const RegistryName = "registry"

const maxNameLen = 32

// ErrInvalidRegistry is wrapped by every NewRegistry failure.
var ErrInvalidRegistry = errors.New("scanner: invalid registry")

type entry struct {
	name string
	s    Scanner
}

// Registry is an ordered, immutable list of scanners.
type Registry struct {
	entries []entry
}

// NewRegistry keeps the order of scanners. It rejects a nil scanner, a name
// that does not match ^[a-z0-9][a-z0-9-]{0,31}$, the reserved name RegistryName
// and duplicate names. Errors name only the zero-based argument index, never
// the scanner's name. Name is called exactly once per scanner.
func NewRegistry(scanners ...Scanner) (*Registry, error) {
	entries := make([]entry, 0, len(scanners))
	seen := make(map[string]bool, len(scanners))
	for i, s := range scanners {
		if s == nil {
			return nil, invalid(i, "nil scanner")
		}
		name := s.Name()
		switch {
		case !validName(name):
			return nil, invalid(i, "invalid name")
		case name == RegistryName:
			return nil, invalid(i, "reserved name")
		case seen[name]:
			return nil, invalid(i, "duplicate name")
		}
		seen[name] = true
		entries = append(entries, entry{name, s})
	}
	return &Registry{entries}, nil
}

func invalid(index int, reason string) error {
	return fmt.Errorf("%w: scanner %d: %s", ErrInvalidRegistry, index, reason)
}

func validName(name string) bool {
	if name == "" || len(name) > maxNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0:
		default:
			return false
		}
	}
	return true
}

// Default returns the production registry. It is empty until scanners are
// added (REDACT-37), so every Run on it is incomplete.
func Default() (*Registry, error) {
	return NewRegistry()
}
