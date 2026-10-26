package artifact

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"unicode/utf8"
)

// Limits enforced by ValidateMetadata.
const (
	MaxMetadataEntries    = 32
	MaxMetadataKeyBytes   = 64
	MaxMetadataValueBytes = 256
)

// ErrInvalidMetadata is wrapped by every ValidateMetadata failure.
var ErrInvalidMetadata = errors.New("invalid metadata")

// ValidateMetadata reports whether m is nil or holds at most MaxMetadataEntries
// bounded scalar values: string, bool, int, int64 or finite float64. Keys are
// 1..MaxMetadataKeyBytes bytes of UTF-8; string values are at most
// MaxMetadataValueBytes bytes of UTF-8. Named types, nil, slices, maps and
// pointers are rejected without recursion.
//
// Errors name counts, lengths and reflect kinds, never keys or values. When
// several entries are bad, which one is reported varies with map order.
func ValidateMetadata(m map[string]any) error {
	if len(m) > MaxMetadataEntries {
		return metadataError("%d entries, max %d", len(m), MaxMetadataEntries)
	}
	for k, v := range m {
		if len(k) == 0 || len(k) > MaxMetadataKeyBytes {
			return metadataError("key is %d bytes, want 1..%d", len(k), MaxMetadataKeyBytes)
		}
		if !utf8.ValidString(k) {
			return metadataError("key is not valid UTF-8")
		}
		if err := validateValue(v); err != nil {
			return err
		}
	}
	return nil
}

func validateValue(v any) error {
	switch x := v.(type) {
	case bool, int, int64:
		return nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return metadataError("value is NaN or infinite")
		}
		return nil
	case string:
		if len(x) > MaxMetadataValueBytes {
			return metadataError("value is %d bytes, max %d", len(x), MaxMetadataValueBytes)
		}
		if !utf8.ValidString(x) {
			return metadataError("value is not valid UTF-8")
		}
		return nil
	case nil:
		return metadataError("value has unsupported kind nil")
	default:
		// Kind, never %T: runtime-built types can embed arbitrary strings.
		return metadataError("value has unsupported kind %s", reflect.TypeOf(v).Kind())
	}
}

func metadataError(format string, args ...any) error {
	return fmt.Errorf("artifact: metadata: %s: %w", fmt.Sprintf(format, args...), ErrInvalidMetadata)
}
