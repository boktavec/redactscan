// Package finding holds the types shared by detectors, policy and reports:
// Finding and Severity.
//
// Redacted-or-bounded: ID, Category, Title, Description, Evidence and Metadata
// keys and values are constant text chosen by the detector or output of
// internal/redactor, never raw scanned content or secrets. Evidence is a short
// excerpt of at most MaxEvidenceBytes bytes and valid UTF-8. Detectors redact
// and shorten before building the finding; Validate never truncates, because
// truncating a secret does not remove it.
//
// Limits of Validate: it cannot detect secrets. It rejects only mistakes it can
// see: an invalid severity, oversize or non-UTF-8 evidence, and metadata that
// breaks artifact.ValidateMetadata. Redaction is the detector's job. Title,
// Description, Category and ID follow the contract but are not checked.
//
// Thresholds: use Severity.AtMost and Severity.AtLeast for every allow or deny
// decision, never Compare or a raw "<" on the integer value. Both methods fail
// closed when either side is invalid (for example a zero-valued config field).
// Callers must call Validate on every finding and treat an error as block or
// error, never allow.
//
// ParseSeverity is for trusted configuration and CLI flags only. Never call it
// on scanned content.
//
// No reflection formatting: never format a Finding with %v, %+v, slog
// attributes or JSON into errors or logs. Log ID and Severity.String() only.
//
// Output escaping: strings may contain terminal control and bidi characters;
// output code must escape them.
package finding

import (
	"cmp"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Severity is an ordered risk level. The zero value is SeverityInvalid, so a
// severity that was never set is detectable instead of silently becoming info.
// The integer values are not a stable external format; serialize String names.
type Severity int

const (
	// SeverityInvalid is the zero value: unset or unknown, never a real severity.
	SeverityInvalid Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

const (
	nameInfo     = "info"
	nameLow      = "low"
	nameMedium   = "medium"
	nameHigh     = "high"
	nameCritical = "critical"
	nameInvalid  = "invalid"
)

const (
	// maxSeverityInputBytes caps what ParseSeverity will examine.
	maxSeverityInputBytes = 64
	// maxQuotedInputBytes caps how much raw input an error message echoes.
	maxQuotedInputBytes = 32
	// asciiSpace is the only whitespace ParseSeverity trims.
	asciiSpace = " \t\n\r\v\f"
)

// ErrInvalidSeverity is wrapped by every ParseSeverity failure.
var ErrInvalidSeverity = errors.New("invalid severity")

// Valid reports whether s is one of the five real severities.
func (s Severity) Valid() bool { return s >= SeverityInfo && s <= SeverityCritical }

// rank maps every invalid value above SeverityCritical.
func (s Severity) rank() int {
	if !s.Valid() {
		return int(SeverityCritical) + 1
	}
	return int(s)
}

// Compare orders severities for sorting and returns -1, 0 or +1. Every invalid
// value sorts above SeverityCritical and compares equal to other invalid values.
//
// Compare is not a threshold check: an invalid threshold compares above every
// valid severity, so s.Compare(t) <= 0 is true for all valid s. Use AtMost or
// AtLeast for allow and deny decisions.
func (s Severity) Compare(other Severity) int { return cmp.Compare(s.rank(), other.rank()) }

// AtMost reports s <= limit. It is false if either side is invalid; use it for
// "allow up to".
func (s Severity) AtMost(limit Severity) bool { return s.Valid() && limit.Valid() && s <= limit }

// AtLeast reports s >= limit. It is true if either side is invalid; use it for
// "block or review at or above".
func (s Severity) AtLeast(limit Severity) bool { return !s.Valid() || !limit.Valid() || s >= limit }

// String returns the lowercase name, or "invalid" for any other value.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return nameInfo
	case SeverityLow:
		return nameLow
	case SeverityMedium:
		return nameMedium
	case SeverityHigh:
		return nameHigh
	case SeverityCritical:
		return nameCritical
	default:
		return nameInvalid
	}
}

// ParseSeverity parses a severity name from trusted configuration or CLI flags.
// Never call it on scanned content. It trims ASCII whitespace, rejects input
// over 64 bytes or containing non-ASCII bytes (before lowercasing, so Unicode
// case folding cannot produce a match), and accepts only the five names.
// "invalid" is deliberately not accepted.
func ParseSeverity(s string) (Severity, error) {
	t := strings.Trim(s, asciiSpace)
	if len(t) <= maxSeverityInputBytes && isASCII(t) {
		switch strings.ToLower(t) {
		case nameInfo:
			return SeverityInfo, nil
		case nameLow:
			return SeverityLow, nil
		case nameMedium:
			return SeverityMedium, nil
		case nameHigh:
			return SeverityHigh, nil
		case nameCritical:
			return SeverityCritical, nil
		}
	}
	return SeverityInvalid, fmt.Errorf("finding: %w %s", ErrInvalidSeverity, quoteBounded(s))
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// quoteBounded quotes at most the first maxQuotedInputBytes bytes of s.
// strconv.Quote escapes any UTF-8 sequence cut by the truncation.
func quoteBounded(s string) string {
	if len(s) <= maxQuotedInputBytes {
		return strconv.Quote(s)
	}
	return strconv.Quote(s[:maxQuotedInputBytes]) + "..."
}
