package finding

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/boktavec/redactscan/internal/artifact"
)

// MaxEvidenceBytes is the largest Evidence that Validate accepts.
const MaxEvidenceBytes = 256

// ErrInvalidFinding is wrapped by every Finding.Validate failure.
var ErrInvalidFinding = errors.New("invalid finding")

// Finding is one detector result. All detectors emit this type.
type Finding struct {
	// ID, Category, Title and Description are constant text or redactor
	// output, per the package contract.
	ID          string
	Severity    Severity
	Category    string
	Title       string
	Description string
	// ArtifactID is the Artifact.ID this finding refers to.
	ArtifactID string
	// File is untrusted. Display only. Never join it to a directory or pass it
	// to a filesystem call. Output code must escape it.
	File string
	// Line is 1-based, or 0 when unknown.
	Line int
	// Evidence is a short redacted excerpt of at most MaxEvidenceBytes bytes
	// and valid UTF-8. Detectors redact and shorten before building the
	// finding; Validate rejects, never truncates.
	Evidence string
	// Metadata follows the same rule as Evidence (keys and values are constant
	// text or redactor output; keys should be fixed identifiers) and is checked
	// by artifact.ValidateMetadata.
	Metadata map[string]any
}

// Validate checks, in order and returning the first failure: severity,
// evidence length, evidence UTF-8, metadata. Errors wrap ErrInvalidFinding and
// never contain evidence or metadata content. It never modifies the finding.
func (f Finding) Validate() error {
	if !f.Severity.Valid() {
		return fmt.Errorf("finding: %w: invalid severity", ErrInvalidFinding)
	}
	if len(f.Evidence) > MaxEvidenceBytes {
		return fmt.Errorf("finding: %w: evidence is %d bytes, max %d", ErrInvalidFinding, len(f.Evidence), MaxEvidenceBytes)
	}
	if !utf8.ValidString(f.Evidence) {
		return fmt.Errorf("finding: %w: evidence is not valid UTF-8", ErrInvalidFinding)
	}
	if err := artifact.ValidateMetadata(f.Metadata); err != nil {
		return fmt.Errorf("finding: %w: metadata: %w", ErrInvalidFinding, err)
	}
	return nil
}
