// Package artifact describes one item to scan or redact, independent of where
// it came from. Ingest produces an Artifact; scanners and the redact pipeline
// consume it. The package performs no I/O.
//
// Every string field is derived from untrusted input. Never format an Artifact
// with %v, %+v, slog attributes or JSON into errors or logs; log ID only.
//
// This package must never import internal/finding: finding imports it for
// ValidateMetadata. If an Artifact ever needs to carry findings, move
// ValidateMetadata into its own package first.
package artifact

import (
	"errors"
	"fmt"
)

// ErrInvalidArtifact is wrapped by every Artifact.Validate failure.
var ErrInvalidArtifact = errors.New("invalid artifact")

// Artifact is one item to scan or redact.
type Artifact struct {
	// ID is a stable identifier assigned by ingest; Finding.ArtifactID refers
	// to it. Constant or generated text, never content from the scanned file.
	ID string
	// Path is where the content is on disk. Open it only through
	// internal/safefs, never with plain os.Open.
	Path string
	// RelativePath is untrusted. Display only. Never join it to a directory or
	// pass it to a filesystem call. Output code must escape it.
	RelativePath string
	// Name is untrusted. Display only. Never join it to a directory or pass it
	// to a filesystem call. Output code must escape it.
	Name string
	// Size is filled by ingest; zero when unknown.
	Size int64
	// MIMEType is filled by ingest; empty when unknown.
	MIMEType string
	// SHA256 is lowercase hex from ingest. Not validated here. Check
	// ^[0-9a-f]{64}$ before using it as a path component.
	SHA256 string
	// Source is where the artifact came from.
	Source SourceMetadata
	// Metadata holds optional extra facts, checked by Validate. Keys and
	// values are constant text or redactor output, never raw scanned content
	// or secrets; keys should be fixed identifiers. Read-only after ingest:
	// scanners receive Artifact by value, but the map is shared, so they must
	// not modify it.
	Metadata map[string]any
}

// Source types for SourceMetadata.Type.
const (
	SourceFile      = "file"
	SourceDirectory = "directory"
	SourceArchive   = "archive"
	SourceGit       = "git"
	SourceDownload  = "download"
)

// SourceMetadata records where an Artifact came from.
type SourceMetadata struct {
	// Type is one of the Source constants.
	Type string
	// URI: ingest stores only scheme, host and path. It drops userinfo, query
	// and fragment and never stores the URL the user typed.
	URI string
}

// Validate checks Metadata with ValidateMetadata. Nothing else is checked: the
// other fields are covered by their documented contracts only.
func (a Artifact) Validate() error {
	if err := ValidateMetadata(a.Metadata); err != nil {
		return fmt.Errorf("artifact: %w: metadata: %w", ErrInvalidArtifact, err)
	}
	return nil
}
