package quarantine

import (
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/redactor"
	"github.com/boktavec/redactscan/internal/scanner"
)

// Input is what Put records about a source besides its bytes. Name and
// Source.URI are redactor-checked here, but finding strings are not re-run
// through the redactor: Findings must come from scanner.Registry.Run (ADR 0006
// caller constraint).
type Input struct {
	Source   artifact.SourceMetadata // Type must be an artifact.Source* constant
	Name     string                  // untrusted, display only
	Decision Decision
	Findings []finding.Finding
}

// Metadata is the decoded metadata.json. All strings are untrusted.
type Metadata struct {
	SchemaVersion int
	ID, SHA256    string
	Size          int64
	CreatedAt     time.Time // UTC, second precision
	Source        artifact.SourceMetadata
	Name          string
	Decision      Decision
	Findings      []finding.Finding
}

// errInvalidRecord carries no detail on purpose: details could echo
// untrusted content. Callers map it to ErrCorruptMetadata or ErrInvalidInput.
var errInvalidRecord = errors.New("invalid record")

// validateFields applies the rules shared by Put and Read (spec 3.5).
func validateFields(m Metadata) error {
	switch m.Decision {
	case Review, Block:
	default:
		return errInvalidRecord
	}
	switch m.Source.Type {
	case artifact.SourceFile, artifact.SourceDirectory, artifact.SourceArchive,
		artifact.SourceGit, artifact.SourceDownload:
	default:
		return errInvalidRecord
	}
	if len(m.Name) > MaxNameBytes || !utf8.ValidString(m.Name) {
		return errInvalidRecord
	}
	if !validURI(m.Source.URI) || len(m.Findings) > scanner.MaxFindings {
		return errInvalidRecord
	}
	for _, f := range m.Findings {
		if !validFinding(f) {
			return errInvalidRecord
		}
	}
	return nil
}

// validURI accepts "" or an http, https or file URI with no userinfo, query,
// fragment or opaque part. url.Parse only fills User after "//", so an opaque
// form such as "https:user:pw@host" would otherwise carry credentials; the
// scheme allowlist and the opaque check refuse it. A "?" or "#" anywhere is
// refused, which also covers a dangling one.
func validURI(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > MaxURIBytes || !utf8.ValidString(s) || strings.ContainsAny(s, "?#") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.User != nil || u.Opaque != "" {
		return false
	}
	switch u.Scheme {
	case "https", "http":
		return u.Host != ""
	case "file":
		return true
	}
	return false
}

func validFinding(f finding.Finding) bool {
	if f.Validate() != nil || f.Line < 0 {
		return false
	}
	if len(f.ID) == 0 || len(f.ID) > scanner.MaxIDBytes || len(f.ArtifactID) > scanner.MaxIDBytes ||
		len(f.Title) > scanner.MaxTitleBytes || len(f.File) > scanner.MaxFileBytes ||
		len(f.Category) > MaxCategoryBytes || len(f.Description) > MaxDescriptionBytes {
		return false
	}
	for _, s := range []string{f.ID, f.ArtifactID, f.Title, f.File, f.Category, f.Description} {
		if !utf8.ValidString(s) {
			return false
		}
	}
	return true
}

// validateStored adds the Read-only rules: the record must belong to the
// entry directory dirID and carry a valid schema version.
func validateStored(m Metadata, dirID string) error {
	if m.SchemaVersion != SchemaVersion || !ValidID(m.ID) || m.ID != dirID ||
		m.SHA256 != m.ID[:idHashLen] || m.Size < 0 {
		return errInvalidRecord
	}
	return validateFields(m)
}

// validateInput applies the Put-only checks before any I/O. Name and URI are
// refused, not redacted, when the redactor flags them (spec D9). These checks
// are not repeated on Read, so a redactor rule change cannot make stored
// entries unreadable.
func validateInput(in Input) error {
	m := Metadata{Source: in.Source, Name: in.Name, Decision: in.Decision, Findings: in.Findings}
	if validateFields(m) != nil {
		return ErrInvalidInput
	}
	if !redactor.IsClean(in.Name) || !redactor.IsClean(in.Source.URI) {
		return ErrSensitiveInput
	}
	return nil
}
