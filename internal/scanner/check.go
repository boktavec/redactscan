package scanner

import (
	"unicode/utf8"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/redactor"
)

// redact is the redactor entry point; tests replace it to count calls and must not call t.Parallel.
var redact = redactor.Redact

// checkFinding reports whether f may be accepted for artifact a. It never
// formats f. Cheap checks run first and the redactor runs last, one field at
// a time, so a finding that fails a cheap check costs no redactor work.
func checkFinding(f finding.Finding, a artifact.Artifact) bool {
	switch {
	case f.Validate() != nil:
		return false
	case f.ArtifactID != a.ID:
		return false
	case len(f.ID) == 0 || len(f.ID) > MaxIDBytes, len(f.Title) > MaxTitleBytes,
		len(f.Category) > MaxCategoryBytes, len(f.Description) > MaxDescriptionBytes:
		return false
	case !utf8.ValidString(f.ID), !utf8.ValidString(f.Title), !utf8.ValidString(f.Description):
		return false
	case len(f.File) > MaxFileBytes, f.Line < 0:
		return false
	case !validIdentifier(f.ID), f.Category != "" && !validIdentifier(f.Category):
		return false
	case !validMetadataKeys(f.Metadata):
		return false
	}
	return redactorClean(f.ID) && redactorClean(f.Title) && redactorClean(f.File) && redactorClean(f.Evidence) &&
		redactorStrict(f.Category) && redactorStrict(f.Description) && metadataClean(f.Metadata)
}

// validIdentifier matches ^[a-z0-9][a-z0-9._-]*$ (non-empty).
func validIdentifier(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}
	return s != ""
}

// validMetadataKeys checks every key against ^[a-z][a-z0-9_]{0,63}$.
func validMetadataKeys(m map[string]any) bool {
	for k := range m {
		if len(k) == 0 || len(k) > artifact.MaxMetadataKeyBytes || k[0] < 'a' || k[0] > 'z' {
			return false
		}
		for i := 1; i < len(k); i++ {
			c := k[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
				return false
			}
		}
	}
	return true
}

// metadataClean applies the redactor to every key (strict: a key is an
// identifier, never a label) and to every string value.
func metadataClean(m map[string]any) bool {
	for k, v := range m {
		if !redactorStrict(k) {
			return false
		}
		if s, ok := v.(string); ok && !redactorClean(s) {
			return false
		}
	}
	return true
}

// redactorClean is true only when the redactor accepts s and finds nothing
// but label-like text, which is already neutralised output.
func redactorClean(s string) bool { return redactorOnly(s, true) }

// redactorStrict is true only when the redactor accepts s and finds nothing,
// label-like text included. Category and Description are constant text, so
// they never need a label.
func redactorStrict(s string) bool { return redactorOnly(s, false) }

func redactorOnly(s string, allowLabels bool) bool {
	res, err := redact([]byte(s))
	if err != nil {
		return false
	}
	for kind := range res.Counts {
		if kind != redactor.KindLabelLike || !allowLabels {
			return false
		}
	}
	return true
}
