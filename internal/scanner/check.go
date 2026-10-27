package scanner

import (
	"unicode/utf8"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/redactor"
)

// checkFinding reports whether f may be accepted for artifact a. It never
// formats f.
func checkFinding(f finding.Finding, a artifact.Artifact) bool {
	switch {
	case f.Validate() != nil:
		return false
	case f.ArtifactID != a.ID:
		return false
	case len(f.ID) == 0 || len(f.ID) > MaxIDBytes, len(f.Title) > MaxTitleBytes:
		return false
	case !utf8.ValidString(f.ID), !utf8.ValidString(f.Title):
		return false
	case len(f.File) > MaxFileBytes, f.Line < 0:
		return false
	}
	return redactorClean(f.ID) && redactorClean(f.Title) && redactorClean(f.File) && redactorClean(f.Evidence)
}

// redactorClean is true only when the redactor accepts s and finds nothing
// but label-like text, which is already neutralised output.
func redactorClean(s string) bool {
	res, err := redactor.Redact([]byte(s))
	if err != nil {
		return false
	}
	for kind := range res.Counts {
		if kind != redactor.KindLabelLike {
			return false
		}
	}
	return true
}
