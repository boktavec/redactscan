package report

import (
	"io"
	"slices"
	"strconv"

	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/scanner"
)

// registryFailureText is the fixed text for failures not tied to a scanner.
var registryFailureText = map[scanner.Reason]string{
	scanner.ReasonTooLarge:        "file exceeds 10 MiB limit",
	scanner.ReasonInvalidArtifact: "invalid artifact",
	scanner.ReasonNoScanner:       "no scanner ran",
}

// textGroups is the five real severities, then the invalid group (FR11).
var textGroups = append(slices.Clone(severities[:]), finding.SeverityInvalid)

// Text writes the readable report for res with one Write. See the package doc
// for the escaping rules.
func Text(w io.Writer, res scanner.Result) error {
	if !validMetadata(res.Findings) {
		return ErrRender
	}
	b := append([]byte("redactscan scan report\nstatus: "), status(res)...)
	b = append(b, '\n')

	if len(res.Findings) == 0 {
		b = append(b, "\nno findings\n"...)
	}
	counts := countBySeverity(res.Findings)
	for _, sev := range textGroups {
		if counts[sev] == 0 {
			continue
		}
		b = append(b, "\n== "...)
		b = append(b, sev.String()...)
		b = append(b, " ("...)
		b = strconv.AppendInt(b, int64(counts[sev]), 10)
		b = append(b, ") ==\n"...)
		for _, f := range res.Findings {
			if group(f.Severity) != sev {
				continue
			}
			b = appendFinding(b, f)
		}
	}

	if len(res.Failures) > 0 {
		b = append(b, "\nfailures ("...)
		b = strconv.AppendInt(b, int64(len(res.Failures)), 10)
		b = append(b, "):\n"...)
		for _, fl := range res.Failures {
			b = append(b, "- "...)
			b = appendFailure(b, fl)
			b = append(b, '\n')
		}
	}

	b = append(b, "\nsummary: "...)
	b = append(b, status(res)...)
	b = append(b, ", "...)
	b = strconv.AppendInt(b, int64(len(res.Findings)), 10)
	b = append(b, " finding"...)
	if len(res.Findings) != 1 {
		b = append(b, 's')
	}
	b = append(b, " ("...)
	for i, sev := range severities {
		if i > 0 {
			b = append(b, ", "...)
		}
		b = append(b, sev.String()...)
		b = append(b, ' ')
		b = strconv.AppendInt(b, int64(counts[sev]), 10)
	}
	b = append(b, ")\n"...)
	return write(w, b)
}

func appendFinding(b []byte, f finding.Finding) []byte {
	b = append(b, "- "...)
	b = appendText(b, f.ID)
	b = append(b, ": "...)
	b = appendText(b, f.Title)
	b = append(b, '\n')
	if f.File != "" {
		b = append(b, "  file: "...)
		b = appendText(b, f.File)
		if f.Line > 0 {
			b = append(b, ':')
			b = strconv.AppendInt(b, int64(f.Line), 10)
		}
		b = append(b, '\n')
	}
	for _, field := range [...]struct{ label, value string }{
		{"category", f.Category}, {"reasoning", f.Description}, {"evidence", f.Evidence},
	} {
		if field.value == "" {
			continue
		}
		b = append(b, "  "+field.label+": "...)
		b = appendText(b, field.value)
		b = append(b, '\n')
	}
	if len(f.Metadata) == 0 {
		return b
	}
	keys := make([]string, 0, len(f.Metadata))
	for k := range f.Metadata {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	b = append(b, "  metadata: "...)
	for i, k := range keys {
		if i > 0 {
			b = append(b, ", "...)
		}
		b = appendText(b, k)
		b = append(b, '=')
		b = appendMetadataValue(b, f.Metadata[k])
	}
	return append(b, '\n')
}

// appendMetadataValue handles the types validMetadata allows.
func appendMetadataValue(b []byte, v any) []byte {
	switch x := v.(type) {
	case string:
		return appendQuotedText(b, x)
	case bool:
		return strconv.AppendBool(b, x)
	case int:
		return strconv.AppendInt(b, int64(x), 10)
	case int64:
		return strconv.AppendInt(b, x, 10)
	case float64:
		return strconv.AppendFloat(b, x, 'g', -1, 64)
	}
	panic("report: metadata type not checked by validMetadata")
}

func appendFailure(b []byte, fl scanner.Failure) []byte {
	if text, ok := registryFailureText[fl.Reason]; ok && fl.Scanner == scanner.RegistryName {
		return append(b, text...)
	}
	b = appendText(b, fl.Scanner)
	b = append(b, ": "...)
	return appendText(b, string(fl.Reason))
}
