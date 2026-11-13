package report

import (
	"encoding/json"
	"io"

	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/scanner"
)

// The document types fix the key order of the JSON report.
type document struct {
	SchemaVersion int           `json:"schema_version"`
	Status        string        `json:"status"`
	Summary       summary       `json:"summary"`
	Findings      []jsonFinding `json:"findings"`
	Failures      []jsonFailure `json:"failures"`
}

type summary struct {
	Total      int            `json:"total"`
	BySeverity severityCounts `json:"by_severity"`
}

type severityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type jsonFinding struct {
	ID          string         `json:"id"`
	Severity    string         `json:"severity"`
	Category    string         `json:"category"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	File        string         `json:"file"`
	Line        int            `json:"line"`
	Evidence    string         `json:"evidence"`
	Metadata    map[string]any `json:"metadata"`
}

type jsonFailure struct {
	Scanner string `json:"scanner"`
	Reason  string `json:"reason"`
}

// JSON writes the versioned JSON document for res, one compact line, with one
// Write. Any marshal or escaping error is ErrRender and nothing is written.
func JSON(w io.Writer, res scanner.Result) error {
	if !validMetadata(res.Findings) {
		return ErrRender
	}
	counts := countBySeverity(res.Findings)
	doc := document{
		SchemaVersion: SchemaVersion,
		Status:        status(res),
		Summary: summary{
			Total: len(res.Findings),
			BySeverity: severityCounts{
				Critical: counts[finding.SeverityCritical],
				High:     counts[finding.SeverityHigh],
				Medium:   counts[finding.SeverityMedium],
				Low:      counts[finding.SeverityLow],
				Info:     counts[finding.SeverityInfo],
			},
		},
		Findings: make([]jsonFinding, 0, len(res.Findings)),
		Failures: make([]jsonFailure, 0, len(res.Failures)),
	}
	for _, f := range res.Findings {
		md := f.Metadata
		if md == nil {
			md = map[string]any{}
		}
		doc.Findings = append(doc.Findings, jsonFinding{
			ID: f.ID, Severity: f.Severity.String(), Category: f.Category,
			Title: f.Title, Description: f.Description, File: f.File,
			Line: f.Line, Evidence: f.Evidence, Metadata: md,
		})
	}
	for _, fl := range res.Failures {
		doc.Failures = append(doc.Failures, jsonFailure{Scanner: fl.Scanner, Reason: string(fl.Reason)})
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		return ErrRender
	}
	out, err := escapeJSON(raw)
	if err != nil {
		return err
	}
	return write(w, append(out, '\n'))
}
