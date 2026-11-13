// Package report renders a scanner.Result as a text report or a versioned JSON
// document (ADR 0005). It performs no I/O except one Write to the caller's
// writer, and it never uses reflection formatting: it imports no fmt and never
// formats a Finding, a Result or an any value.
//
// # Escaping
//
// Every string taken from a finding or a failure is untrusted. Both renderers
// escape every dangerous rune (see textsafe.IsDangerous) visibly instead of deleting it:
// text writes Go-style escapes such as \x1b or \u202e, JSON writes \uXXXX.
// In text an invalid UTF-8 byte is written as \xNN and a backslash as \\. In
// JSON an invalid UTF-8 byte in a field becomes U+FFFD, which is a limit of
// encoding/json, so a file name from disk is lossy there.
//
// # Schema version
//
// The JSON document carries SchemaVersion. It changes only for a breaking
// change: a removed or renamed field, or a changed type or meaning. Adding a
// field does not change it. Arrays and objects are never null.
//
// # Consumers
//
// status is derived only from Result.Incomplete. Check the process exit code
// first, and treat empty or unparseable output as a failed scan, never as a
// clean one. A caller that renders a directory scan must also report
// incomplete when ingest.Walk returns ErrIncomplete, even if
// Result.Incomplete is false (follow-up F2).
package report

import (
	"errors"
	"io"
	"math"

	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/scanner"
)

// SchemaVersion is the schema_version of the JSON document.
const SchemaVersion = 1

// Errors returned by Text and JSON. Their text is constant and never carries
// report content.
var (
	ErrWrite  = errors.New("report: write failed")
	ErrRender = errors.New("report: cannot render")
)

const (
	statusComplete   = "complete"
	statusIncomplete = "incomplete"
)

// severities lists the five real severities, most severe first.
var severities = [...]finding.Severity{
	finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
	finding.SeverityLow, finding.SeverityInfo,
}

// status derives the report status only from res.Incomplete().
func status(res scanner.Result) string {
	if res.Incomplete() {
		return statusIncomplete
	}
	return statusComplete
}

// group maps every invalid severity to SeverityInvalid, so counts has a slot
// for each finding (FR11).
func group(s finding.Severity) finding.Severity {
	if s.Valid() {
		return s
	}
	return finding.SeverityInvalid
}

// countBySeverity is indexed by group(severity).
func countBySeverity(fs []finding.Finding) [finding.SeverityCritical + 1]int {
	var counts [finding.SeverityCritical + 1]int
	for _, f := range fs {
		counts[group(f.Severity)]++
	}
	return counts
}

// write sends the whole report in one Write. A write error or short write is
// ErrWrite.
func write(w io.Writer, b []byte) error {
	if n, err := w.Write(b); err != nil || n != len(b) {
		return ErrWrite
	}
	return nil
}

// validMetadata is the one metadata check both renderers run before building
// output. It allows exactly the types artifact.ValidateMetadata allows, with
// finite floats. Named types are rejected too, so none can bring a MarshalJSON.
func validMetadata(fs []finding.Finding) bool {
	for _, f := range fs {
		for _, v := range f.Metadata {
			switch x := v.(type) {
			case string, bool, int, int64:
			case float64:
				if math.IsNaN(x) || math.IsInf(x, 0) {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}
