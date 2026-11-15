// Package scanner defines the Scanner interface and the Registry that runs
// scanners over one artifact. It opens nothing: the caller opens the content
// and Run hands scanners a bounded io.ReaderAt over it (ADR 0007).
//
// Scanned content is untrusted, and so is scanner output, because it is
// derived from that content. Registry.Run is fail-closed: anything that stops
// a scanner from running cleanly is recorded as a Failure and makes the
// Result incomplete, while findings from the other scanners are kept.
//
// # Scanner contract
//
// A Scanner implementation must:
//   - not call os.Exit, log.Fatal or runtime.Goexit;
//   - not start goroutines that outlive Scan or that can panic unrecovered;
//   - read content only through the ReaderAt it is given: never past size,
//     never keep it after Scan returns, and never allocate size bytes at once
//     (a buffering scanner keeps its own small cap);
//   - not modify a.Metadata (shared and read-only; call
//     scannertest.AssertNoMutation in its tests);
//   - use only constant text in panics and errors, never scanned content;
//   - return only redacted-or-bounded findings, as the finding package
//     requires;
//   - check ctx in long loops;
//   - never execute, load or open anything named by the content.
//
// Run wraps the caller's reader in an opaque bounded type, so a scanner cannot
// reach the underlying file, and replaces read errors, which can carry paths,
// with fixed text. It reads nothing itself, so the content is read live, once
// per scanner: a file that changes during the scan can give scanners different
// bytes, and the caller must detect that.
//
// Registry.Run drops a finding that breaks the field contract in check.go
// (identifier grammars for ID, Category and Metadata keys, size limits, UTF-8,
// and redactor checks on every text field) and records an invalid finding.
//
// Run's isolation (recovered panics, Goexit, discarded errors) does not cover
// goroutines a scanner starts: a panic there crashes the process.
package scanner

import (
	"context"
	"io"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
)

// Limits. MaxContentSize is an assumed default (ADR 0007).
const (
	MaxContentSize = 1 << 30 // largest content Run scans (1 GiB)
	MaxFindings    = 1000    // accepted findings per Run
	MaxIDBytes     = 128
	MaxTitleBytes  = 128
	MaxFileBytes   = 4096

	MaxCategoryBytes    = 64
	MaxDescriptionBytes = 1024
)

// Scanner inspects one artifact. See the package doc for the contract.
type Scanner interface {
	// Name is a stable identifier matching ^[a-z0-9][a-z0-9-]{0,31}$. The
	// registry calls it once, at registration.
	Name() string
	// Supports reports whether Scan should run for a.
	Supports(a artifact.Artifact) bool
	// Scan returns findings for a. r holds exactly size bytes and is valid only
	// during the call; read it with ReadAt, never past size.
	Scan(ctx context.Context, a artifact.Artifact, r io.ReaderAt, size int64) ([]finding.Finding, error)
}

// Reason says why a scanner, or the registry, did not complete cleanly. These
// are the only values Run produces.
type Reason string

const (
	ReasonError           Reason = "error"
	ReasonPanic           Reason = "panic"
	ReasonInvalidFinding  Reason = "invalid finding"
	ReasonCanceled        Reason = "canceled"
	ReasonTooLarge        Reason = "too large"
	ReasonInvalidArtifact Reason = "invalid artifact"
	ReasonNoScanner       Reason = "no scanner"
	ReasonTooManyFindings Reason = "too many findings"
)

// Failure records one abnormal outcome. It carries no error or panic text.
type Failure struct {
	Scanner string // registered name, or RegistryName
	Reason  Reason
}

// Result is the outcome of Registry.Run.
type Result struct {
	Findings []finding.Finding // validated, checked, sorted
	Failures []Failure         // in recorded order, one per (scanner, reason)
	Ran      int               // scanners whose Scan returned without error or panic
}

// Incomplete reports whether anything prevented a clean scan.
func (r Result) Incomplete() bool { return len(r.Failures) > 0 }
