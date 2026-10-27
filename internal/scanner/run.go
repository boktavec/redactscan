package scanner

import (
	"cmp"
	"context"
	"slices"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
)

// Run scans one artifact with every supported scanner, in registry order and
// one at a time. See the package doc and ADR 0004 for the failure rules.
func (r *Registry) Run(ctx context.Context, a artifact.Artifact, content []byte) Result {
	if a.Validate() != nil {
		return Result{Failures: []Failure{{RegistryName, ReasonInvalidArtifact}}}
	}
	if len(content) > MaxContentSize {
		return Result{Failures: []Failure{{RegistryName, ReasonTooLarge}}}
	}

	var res Result
	record := func(name string, reason Reason) {
		f := Failure{name, reason}
		if !slices.Contains(res.Failures, f) {
			res.Failures = append(res.Failures, f)
		}
	}

	for i, e := range r.entries {
		if ctx.Err() != nil {
			for _, rest := range r.entries[i:] {
				record(rest.name, ReasonCanceled)
			}
			break
		}

		var supported bool
		if !call(func() { supported = e.s.Supports(a) }) {
			record(e.name, ReasonPanic)
			continue
		}
		if !supported {
			continue
		}

		var found []finding.Finding
		var err error
		if !call(func() { found, err = e.s.Scan(ctx, a, content) }) {
			record(e.name, ReasonPanic)
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				record(e.name, ReasonCanceled)
			} else {
				record(e.name, ReasonError)
			}
			continue
		}

		res.Ran++
		for _, f := range found {
			if !checkFinding(f, a) {
				record(e.name, ReasonInvalidFinding)
				continue
			}
			res.Findings = append(res.Findings, f)
		}
	}

	if res.Ran == 0 {
		record(RegistryName, ReasonNoScanner)
	}
	sortFindings(res.Findings)
	return res
}

// call runs f on its own goroutine and waits. It reports false if f panicked
// (including panic(nil)) or called runtime.Goexit. The panic value is dropped.
// The completed flag, not recover() != nil, detects both cases.
func call(f func()) bool {
	done := make(chan bool, 1)
	go func() {
		completed := false
		defer func() {
			if !completed {
				_ = recover() // stops a panic; Goexit still runs this defer
			}
			done <- completed
		}()
		f()
		completed = true
	}()
	return <-done
}

// checkFinding reports whether f may be accepted for artifact a. PR 1b
// replaces it with the full bounds and redactor checks (check.go).
func checkFinding(f finding.Finding, a artifact.Artifact) bool {
	return f.Validate() == nil && f.ArtifactID == a.ID
}

// sortFindings orders by severity descending, then by identifying fields
// ascending, so the result does not depend on registry order.
func sortFindings(fs []finding.Finding) {
	slices.SortStableFunc(fs, func(x, y finding.Finding) int {
		return cmp.Or(
			y.Severity.Compare(x.Severity),
			cmp.Compare(x.ArtifactID, y.ArtifactID),
			cmp.Compare(x.File, y.File),
			cmp.Compare(x.Line, y.Line),
			cmp.Compare(x.ID, y.ID),
			cmp.Compare(x.Category, y.Category),
			cmp.Compare(x.Title, y.Title),
			cmp.Compare(x.Evidence, y.Evidence),
		)
	})
}
