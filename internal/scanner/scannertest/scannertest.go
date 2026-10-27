// Package scannertest holds test helpers for scanner implementations. Every
// scanner's tests must call AssertNoMutation, because the scanner contract
// forbids modifying content and artifact metadata and Registry.Run does not
// enforce it.
package scannertest

import (
	"bytes"
	"context"
	"maps"
	"testing"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/scanner"
)

// AssertNoMutation calls s.Scan once and fails t if Scan changed content or
// a.Metadata. The artifact must be valid (a.Validate), or the test fails
// without calling Scan. Metadata is scalar-only (enforced by that Validate
// gate), so a shallow comparison detects every change.
func AssertNoMutation(t testing.TB, s scanner.Scanner, a artifact.Artifact, content []byte) {
	t.Helper()
	// maps.Equal panics on uncomparable values; Validate rejects them.
	if a.Validate() != nil {
		t.Error("artifact is invalid: metadata must pass artifact.ValidateMetadata")
		return
	}
	contentBefore := bytes.Clone(content)
	metadataBefore := maps.Clone(a.Metadata)

	_, _ = s.Scan(context.Background(), a, content)

	if !bytes.Equal(content, contentBefore) {
		t.Error("Scan modified content")
	}
	if !maps.Equal(a.Metadata, metadataBefore) {
		t.Error("Scan modified artifact metadata")
	}
}
