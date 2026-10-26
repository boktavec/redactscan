package finding

import (
	"errors"
	"maps"
	"reflect"
	"strings"
	"testing"

	"github.com/boktavec/redactscan/internal/artifact"
)

func baseline() Finding { return Finding{Severity: SeverityLow} }

func TestZeroFindingSeverityIsInvalid(t *testing.T) {
	t.Parallel()
	if (Finding{}).Severity != SeverityInvalid {
		t.Error("Finding{}.Severity is not SeverityInvalid")
	}
}

func TestFindingValidate(t *testing.T) {
	t.Parallel()
	badMeta := map[string]any{"k": []byte("x")}
	withEvidence := func(e string) Finding { f := baseline(); f.Evidence = e; return f }
	tests := []struct {
		name    string
		f       Finding
		want    string // empty means valid
		wantErr error
	}{
		{"baseline", baseline(), "", nil},
		{"evidence at limit", withEvidence(strings.Repeat("a", MaxEvidenceBytes)), "", nil},
		{"multi-byte at limit", withEvidence(strings.Repeat("é", MaxEvidenceBytes/2)), "", nil},
		{"zero value", Finding{}, "invalid severity", nil},
		{"severity 99", Finding{Severity: 99}, "invalid severity", nil},
		{"evidence too long", withEvidence(strings.Repeat("a", MaxEvidenceBytes+1)), "evidence is 257 bytes, max 256", nil},
		{"evidence not UTF-8", withEvidence("ok\xff"), "evidence is not valid UTF-8", nil},
		{"limit counts bytes not runes", withEvidence(strings.Repeat("\u00e9", MaxEvidenceBytes/2+1)), "evidence is 258 bytes, max 256", nil},
		{"order: UTF-8 before metadata", Finding{Severity: SeverityLow, Evidence: "ok\xff", Metadata: badMeta}, "evidence is not valid UTF-8", nil},
		{"bad metadata", Finding{Severity: SeverityLow, Metadata: badMeta}, "metadata: ", artifact.ErrInvalidMetadata},
		{"order: severity first", Finding{Evidence: strings.Repeat("a", 300), Metadata: badMeta}, "invalid severity", nil},
		{"order: evidence before metadata", Finding{Severity: SeverityLow, Evidence: strings.Repeat("a", 300), Metadata: badMeta}, "evidence is 300 bytes", nil},
		{"order: length before UTF-8", withEvidence(strings.Repeat("\xff", 300)), "evidence is 300 bytes", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.f.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Validate() = %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidFinding) {
				t.Fatalf("err = %v, want ErrInvalidFinding", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want substring %q", err, tt.want)
			}
		})
	}
}

func TestFindingValidateDoesNotEchoContent(t *testing.T) {
	t.Parallel()
	secret := strings.Join([]string{"sk", "live", "Zq8"}, "_") + strings.Repeat("A", 40)
	tests := map[string]Finding{
		"long evidence":   {Severity: SeverityLow, Evidence: secret + strings.Repeat("e", MaxEvidenceBytes)},
		"bad UTF-8":       {Severity: SeverityLow, Evidence: secret + "\xff"},
		"metadata key":    {Severity: SeverityLow, Metadata: map[string]any{secret: []byte(secret)}},
		"metadata value":  {Severity: SeverityLow, Metadata: map[string]any{"k": secret + strings.Repeat("v", 300)}},
		"invalid sev + e": {Evidence: secret},
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := f.Validate()
			if err == nil {
				t.Fatal("err = nil, want error")
			}
			for i := 0; i+8 <= len(secret); i++ {
				if strings.Contains(err.Error(), secret[i:i+8]) {
					t.Fatalf("error echoes content: %q", err)
				}
			}
		})
	}
}

func TestFindingValidateDoesNotMutate(t *testing.T) {
	t.Parallel()
	meta := map[string]any{"k": "v", "n": 1}
	f := Finding{Severity: SeverityLow, Evidence: "ok\xff", Metadata: meta}
	orig := f
	origMeta := maps.Clone(meta)
	_ = f.Validate()
	if !reflect.DeepEqual(f, orig) || !maps.Equal(meta, origMeta) {
		t.Error("Validate modified the finding")
	}
}
