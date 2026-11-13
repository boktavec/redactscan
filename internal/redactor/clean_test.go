package redactor

import (
	"strings"
	"testing"
)

func TestIsClean(t *testing.T) {
	t.Parallel()
	// Guards the assumption behind IsClean: label-like text is the only kind
	// accepted, and the redactor reports it as KindLabelLike.
	res, err := Redact([]byte("[GITHUB_TOKEN_1]"))
	if err != nil || res.Counts[KindLabelLike] != 1 {
		t.Fatalf("redactor changed: counts=%v err=%v", res.Counts, err)
	}
	secret := strings.Join([]string{"AK", "IA"}, "") + "IOSFODNN7EXAMPLE"
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", true},
		{"plain", "install.sh", true},
		{"label-like", "[GITHUB_TOKEN_1]", true},
		{"secret", secret, false},
		{"secret in text", "key " + secret + " end", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsClean(tt.in); got != tt.want {
				t.Errorf("IsClean() = %v, want %v", got, tt.want)
			}
		})
	}
}
