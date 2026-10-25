package redactor

import (
	"bytes"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// Test secrets are generated at runtime from a seeded source so the
// repository never contains literal key material. Nothing here is a real
// credential. Failure messages must report kind and length, never a value.

const (
	upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	alnum       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	alnumUnder  = alnum + "_"
	base64Chars = alnum + "/+"
)

type secretGen struct{ r *rand.Rand }

func newSecretGen(seed int64) *secretGen {
	return &secretGen{r: rand.New(rand.NewSource(seed))} //nolint:gosec // deterministic test data, not security-relevant
}

func (g *secretGen) from(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[g.r.Intn(len(alphabet))]
	}
	return string(b)
}

// awsKeyID returns prefix (AKIA or ASIA) plus 16 upper/digit characters.
func (g *secretGen) awsKeyID(prefix string) string { return prefix + g.from(upperDigits, 16) }

// awsSecret returns a 40 character base64-alphabet value.
func (g *secretGen) awsSecret() string { return g.from(base64Chars, 40) }

// ghClassic returns gh<p|o|u|s|r>_ plus n alphanumerics.
func (g *secretGen) ghClassic(kind byte, n int) string {
	return "gh" + string(kind) + "_" + g.from(alnum, n)
}

// ghFine returns a fine-grained token with n body characters.
func (g *secretGen) ghFine(n int) string { return "github_pat_" + g.from(alnumUnder, n) }

// pemBlock returns a block whose type is typeName (for example "RSA" or "").
// Markers are assembled at runtime so no marker literal sits in the source.
func (g *secretGen) pemBlock(typeName, eol string) string {
	return g.pemBlockWith(typeName, typeName, eol)
}

// pemBlockWith allows differing BEGIN and END types.
func (g *secretGen) pemBlockWith(beginType, endType, eol string) string {
	var b strings.Builder
	b.WriteString(pemMarker("BEGIN", beginType) + eol)
	for i := 0; i < 4; i++ {
		b.WriteString(g.from(base64Chars, 64) + eol)
	}
	b.WriteString(pemMarker("END", endType))
	return b.String()
}

// pemMarker builds a "<word> <type> PRIVATE KEY" marker between dashes.
func pemMarker(word, typeName string) string {
	dashes := strings.Repeat("-", 5)
	if typeName == "" {
		return dashes + word + " PRIVATE KEY" + dashes
	}
	return dashes + word + " " + typeName + " PRIVATE KEY" + dashes
}

// pemMarkerPGP builds the PGP "PRIVATE KEY BLOCK" marker form.
func pemMarkerPGP(word string) string {
	dashes := strings.Repeat("-", 5)
	return dashes + word + " PGP PRIVATE KEY BLOCK" + dashes
}

// absent fails the test if secret survives in out, reporting only length.
func absent(t *testing.T, out []byte, secret, what string) {
	t.Helper()
	if secret != "" && bytes.Contains(out, []byte(secret)) {
		t.Errorf("%s (len %d) survived in output", what, len(secret))
	}
}

func TestGeneratedSecretsMatchDocumentedFormats(t *testing.T) {
	g := newSecretGen(1)
	tests := []struct {
		name  string
		value string
		re    string
	}{
		{"akia", g.awsKeyID("AKIA"), `^AKIA[A-Z0-9]{16}$`},
		{"asia", g.awsKeyID("ASIA"), `^ASIA[A-Z0-9]{16}$`},
		{"aws secret", g.awsSecret(), `^[A-Za-z0-9/+]{40}$`},
		{"ghp", g.ghClassic('p', 36), `^ghp_[A-Za-z0-9]{36}$`},
		{"ghs", g.ghClassic('s', 36), `^ghs_[A-Za-z0-9]{36}$`},
		{"fine grained", g.ghFine(82), `^github_pat_[A-Za-z0-9_]{82}$`},
		{"pem rsa", g.pemBlock("RSA", "\n"), `(?s)^-{5}BEGIN RSA PRIVATE[ ]KEY-{5}\n.*\n-{5}END RSA PRIVATE[ ]KEY-{5}$`},
		{"pem empty type", g.pemBlock("", "\r\n"), `(?s)^-{5}BEGIN PRIVATE[ ]KEY-{5}\r\n.*\r\n-{5}END PRIVATE[ ]KEY-{5}$`},
	}
	for _, tt := range tests {
		if !regexp.MustCompile(tt.re).MatchString(tt.value) {
			t.Errorf("%s: generated value (len %d) does not match its format", tt.name, len(tt.value))
		}
	}
}

func TestGeneratorIsDeterministicPerSeed(t *testing.T) {
	first, second := newSecretGen(7), newSecretGen(7)
	if first.awsSecret() != second.awsSecret() {
		t.Error("same seed produced different values")
	}
	if newSecretGen(7).awsSecret() == newSecretGen(8).awsSecret() {
		t.Error("different seeds produced the same value")
	}
}
