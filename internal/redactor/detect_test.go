package redactor

import (
	"strings"
	"testing"
)

func mustRedact(t *testing.T, input string) (string, map[Kind]int) {
	t.Helper()
	res, err := Redact([]byte(input))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	return string(res.Output), res.Counts
}

func TestAWSAccessKeyDetection(t *testing.T) {
	g := newSecretGen(10)
	akia, asia := g.awsKeyID("AKIA"), g.awsKeyID("ASIA")
	tests := []struct {
		name, input, want string
	}{
		{"akia", "k=" + akia + "!", "k=[AWS_ACCESS_KEY_1]!"},
		{"asia", asia, "[AWS_ACCESS_KEY_1]"},
		{"embedded after underscore", "AWS_KEY_" + akia, "AWS_KEY_[AWS_ACCESS_KEY_1]"},
		{"back to back", akia + asia, "[AWS_ACCESS_KEY_1]"}, // touching spans merge into one
		{"trailing x", akia + "x", "[AWS_ACCESS_KEY_1]x"},
		{"leading letters", "xyz" + akia, "xyz[AWS_ACCESS_KEY_1]"},
		{"too short", akia[:19], akia[:19]},
		{"lowercase prefix", "akia" + akia[4:], "akia" + akia[4:]},
		{"lowercase body", "AKIA" + strings.ToLower(akia[4:]) + "", "AKIA" + strings.ToLower(akia[4:])},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := mustRedact(t, tt.input)
			assertOutput(t, got, tt.want)
		})
	}
}

// assertOutput compares output to the expected text. On mismatch it reports
// lengths and the first differing index, never the output, which may hold a
// surviving secret.
func assertOutput(t *testing.T, got, want string) {
	t.Helper()
	if got == want {
		return
	}
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	t.Errorf("output mismatch: got len %d, want len %d, first difference at %d (want %q...)",
		len(got), len(want), i, want[:min(len(want), i+8)])
}

func TestAWSSecretKeyDetection(t *testing.T) {
	g := newSecretGen(11)
	v := g.awsSecret()
	tests := []struct {
		name, input, want string
	}{
		{"env", "AWS_SECRET_ACCESS_KEY=" + v, "AWS_SECRET_ACCESS_KEY=[AWS_SECRET_KEY_1]"},
		{"yaml", "aws_secret_access_key: " + v, "aws_secret_access_key: [AWS_SECRET_KEY_1]"},
		{"json", `"aws_secret_access_key": "` + v + `"`, `"aws_secret_access_key": "[AWS_SECRET_KEY_1]"`},
		{"quoted single with spaces", "aws_secret_access_key = '" + v + "'", "aws_secret_access_key = '[AWS_SECRET_KEY_1]'"},
		{"fat arrow", "aws_secret_access_key => " + v, "aws_secret_access_key => [AWS_SECRET_KEY_1]"},
		{"walrus", "aws_secret_access_key := " + v, "aws_secret_access_key := [AWS_SECRET_KEY_1]"},
		{"export", `export AWS_SECRET_ACCESS_KEY="` + v + `"`, `export AWS_SECRET_ACCESS_KEY="[AWS_SECRET_KEY_1]"`},
		{"hyphenated name", "aws-secret-access-key=" + v, "aws-secret-access-key=[AWS_SECRET_KEY_1]"},
		{"tail extended over base64 chars", "AWS_SECRET_ACCESS_KEY=" + v + "ab==", "AWS_SECRET_ACCESS_KEY=[AWS_SECRET_KEY_1]"},
		{"unanchored 40 char run untouched", "token " + v, "token " + v},
		{"too short value untouched", "AWS_SECRET_ACCESS_KEY=" + v[:39], "AWS_SECRET_ACCESS_KEY=" + v[:39]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := mustRedact(t, tt.input)
			assertOutput(t, got, tt.want)
		})
	}
}

func TestGitHubTokenDetection(t *testing.T) {
	g := newSecretGen(12)
	for _, kind := range []byte("pousr") {
		for _, n := range []int{36, 37, 255, 256, 300} {
			tok := g.ghClassic(kind, n)
			got, counts := mustRedact(t, "t="+tok+" end")
			assertOutput(t, got, "t=[GITHUB_TOKEN_1] end")
			if counts[KindGitHubToken] != 1 {
				t.Errorf("gh%c_ body %d: count = %d", kind, n, counts[KindGitHubToken])
			}
		}
	}
	for _, n := range []int{22, 82, 300} {
		tok := g.ghFine(n)
		got, _ := mustRedact(t, "x"+tok+".")
		assertOutput(t, got, "x[GITHUB_TOKEN_1].")
	}
	// Wrong prefix letter is not a token and not loose-flagged either.
	notToken := "ghx_" + g.from(alnum, 40)
	got, _ := mustRedact(t, notToken)
	assertOutput(t, got, notToken)
}

func TestGitHubTokenAdjacentToAWSKeyDoesNotFalseFail(t *testing.T) {
	g := newSecretGen(13)
	tok, key := g.ghClassic('p', 36), g.awsKeyID("AKIA")
	for _, in := range []string{tok + key, key + tok} {
		got, counts := mustRedact(t, in)
		assertOutput(t, got, "[GITHUB_TOKEN_1]")
		if counts[KindAWSAccessKey] != 0 {
			t.Error("merged span must take the higher-priority GITHUB_TOKEN kind")
		}
	}
}

// Regression for security finding F1: a stray AKIA/ASIA prefix just before a
// real key must not end the match partway into the key and leave its tail.
func TestAWSKeyPrefixBeforeRealKeyLeavesNoBody(t *testing.T) {
	g := newSecretGen(14)
	key := g.awsKeyID("AKIA")
	body := key[4:]
	tests := []struct {
		name, input string
	}{
		{"AKIA directly before key", "AKIA" + key},
		{"AKIA and 12 characters before key", "AKIA" + g.from(upperDigits, 12) + key},
		{"ASIA and 8 characters before key", "ASIA" + g.from(upperDigits, 8) + key},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := mustRedact(t, tt.input)
			assertOutput(t, got, "[AWS_ACCESS_KEY_1]")
			absent(t, []byte(got), body, "key body")
		})
	}
}
