package redactor

import (
	"errors"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

func TestVerifyLooseChecksFailClosed(t *testing.T) {
	g := newSecretGen(40)
	tests := []struct {
		name string
		out  string
		kind Kind
	}{
		{"aws key", "x " + g.awsKeyID("AKIA"), KindAWSAccessKey},
		{"aws key asia", g.awsKeyID("ASIA"), KindAWSAccessKey},
		{"aws secret with odd separator", "secret_access_key is " + g.awsSecret(), KindAWSSecretKey},
		{"aws secret hyphens", "SECRET-ACCESS-KEY" + g.awsSecret(), KindAWSSecretKey},
		{"truncated github token", g.ghClassic('p', 20), KindGitHubToken},
		{"short fine grained", "github_pat_a", KindGitHubToken},
		{"begin marker", pemMarker("BEGIN", "RSA"), KindPrivateKey},
		{"end marker only", pemMarker("END", ""), KindPrivateKey},
		{"marker tail only", "PRIVATE KEY BLOCK-----", KindPrivateKey},
		{"lowercase marker", strings.ToLower(pemMarker("BEGIN", "EC")), KindPrivateKey},
		{"spoofed label", "[AWS_ACCESS_KEY_1]", KindLabelLike},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verify([]byte(tt.out), nil)
			if !errors.Is(err, ErrVerificationFailed) {
				t.Fatalf("err = %v, want ErrVerificationFailed", err)
			}
			if want := ErrVerificationFailed.Error() + ": " + string(tt.kind); err.Error() != want {
				t.Errorf("error text = %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestVerifyAcceptsExactlyTheEmittedLabels(t *testing.T) {
	out := "a [AWS_ACCESS_KEY_1] b [GITHUB_TOKEN_2]"
	emitted := []int{2, 23}
	if err := verify([]byte(out), emitted); err != nil {
		t.Fatalf("verify rejected emitted labels: %v", err)
	}
	if err := verify([]byte(out), emitted[:1]); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("extra label in output not rejected: %v", err)
	}
	shifted := []int{3, 23}
	if err := verify([]byte(out), shifted); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("label at unexpected offset not rejected: %v", err)
	}
	if err := verify([]byte("no labels"), emitted); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("missing emitted label not rejected: %v", err)
	}
}

func TestVerifyErrorsNameKindOnly(t *testing.T) {
	g := newSecretGen(41)
	secret := g.awsKeyID("AKIA")
	err := verify([]byte("leak "+secret), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) || strings.ContainsAny(err.Error(), "0123456789") {
		t.Error("verification error leaks a value or offset")
	}
}

// Emitted labels for any N must not trip a detector or a loose check.
func TestEmittedLabelsPassEveryCheckForLargeN(t *testing.T) {
	ns := []int{1, 2, 9, 10, 99, 100, 999999, 1000000}
	for n := 1; n <= 1000; n++ {
		ns = append(ns, n)
	}
	r := rand.New(rand.NewSource(42)) //nolint:gosec // deterministic test data
	for i := 0; i < 200; i++ {
		ns = append(ns, 1+r.Intn(1000000))
	}
	for _, kind := range []Kind{KindAWSAccessKey, KindAWSSecretKey, KindGitHubToken, KindPrivateKey} {
		for _, n := range ns {
			label := "[" + string(kind) + "_" + strconv.Itoa(n) + "]"
			if spans := detect([]byte(label)); len(spans) != 1 || spans[0].kind != KindLabelLike {
				t.Fatalf("label %s detected as %v", label, spans)
			}
			if err := verify([]byte(label), []int{0}); err != nil {
				t.Fatalf("label %s failed verification: %v", label, err)
			}
		}
	}
}

func TestVerificationErrorCarriesKind(t *testing.T) {
	err := verify([]byte(newSecretGen(41).ghClassic('p', 20)), nil)

	var ve *VerificationError
	if !errors.As(err, &ve) {
		t.Fatalf("errors.As failed for %v", err)
	}
	if ve.Kind != KindGitHubToken {
		t.Errorf("Kind = %q, want %q", ve.Kind, KindGitHubToken)
	}
	if !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("errors.Is(err, ErrVerificationFailed) = false")
	}
	if want := ErrVerificationFailed.Error() + ": " + string(KindGitHubToken); err.Error() != want {
		t.Errorf("error text = %q, want %q", err.Error(), want)
	}
}
