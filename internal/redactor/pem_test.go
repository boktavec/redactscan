package redactor

import (
	"errors"
	"strings"
	"testing"
)

func TestPEMBlockTypes(t *testing.T) {
	g := newSecretGen(20)
	for _, typeName := range []string{"RSA", "EC", "DSA", "OPENSSH", "ENCRYPTED", "", "SOME OTHER"} {
		for _, eol := range []string{"\n", "\r\n"} {
			block := g.pemBlock(typeName, eol)
			got, counts := mustRedact(t, "before"+eol+block+eol+"after")
			assertOutput(t, got, "before"+eol+"[PRIVATE_KEY_1]"+eol+"after")
			if counts[KindPrivateKey] != 1 {
				t.Errorf("type %q: count = %d, want 1", typeName, counts[KindPrivateKey])
			}
		}
	}
}

func TestPEMPGPBlock(t *testing.T) {
	g := newSecretGen(21)
	body := g.from(base64Chars, 64)
	in := pemMarkerPGP("BEGIN") + "\n" + body + "\n" + pemMarkerPGP("END") + "\ntail"
	got, _ := mustRedact(t, in)
	assertOutput(t, got, "[PRIVATE_KEY_1]\ntail")
}

func TestPEMLowercaseMarkers(t *testing.T) {
	g := newSecretGen(22)
	block := strings.ToLower(g.pemBlock("RSA", "\n"))
	got, _ := mustRedact(t, "x\n"+block+"\ny")
	assertOutput(t, got, "x\n[PRIVATE_KEY_1]\ny")
}

func TestPEMEncryptedHeadersAreCovered(t *testing.T) {
	g := newSecretGen(23)
	header := "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC," + g.from("0123456789ABCDEF", 32) + "\n\n"
	block := pemMarker("BEGIN", "RSA") + "\n" + header + g.from(base64Chars, 64) + "\n" + pemMarker("END", "RSA")
	got, _ := mustRedact(t, block)
	assertOutput(t, got, "[PRIVATE_KEY_1]")
}

func TestPEMNestedBeginInsideBlock(t *testing.T) {
	g := newSecretGen(24)
	in := pemMarker("BEGIN", "RSA") + "\n" + g.from(base64Chars, 64) + "\n" +
		pemMarker("BEGIN", "EC") + "\n" + g.from(base64Chars, 64) + "\n" +
		pemMarker("END", "RSA") + "\nafter"
	got, counts := mustRedact(t, in)
	// The nested BEGIN is skipped by construction; the first END closes the block.
	assertOutput(t, got, "[PRIVATE_KEY_1]\nafter")
	if counts[KindPrivateKey] != 1 {
		t.Errorf("count = %d, want 1", counts[KindPrivateKey])
	}
}

func TestPEMTypeMismatchRedactsToEOF(t *testing.T) {
	g := newSecretGen(25)
	in := "head\n" + g.pemBlockWith("RSA", "EC", "\n") + "\nlater text\n" + g.pemBlock("DSA", "\n")
	got, _ := mustRedact(t, in)
	assertOutput(t, got, "head\n[PRIVATE_KEY_1]")
}

func TestPEMUnterminatedRedactsToEOF(t *testing.T) {
	g := newSecretGen(26)
	body := g.from(base64Chars, 64)
	in := "head\n" + pemMarker("BEGIN", "RSA") + "\n" + body + "\nmore"
	got, _ := mustRedact(t, in)
	assertOutput(t, got, "head\n[PRIVATE_KEY_1]")
}

func TestPEMTwoBlocksGetDistinctLabels(t *testing.T) {
	g := newSecretGen(27)
	in := g.pemBlock("RSA", "\n") + "\nmid\n" + g.pemBlock("EC", "\n")
	got, counts := mustRedact(t, in)
	assertOutput(t, got, "[PRIVATE_KEY_1]\nmid\n[PRIVATE_KEY_2]")
	if counts[KindPrivateKey] != 2 {
		t.Errorf("count = %d, want 2", counts[KindPrivateKey])
	}
}

func TestPEMOrphanedEndAtStart(t *testing.T) {
	g := newSecretGen(28)
	in := "Proc-Type: 4,ENCRYPTED\n" + g.from(base64Chars, 64) + "\n" + pemMarker("END", "RSA") + "\ntail"
	got, _ := mustRedact(t, in)
	assertOutput(t, got, "[PRIVATE_KEY_1]\ntail")
}

func TestPEMOrphanedEndAfterEarlierBlock(t *testing.T) {
	g := newSecretGen(29)
	first := g.pemBlock("RSA", "\n")
	orphanBody := g.from(base64Chars, 64)
	in := "a\n" + first + "\nkept text\n" + orphanBody + "\n" + pemMarker("END", "EC") + "\nz"
	got, counts := mustRedact(t, in)
	// The orphan span starts where the earlier block ended, so it touches the
	// block and the two merge into one span (the text between is over-redacted).
	assertOutput(t, got, "a\n[PRIVATE_KEY_1]\nz")
	if counts[KindPrivateKey] != 1 {
		t.Errorf("count = %d, want 1", counts[KindPrivateKey])
	}
	absent(t, []byte(got), orphanBody, "orphan body")
}

func TestPEMManyOrphanedEnds(t *testing.T) {
	end := pemMarker("END", "RSA")
	got, _ := mustRedact(t, "x"+end+"y"+end+"z")
	assertOutput(t, got, "[PRIVATE_KEY_1]z") // touching orphan spans merge
}

func TestPEMNearMissesAreUntouched(t *testing.T) {
	for _, in := range []string{
		"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
		"-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----",
	} {
		got, counts := mustRedact(t, in)
		assertOutput(t, got, in)
		if len(counts) != 0 {
			t.Errorf("counts = %v, want none", counts)
		}
	}
}

// A marker the detector does not cover (five type words) still trips the
// looser verifier, so it fails closed instead of passing through.
func TestPEMUncoveredMarkerFailsClosed(t *testing.T) {
	_, err := Redact([]byte(pemMarker("BEGIN", "A B C D E")))
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("err = %v, want ErrVerificationFailed", err)
	}
}
