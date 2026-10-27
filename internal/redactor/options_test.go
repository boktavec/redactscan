package redactor

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var allKinds = []Kind{KindAWSAccessKey, KindAWSSecretKey, KindGitHubToken, KindPrivateKey}

// kindSamples returns one runtime-generated input per secret kind.
func kindSamples() map[Kind]string {
	g := newSecretGen(300)
	return map[Kind]string{
		KindAWSAccessKey: "key " + g.awsKeyID("AKIA") + " end",
		KindAWSSecretKey: "AWS_SECRET_ACCESS_KEY=" + g.awsSecret(),
		KindGitHubToken:  "tok " + g.ghClassic('p', 36) + " end",
		KindPrivateKey:   g.pemBlock("RSA", "\n"),
	}
}

func assertRefused(t *testing.T, res Result, err error, kind Kind) {
	t.Helper()
	var ve *VerificationError
	if !errors.As(err, &ve) || ve.Kind != kind || !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("err = %v, want VerificationError{%s}", err, kind)
	}
	assertNilResult(t, res)
}

// errKind returns the kind named by a VerificationError, or "" for any other
// error (including nil).
func errKind(err error) Kind {
	var ve *VerificationError
	if errors.As(err, &ve) {
		return ve.Kind
	}
	return ""
}

// The verifier must run in full whatever is selected: these shapes are not
// found by any detector, so only verify can refuse them.
func TestRedactWithVerifierStillRunsForEverySelection(t *testing.T) {
	g := newSecretGen(305)
	tests := []struct {
		name  string
		input string
		want  Kind
	}{
		{"truncated github token", "tok " + g.ghClassic('p', 25), KindGitHubToken},
		{"unanchored secret run", "secret_access_key=" + g.awsSecret(), KindAWSSecretKey},
	}
	for _, tt := range tests {
		if _, err := Redact([]byte(tt.input)); errKind(err) != tt.want {
			t.Fatalf("%s: Redact err = %v, want verifier failure %s", tt.name, err, tt.want)
		}
		for _, sel := range allKinds {
			t.Run(tt.name+", "+string(sel)+" selected", func(t *testing.T) {
				res, err := RedactWith([]byte(tt.input), Options{Kinds: []Kind{sel}})
				assertRefused(t, res, err, tt.want)
			})
		}
	}
}

func TestRedactWithDefaultSelectionEqualsRedact(t *testing.T) {
	samples := kindSamples()
	inputs := [][]byte{nil, []byte("plain text"), []byte("[PRIVATE_KEY_1] forged")}
	var mixed []string
	for _, k := range allKinds {
		inputs = append(inputs, []byte(samples[k]))
		mixed = append(mixed, samples[k])
	}
	for _, s := range fuzzSecrets() {
		inputs = append(inputs, []byte("a "+s.embedded+" b"))
	}
	inputs = append(inputs, []byte(strings.Join(mixed, "\n")),
		[]byte("a\x00b")) // an error case too

	selections := map[string][]Kind{
		"nil":        nil,
		"empty":      {},
		"all":        allKinds,
		"duplicates": append(slices.Clone(allKinds), allKinds...),
	}
	for name, kinds := range selections {
		for i, in := range inputs {
			want, wantErr := Redact(in)
			got, err := RedactWith(in, Options{Kinds: kinds})
			if !reflect.DeepEqual(got, want) || errKind(err) != errKind(wantErr) || (err == nil) != (wantErr == nil) {
				t.Errorf("%s, input %d: got (%v, %v), want (%v, %v)", name, i, got.Counts, err, want.Counts, wantErr)
			}
		}
	}
}

func TestRedactWithRejectsUnknownKinds(t *testing.T) {
	bad := []Kind{KindLabelLike, "", "aws_access_key", "Github_Token", "EMAIL", "AWS_ACCESS_KEY "}
	for _, k := range bad {
		for _, kinds := range [][]Kind{{k}, {KindGitHubToken, k}} {
			res, err := RedactWith([]byte("x"), Options{Kinds: kinds})
			if err != ErrUnknownKind {
				t.Errorf("kinds %q: err = %v, want ErrUnknownKind", kinds, err)
			}
			assertNilResult(t, res)
		}
	}
}

func TestRedactWithValidatesOptionsBeforeInput(t *testing.T) {
	opts := Options{Kinds: []Kind{"NOPE"}}
	for name, input := range map[string][]byte{
		"oversize": make([]byte, MaxInputSize+1),
		"NUL":      []byte("a\x00b"),
	} {
		res, err := RedactWith(input, opts)
		if err != ErrUnknownKind {
			t.Errorf("%s: err = %v, want ErrUnknownKind", name, err)
		}
		assertNilResult(t, res)
	}
}

func TestErrUnknownKindTextIsConstant(t *testing.T) {
	const rejected = "NOT_A_KIND_SENTINEL"
	_, err := RedactWith([]byte("x"), Options{Kinds: []Kind{KindGitHubToken, rejected}})
	if err.Error() != "redactor: unknown kind" {
		t.Errorf("error text = %q", err.Error())
	}
}

func TestRedactWithLeavesCallerSliceUnchanged(t *testing.T) {
	kinds := []Kind{KindPrivateKey, KindAWSAccessKey, KindPrivateKey}
	before := slices.Clone(kinds)
	if _, err := RedactWith([]byte(kindSamples()[KindAWSAccessKey]), Options{Kinds: kinds}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(kinds, before) {
		t.Errorf("Kinds modified: %v, want %v", kinds, before)
	}
}

func TestRedactWithSingleKindSelection(t *testing.T) {
	samples := kindSamples()
	for _, sel := range allKinds {
		opts := Options{Kinds: []Kind{sel}}
		for _, present := range allKinds {
			t.Run(string(sel)+" selected, "+string(present)+" present", func(t *testing.T) {
				input := []byte(samples[present])
				res, err := RedactWith(input, opts)
				if present != sel {
					assertRefused(t, res, err, present)
					return
				}
				want, wantErr := Redact(input)
				if err != nil || wantErr != nil || !bytes.Equal(res.Output, want.Output) ||
					!reflect.DeepEqual(res.Counts, want.Counts) {
					t.Fatalf("err = %v (Redact: %v), output differs from Redact", err, wantErr)
				}
			})
		}
	}
}

func TestRedactWithNestedUnselectedKindIsRefused(t *testing.T) {
	g := newSecretGen(301)
	input := []byte("t=" + g.ghClassic('p', 20) + g.awsKeyID("AKIA") + g.from(alnum, 20))
	if _, err := Redact(input); err != nil {
		t.Fatalf("Redact must accept the fixture: %v", err)
	}
	res, err := RedactWith(input, Options{Kinds: []Kind{KindGitHubToken}})
	assertRefused(t, res, err, KindAWSAccessKey)
	res, err = RedactWith(input, Options{Kinds: []Kind{KindAWSAccessKey}})
	assertRefused(t, res, err, KindGitHubToken)
}

func TestRedactWithRefusesSecretKeyFoundOnlyByDetector(t *testing.T) {
	g := newSecretGen(302)
	gap := strings.Repeat(" \t", 10) // 20 characters, beyond the verifier's 16
	input := []byte("aws_secret_access_key" + gap + "=" + gap + g.awsSecret())
	if _, err := Redact(input); err != nil {
		t.Fatalf("Redact must accept the fixture: %v", err)
	}
	res, err := RedactWith(input, Options{Kinds: []Kind{KindGitHubToken}})
	assertRefused(t, res, err, KindAWSSecretKey)
}

func TestRedactWithRefusalOrderIsFixed(t *testing.T) {
	s := kindSamples()
	input := []byte(strings.Join([]string{s[KindPrivateKey], s[KindGitHubToken], s[KindAWSSecretKey], s[KindAWSAccessKey]}, "\n"))
	tests := []struct {
		kinds []Kind
		want  Kind
	}{
		{[]Kind{KindPrivateKey}, KindAWSAccessKey},
		{[]Kind{KindAWSAccessKey}, KindAWSSecretKey},
		{[]Kind{KindAWSAccessKey, KindAWSSecretKey}, KindGitHubToken},
		{[]Kind{KindAWSAccessKey, KindAWSSecretKey, KindGitHubToken}, KindPrivateKey},
	}
	for _, tt := range tests {
		res, err := RedactWith(input, Options{Kinds: tt.kinds})
		assertRefused(t, res, err, tt.want)
	}
}

func TestRedactWithForgedLabelIsIndependentOfSelection(t *testing.T) {
	res, err := RedactWith([]byte("see [PRIVATE_KEY_1] here"), Options{Kinds: []Kind{KindGitHubToken}})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(res.Output); got != "see (PRIVATE_KEY_1) here" {
		t.Errorf("output = %q", got)
	}
	if res.Counts[KindLabelLike] != 1 {
		t.Errorf("Counts = %v, want one LABEL_LIKE", res.Counts)
	}
}

// Pins the documented false failure: selection is checked on raw spans, so an
// AWS-shaped string inside a selected PEM span still refuses the input.
func TestRedactWithPEMBodyContainingUnselectedKindIsRefused(t *testing.T) {
	g := newSecretGen(303)
	block := pemMarker("BEGIN", "RSA") + "\n" + g.awsKeyID("AKIA") + "\n" +
		g.from(base64Chars, 64) + "\n" + pemMarker("END", "RSA")
	if _, err := Redact([]byte(block)); err != nil {
		t.Fatalf("Redact must accept the fixture: %v", err)
	}
	res, err := RedactWith([]byte(block), Options{Kinds: []Kind{KindPrivateKey}})
	assertRefused(t, res, err, KindAWSAccessKey)
}

func TestRedactWithPEMContainingSelectedKindIsRefusedAsPrivateKey(t *testing.T) {
	g := newSecretGen(304)
	block := pemMarker("BEGIN", "RSA") + "\n" + g.ghClassic('p', 36) + "\n" + pemMarker("END", "RSA")
	res, err := RedactWith([]byte(block), Options{Kinds: []Kind{KindGitHubToken}})
	assertRefused(t, res, err, KindPrivateKey)
}
