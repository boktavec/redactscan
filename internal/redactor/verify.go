package redactor

import "regexp"

// looseChecks are deliberately broader than the detectors: anything that
// merely resembles a covered secret in the final output is a failure, so a
// detector gap becomes an error instead of a leak. False failures are an
// accepted fail-closed trade-off.
//
// A check for base64 of "-----BEGIN" is intentionally absent: it would also
// fire on base64-encoded certificates and fail common inputs. Encoded keys
// are a documented non-goal.
var looseChecks = []struct {
	kind Kind
	re   *regexp.Regexp
}{
	{KindAWSAccessKey, regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`)},
	{KindAWSSecretKey, regexp.MustCompile(`(?i)secret[_-]?access[_-]?key[^\n]{0,16}[A-Za-z0-9/+]{40}`)},
	{KindGitHubToken, regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]`)},
	{KindPrivateKey, regexp.MustCompile(
		`(?i)-----(?:BEGIN|END)[^\n]{0,64}PRIVATE KEY|PRIVATE KEY(?: BLOCK)?-----`)},
}

// verify checks the exact bytes about to be returned. emitted lists the
// offsets of the labels this call wrote; every label-grammar match in out
// must start at exactly one of them, so spoofed or accidentally formed labels
// fail closed. A match is fully determined by its start offset (it ends at the
// first ']'), so offsets suffice. Errors name the kind only, never a value or
// offset.
func verify(out []byte, emitted []int) error {
	for _, c := range looseChecks {
		if c.re.Match(out) {
			return verifyError(c.kind)
		}
	}

	i, ok := 0, true
	eachMatch(labelRe, out, func(m []int) {
		if i >= len(emitted) || m[0] != emitted[i] {
			ok = false
		}
		i++
	})
	if !ok || i != len(emitted) {
		return verifyError(KindLabelLike)
	}
	return nil
}
