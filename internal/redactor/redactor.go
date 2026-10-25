// Package redactor replaces well-known secret formats in text with typed,
// per-call numbered labels and fails closed when it cannot vouch for its
// output.
//
// It reduces accidental disclosure of the covered formats only. Its output
// must not be described as "safe to share": uncovered formats, encoded
// secrets and deliberate obfuscation are not detected (see
// docs/threat-model.md).
package redactor

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strconv"
)

// MaxInputSize is the largest input Redact accepts, in bytes.
const MaxInputSize = 10 << 20 // 10 MiB

// Kind classifies a redacted span.
type Kind string

// Kinds of redacted or neutralised text.
const (
	KindAWSAccessKey Kind = "AWS_ACCESS_KEY"
	KindAWSSecretKey Kind = "AWS_SECRET_KEY" // #nosec G101 -- label name, not a credential
	KindGitHubToken  Kind = "GITHUB_TOKEN"   // #nosec G101 -- label name, not a credential
	KindPrivateKey   Kind = "PRIVATE_KEY"
	// KindLabelLike is pre-existing label-looking input text that was
	// neutralised. It is not a secret.
	KindLabelLike Kind = "LABEL_LIKE"
)

// Sentinel errors. Their text is constant and never contains input data.
var (
	ErrInputTooLarge       = errors.New("redactor: input exceeds maximum size")
	ErrUnsupportedEncoding = errors.New("redactor: unsupported encoding")
	ErrVerificationFailed  = errors.New("redactor: verification failed")
)

// Result is the outcome of a successful Redact call. Both fields are nil
// when Redact returns an error.
type Result struct {
	// Output is a freshly allocated slice that never aliases the input.
	Output []byte
	// Counts holds the number of distinct labels emitted per secret kind,
	// plus the number of neutralised label-like occurrences under
	// KindLabelLike. Kinds with a zero count are absent.
	Counts map[Kind]int
}

// span is a half-open byte range [start, end) of the input.
type span struct {
	start, end int
	kind       Kind
}

// Redact replaces covered secrets in input with labels such as
// [AWS_ACCESS_KEY_1]. Labels are numbered per call in order of first
// appearance, and equal values share a label within one call; the same
// label in two calls refers to unrelated values.
//
// Redact returns ErrInputTooLarge, ErrUnsupportedEncoding or an error
// wrapping ErrVerificationFailed (naming only the kind) instead of output it
// cannot vouch for. It is safe for concurrent use.
func Redact(input []byte) (Result, error) {
	if len(input) > MaxInputSize {
		return Result{}, ErrInputTooLarge
	}
	if err := checkEncoding(input); err != nil {
		return Result{}, err
	}

	spans := mergeSpans(detect(input))
	out, counts, emitted := render(input, spans)
	if err := verify(out, emitted); err != nil {
		return Result{}, err
	}
	return Result{Output: out, Counts: counts}, nil
}

// checkEncoding rejects text the byte-oriented detectors cannot see through:
// anything containing NUL (UTF-16/32 without BOM, binary) or starting with a
// UTF-16/32 byte order mark. A UTF-8 BOM is accepted.
func checkEncoding(input []byte) error {
	if bytes.IndexByte(input, 0) >= 0 ||
		bytes.HasPrefix(input, []byte{0xFE, 0xFF}) ||
		bytes.HasPrefix(input, []byte{0xFF, 0xFE}) {
		return ErrUnsupportedEncoding
	}
	return nil
}

// render builds the output from non-overlapping, ordered spans. It returns
// the output, the counts, and the output offsets of the labels it emitted so
// verify can distinguish them from label-like text.
func render(input []byte, spans []span) ([]byte, map[Kind]int, []int) {
	out := make([]byte, 0, len(input))
	counts := make(map[Kind]int)
	// Keyed by digest so the map holds no extra copies of secret values.
	seen := make(map[Kind]map[[sha256.Size]byte]int)
	var emitted []int

	cursor := 0
	for _, s := range spans {
		out = append(out, input[cursor:s.start]...)
		cursor = s.end
		value := input[s.start:s.end]

		if s.kind == KindLabelLike {
			out = appendNeutralised(out, value)
			counts[KindLabelLike]++
			continue
		}

		ids := seen[s.kind]
		if ids == nil {
			ids = make(map[[sha256.Size]byte]int)
			seen[s.kind] = ids
		}
		digest := sha256.Sum256(value)
		n, ok := ids[digest]
		if !ok {
			n = len(ids) + 1
			ids[digest] = n
			counts[s.kind] = n
		}

		start := len(out)
		out = append(out, '[')
		out = append(out, s.kind...)
		out = append(out, '_')
		out = strconv.AppendInt(out, int64(n), 10)
		out = append(out, ']')
		emitted = append(emitted, start)
	}
	out = append(out, input[cursor:]...)
	return out, counts, emitted
}

// appendNeutralised appends label-like text with its brackets turned into
// parentheses so it can no longer be mistaken for an emitted label.
func appendNeutralised(dst, label []byte) []byte {
	for _, b := range label {
		switch b {
		case '[':
			b = '('
		case ']':
			b = ')'
		}
		dst = append(dst, b)
	}
	return dst
}

// VerificationError reports which kind failed verification. It matches
// ErrVerificationFailed with errors.Is and carries no input data.
type VerificationError struct{ Kind Kind }

func (e *VerificationError) Error() string {
	return ErrVerificationFailed.Error() + ": " + string(e.Kind)
}

// Is reports whether target is ErrVerificationFailed.
func (e *VerificationError) Is(target error) bool { return target == ErrVerificationFailed }

// verifyError reports the kind that failed verification, never a value or
// offset.
func verifyError(kind Kind) error {
	return &VerificationError{Kind: kind}
}
