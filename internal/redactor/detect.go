package redactor

import (
	"cmp"
	"regexp"
	"slices"
)

// detector is one row of the regex detector table. Only capture group
// `group` of a match is redacted (0 means the whole match).
type detector struct {
	kind  Kind
	re    *regexp.Regexp
	group int
}

// Adding a regex-expressible detector means adding a row. Patterns are
// deliberately unanchored: RE2 has no lookbehind and treats '_' as a word
// character, so \b would miss keys embedded in identifiers. Over-redaction is
// the safe direction. Tails are greedy ({n,}) so a stray prefix just before a
// real token cannot end a match partway into it and leave the rest behind.
var detectors = []detector{
	{kind: KindAWSAccessKey, re: regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16,}`)},
	{
		kind: KindAWSSecretKey,
		re: regexp.MustCompile(`(?i:aws[_-]?secret[_-]?access[_-]?key)["']?[ \t]*` +
			`(?:=>|:=|[:=])[ \t]*["']?([A-Za-z0-9/+]{40}[A-Za-z0-9/+=]*)`),
		group: 1,
	},
	{kind: KindGitHubToken, re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
	{kind: KindGitHubToken, re: regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`)},
}

// labelRe is the closed grammar of emitted labels. It is shared by the
// label-like detector and the verifier.
var labelRe = regexp.MustCompile(
	`\[(?:AWS_ACCESS_KEY|AWS_SECRET_KEY|GITHUB_TOKEN|PRIVATE_KEY)_[1-9][0-9]*\]`)

// eachMatch calls fn with the submatch indices (relative to input) of every
// non-overlapping match of re, in order. Unlike FindAll* it never holds all
// matches at once, which matters for inputs with hundreds of thousands of
// them. It is only valid for patterns that cannot match the empty string and
// use no anchors or word boundaries, so restarting after each match is
// equivalent to FindAll.
func eachMatch(re *regexp.Regexp, input []byte, fn func(m []int)) {
	for pos := 0; pos < len(input); {
		m := re.FindSubmatchIndex(input[pos:])
		if m == nil {
			return
		}
		for i := range m {
			if m[i] >= 0 {
				m[i] += pos
			}
		}
		fn(m)
		pos = m[1]
	}
}

// detect returns every candidate span in input, unordered and possibly
// overlapping.
func detect(input []byte) []span {
	var spans []span
	for _, d := range detectors {
		eachMatch(d.re, input, func(m []int) {
			spans = append(spans, span{start: m[2*d.group], end: m[2*d.group+1], kind: d.kind})
		})
	}
	spans = append(spans, pemSpans(input)...)
	eachMatch(labelRe, input, func(m []int) {
		spans = append(spans, span{start: m[0], end: m[1], kind: KindLabelLike})
	})
	return spans
}

// priority orders kinds for merged spans; higher wins.
func priority(k Kind) int {
	switch k {
	case KindPrivateKey:
		return 4
	case KindGitHubToken:
		return 3
	case KindAWSSecretKey:
		return 2
	case KindAWSAccessKey:
		return 1
	default: // KindLabelLike
		return 0
	}
}

// mergeSpans unions overlapping spans, and touching secret spans, into
// ordered non-overlapping spans. A merged span takes the highest-priority
// kind, so no byte of any constituent survives. Label-like spans that merely
// touch another span stay separate so each label is neutralised on its own.
// It reuses the backing array of spans, which the caller must not use again.
func mergeSpans(spans []span) []span {
	slices.SortFunc(spans, func(a, b span) int {
		if c := cmp.Compare(a.start, b.start); c != 0 {
			return c
		}
		return cmp.Compare(b.end, a.end)
	})

	merged := spans[:0] // the write index never passes the read index
	for _, s := range spans {
		if n := len(merged); n > 0 {
			last := &merged[n-1]
			touching := s.start == last.end &&
				last.kind != KindLabelLike && s.kind != KindLabelLike
			if s.start < last.end || touching {
				last.end = max(last.end, s.end)
				if priority(s.kind) > priority(last.kind) {
					last.kind = s.kind
				}
				continue
			}
		}
		merged = append(merged, s)
	}
	return merged
}
