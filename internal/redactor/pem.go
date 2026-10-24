package redactor

import (
	"bytes"
	"regexp"
)

// RE2 has no backreferences, so BEGIN/END type matching is done by hand in
// pemSpans rather than as a detector table row.
var (
	pemBeginRe = regexp.MustCompile(`(?i)-----BEGIN ((?:[A-Z0-9]+ ){0,4})PRIVATE KEY( BLOCK)?-----`)
	pemEndRe   = regexp.MustCompile(`(?i)-----END ((?:[A-Z0-9]+ ){0,4})PRIVATE KEY( BLOCK)?-----`)
)

const (
	pemBeginPrefix = len("-----BEGIN ")
	pemEndPrefix   = len("-----END ")
	pemDashes      = len("-----")
)

// pemSpans returns the spans of private key material in input:
//
//   - a terminated block, from its BEGIN marker through its matching END;
//   - an unterminated or type-mismatched block, from BEGIN to end of input
//     (scanning then stops);
//   - an orphaned END marker, from the end of the previous PEM span (or the
//     start of input) through the marker, so headers and body lines that
//     lost their BEGIN are covered.
//
// It makes a bounded number of forward passes, so it is linear in len(input).
func pemSpans(input []byte) []span {
	claimed := claimedBlocks(input)

	spans := claimed
	prevEnd := 0
	next := 0 // index into claimed
	eachMatch(pemEndRe, input, func(m []int) {
		for next < len(claimed) && claimed[next].end <= m[0] {
			prevEnd = max(prevEnd, claimed[next].end)
			next++
		}
		// claimed[next] is the first block ending after this marker starts, so
		// it is the only one that can contain the marker.
		if next < len(claimed) && claimed[next].start <= m[0] && m[1] <= claimed[next].end {
			return
		}
		spans = append(spans, span{start: prevEnd, end: m[1], kind: KindPrivateKey})
		prevEnd = m[1]
	})
	return spans
}

// claimedBlocks finds spans started by a BEGIN marker.
func claimedBlocks(input []byte) []span {
	var blocks []span
	pos := 0
	for {
		begin := pemBeginRe.FindIndex(input[pos:])
		if begin == nil {
			return blocks
		}
		beginStart, beginEnd := pos+begin[0], pos+begin[1]

		end := pemEndRe.FindIndex(input[beginEnd:])
		if end == nil {
			return append(blocks, span{start: beginStart, end: len(input), kind: KindPrivateKey})
		}
		endEnd := beginEnd + end[1]

		beginType := input[beginStart+pemBeginPrefix : beginEnd-pemDashes]
		endType := input[beginEnd+end[0]+pemEndPrefix : endEnd-pemDashes]
		if !bytes.EqualFold(beginType, endType) {
			return append(blocks, span{start: beginStart, end: len(input), kind: KindPrivateKey})
		}
		blocks = append(blocks, span{start: beginStart, end: endEnd, kind: KindPrivateKey})
		pos = endEnd
	}
}
