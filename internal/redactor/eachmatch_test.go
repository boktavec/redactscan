package redactor

import (
	"reflect"
	"regexp"
	"testing"
)

// eachMatch restarts the search after every match instead of using FindAll.
// That is only equivalent for patterns with no anchors, no \b and no empty
// matches. This test guards that invariant for every current regex and for
// any row added to detectors later.
func TestEachMatchEqualsFindAllSubmatchIndex(t *testing.T) {
	g := newSecretGen(300)
	key, tok, secret := g.awsKeyID("AKIA"), g.ghClassic('p', 40), g.awsSecret()
	inputs := []string{
		"",
		"no secrets here",
		key + key + "x" + key,
		"AKIA" + key + " ASIA" + g.from(upperDigits, 8) + key,
		tok + " " + tok + "_" + g.ghFine(30) + g.ghFine(22),
		"aws_secret_access_key=" + secret + "\nAWS-SECRET-ACCESS-KEY: '" + secret + "'",
		"[AWS_ACCESS_KEY_1][PRIVATE_KEY_22] [[GITHUB_TOKEN_3]]",
		g.pemBlock("RSA", "\n") + "\n" + g.pemBlock("", "\r\n") + pemMarker("END", "EC") +
			pemMarker("BEGIN", "EC") + pemMarkerPGP("END"),
	}

	patterns := map[string]*regexp.Regexp{
		"labelRe":    labelRe,
		"pemBeginRe": pemBeginRe,
		"pemEndRe":   pemEndRe,
	}
	for i, d := range detectors {
		patterns["detectors["+string(rune('0'+i))+"]"] = d.re
	}

	for name, re := range patterns {
		for n, in := range inputs {
			input := []byte(in)
			var got [][]int
			eachMatch(re, input, func(m []int) { got = append(got, append([]int(nil), m...)) })
			want := re.FindAllSubmatchIndex(input, -1)
			if len(got) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got, want)) {
				t.Errorf("%s, input %d: eachMatch differs from FindAllSubmatchIndex (%d vs %d matches)",
					name, n, len(got), len(want))
			}
		}
	}
}
