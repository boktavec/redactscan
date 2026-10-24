package redactor

import (
	"reflect"
	"testing"
)

func TestMergeSpans(t *testing.T) {
	const (
		aws   = KindAWSAccessKey
		sec   = KindAWSSecretKey
		gh    = KindGitHubToken
		pk    = KindPrivateKey
		label = KindLabelLike
	)
	tests := []struct {
		name string
		in   []span
		want []span
	}{
		{"nested", []span{{0, 10, pk}, {2, 5, aws}}, []span{{0, 10, pk}}},
		{"nested lower priority listed first", []span{{2, 5, pk}, {0, 10, aws}}, []span{{0, 10, pk}}},
		{"partial overlap takes max end and top kind", []span{{0, 6, aws}, {4, 12, gh}}, []span{{0, 12, gh}}},
		{"touching secrets merge", []span{{0, 5, aws}, {5, 9, sec}}, []span{{0, 9, sec}}},
		{"identical", []span{{3, 8, aws}, {3, 8, aws}}, []span{{3, 8, aws}}},
		{"identical different kinds", []span{{3, 8, aws}, {3, 8, pk}}, []span{{3, 8, pk}}},
		{"disjoint stay separate", []span{{0, 3, aws}, {4, 8, aws}}, []span{{0, 3, aws}, {4, 8, aws}}},
		{"chain via transitive overlap", []span{{0, 5, aws}, {4, 9, sec}, {8, 14, gh}}, []span{{0, 14, gh}}},
		{"unsorted input", []span{{10, 12, aws}, {0, 3, aws}}, []span{{0, 3, aws}, {10, 12, aws}}},
		{"label inside secret is absorbed", []span{{0, 20, pk}, {5, 10, label}}, []span{{0, 20, pk}}},
		{"label partially overlapping secret is absorbed", []span{{0, 8, aws}, {5, 12, label}}, []span{{0, 12, aws}}},
		{"touching labels stay separate", []span{{0, 5, label}, {5, 9, label}}, []span{{0, 5, label}, {5, 9, label}}},
		{"label touching secret stays separate", []span{{0, 5, label}, {5, 9, aws}}, []span{{0, 5, label}, {5, 9, aws}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeSpans(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mergeSpans = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOverlappingDetectionsLeaveNoConstituentByte(t *testing.T) {
	g := newSecretGen(30)
	// An AWS key embedded in a longer GitHub token body and a private key
	// block containing a token: all overlap different detectors.
	key := g.awsKeyID("AKIA")
	tok := g.ghClassic('p', 20) + key + g.from(alnum, 20)
	block := pemMarker("BEGIN", "RSA") + "\n" + g.ghClassic('o', 36) + "\n" + pemMarker("END", "RSA")
	got, counts := mustRedact(t, "a "+tok+" b "+block+" c")
	assertOutput(t, got, "a [GITHUB_TOKEN_1] b [PRIVATE_KEY_1] c")
	if counts[KindAWSAccessKey] != 0 || counts[KindGitHubToken] != 1 || counts[KindPrivateKey] != 1 {
		t.Errorf("counts = %v", counts)
	}
}

func TestEqualValuesShareLabelAndDistinctValuesAreNumberedByAppearance(t *testing.T) {
	g := newSecretGen(31)
	a, b := g.awsKeyID("AKIA"), g.awsKeyID("AKIA")
	got, counts := mustRedact(t, b+" "+a+" "+b+" "+a+" "+b)
	assertOutput(t, got, "[AWS_ACCESS_KEY_1] [AWS_ACCESS_KEY_2] [AWS_ACCESS_KEY_1] [AWS_ACCESS_KEY_2] [AWS_ACCESS_KEY_1]")
	if counts[KindAWSAccessKey] != 2 {
		t.Errorf("distinct label count = %d, want 2", counts[KindAWSAccessKey])
	}
}

func TestNumberingIsPerKind(t *testing.T) {
	g := newSecretGen(32)
	in := g.ghClassic('p', 36) + " " + g.awsKeyID("AKIA") + " " + g.ghClassic('s', 36)
	got, counts := mustRedact(t, in)
	assertOutput(t, got, "[GITHUB_TOKEN_1] [AWS_ACCESS_KEY_1] [GITHUB_TOKEN_2]")
	if counts[KindGitHubToken] != 2 || counts[KindAWSAccessKey] != 1 {
		t.Errorf("counts = %v", counts)
	}
}

func TestLabelNumberIndependentOfKeyPrefixAndContent(t *testing.T) {
	g := newSecretGen(33)
	got, _ := mustRedact(t, g.awsKeyID("ASIA")+" "+g.awsKeyID("AKIA")+" "+g.awsKeyID("ASIA"))
	assertOutput(t, got, "[AWS_ACCESS_KEY_1] [AWS_ACCESS_KEY_2] [AWS_ACCESS_KEY_3]")
}

func TestLabelsAreScopedToOneCall(t *testing.T) {
	g := newSecretGen(34)
	a, b := g.awsKeyID("AKIA"), g.awsKeyID("AKIA")
	first, _ := mustRedact(t, a)
	second, _ := mustRedact(t, b)
	if first != second {
		t.Error("each call must restart numbering at 1")
	}
}

func TestPreExistingLabelIsNeutralised(t *testing.T) {
	g := newSecretGen(35)
	in := "[AWS_ACCESS_KEY_1] then " + g.awsKeyID("AKIA")
	got, counts := mustRedact(t, in)
	assertOutput(t, got, "(AWS_ACCESS_KEY_1) then [AWS_ACCESS_KEY_1]")
	if counts[KindLabelLike] != 1 || counts[KindAWSAccessKey] != 1 {
		t.Errorf("counts = %v", counts)
	}
}

func TestLabelLikeCountsOccurrencesAndHandlesAdjacency(t *testing.T) {
	in := "[PRIVATE_KEY_9][PRIVATE_KEY_9] [[GITHUB_TOKEN_12]] [AWS_SECRET_KEY_0] [AWS_SECRET_KEY_01]"
	got, counts := mustRedact(t, in)
	// _0 and _01 are outside the grammar and left alone.
	assertOutput(t, got, "(PRIVATE_KEY_9)(PRIVATE_KEY_9) [(GITHUB_TOKEN_12)] [AWS_SECRET_KEY_0] [AWS_SECRET_KEY_01]")
	if counts[KindLabelLike] != 3 {
		t.Errorf("label-like count = %d, want 3", counts[KindLabelLike])
	}
}

func TestLabelLikeInsideSecretSpanIsNotCounted(t *testing.T) {
	block := pemMarker("BEGIN", "RSA") + "\n[AWS_ACCESS_KEY_1]\n" + pemMarker("END", "RSA")
	got, counts := mustRedact(t, block)
	assertOutput(t, got, "[PRIVATE_KEY_1]")
	if _, ok := counts[KindLabelLike]; ok {
		t.Errorf("label-like inside a secret span counted: %v", counts)
	}
}

func TestZeroCountKindsAreAbsent(t *testing.T) {
	_, counts := mustRedact(t, "nothing here")
	if len(counts) != 0 {
		t.Errorf("counts = %v, want empty", counts)
	}
}
