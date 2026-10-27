package redactor

import (
	"bytes"
	"errors"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fuzzSecret is a runtime-generated secret, the text that embeds it so the
// detector sees its real context, and the parts of it that must not survive
// even partially (bodies without their fixed prefixes).
type fuzzSecret struct {
	secret   string
	embedded string
	bodies   []string
}

// partialLeakWindow is the length of a secret fragment that counts as a leak.
const partialLeakWindow = 12

func fuzzSecrets() []fuzzSecret {
	g := newSecretGen(100)
	var out []fuzzSecret
	add := func(secret, embedded string, bodies ...string) {
		out = append(out, fuzzSecret{secret, embedded, bodies})
	}
	for _, prefix := range []string{"AKIA", "ASIA"} {
		k := g.awsKeyID(prefix)
		add(k, k, k[4:])
	}
	aws := g.awsSecret()
	add(aws, "AWS_SECRET_ACCESS_KEY="+aws, aws)
	for _, kind := range []byte("pousr") {
		tok := g.ghClassic(kind, 36)
		add(tok, tok, tok[4:])
	}
	tok := g.ghClassic('p', 255)
	add(tok, tok, tok[4:])
	tok = g.ghFine(82)
	add(tok, tok, tok[len("github_pat_"):])
	for _, typeName := range []string{"RSA", "EC", "OPENSSH", ""} {
		block := g.pemBlock(typeName, "\r\n")
		lines := strings.Split(block, "\r\n")
		add(block, block, lines[1:len(lines)-1]...) // body lines only
	}
	return out
}

// leakedFragment reports whether out contains the whole secret or any
// window of partialLeakWindow bytes of one of its bodies.
func leakedFragment(out []byte, s fuzzSecret) bool {
	if bytes.Contains(out, []byte(s.secret)) {
		return true
	}
	for _, body := range s.bodies {
		for i := 0; i+partialLeakWindow <= len(body); i++ {
			if bytes.Contains(out, []byte(body[i:i+partialLeakWindow])) {
				return true
			}
		}
	}
	return false
}

func FuzzRedact(f *testing.F) {
	secrets := fuzzSecrets()
	seeds := [][2]string{
		{"", ""},
		{"AWS_KEY_", ""},
		{"AKIA", ""},
		{"ASIAABCDEFGH", ""},
		{"_", "_"},
		{"x", "x"},
		{"\r\n", "\r\n"},
		{pemMarker("END", "RSA") + "\n", ""},
		{pemMarker("BEGIN", "EC") + "\n", ""},
		{"[AWS_ACCESS_KEY_1]", "[PRIVATE_KEY_2]"},
	}
	for i := range secrets {
		for _, s := range seeds {
			f.Add([]byte(s[0]), []byte(s[1]), uint8(i))
		}
	}

	f.Fuzz(func(t *testing.T, prefix, suffix []byte, which uint8) {
		i := int(which) % len(secrets)
		input := bytes.Join([][]byte{prefix, []byte(secrets[i].embedded), suffix}, nil)
		res, err := Redact(input)
		if err != nil {
			if res.Output != nil || res.Counts != nil {
				t.Fatal("non-nil result alongside error")
			}
			return
		}
		if leakedFragment(res.Output, secrets[i]) {
			t.Fatalf("secret %d (len %d) survived, wholly or in part", i, len(secrets[i].secret))
		}
	})
}

// kindsFromMask maps a bit mask to a selection; 0 is nil (all kinds).
func kindsFromMask(mask uint8) []Kind {
	var kinds []Kind
	for i, k := range allKinds {
		if mask&(1<<i) != 0 {
			kinds = append(kinds, k)
		}
	}
	return kinds
}

func FuzzRedactWith(f *testing.F) {
	secrets := fuzzSecrets()
	seeds := []string{"", "x", "[AWS_ACCESS_KEY_1]", "AKIA", pemMarker("END", "RSA") + "\n"}
	for i := range secrets {
		for _, seed := range seeds {
			for _, mask := range []uint8{0, 1, 4, 8, 15} {
				f.Add([]byte(seed), []byte(""), uint8(i), mask)
			}
		}
	}

	f.Fuzz(func(t *testing.T, prefix, suffix []byte, which, mask uint8) {
		input := bytes.Join([][]byte{prefix, []byte(secrets[int(which)%len(secrets)].embedded), suffix}, nil)
		kinds := kindsFromMask(mask)
		res, err := RedactWith(input, Options{Kinds: kinds})
		want, wantErr := Redact(input)
		if err != nil {
			if res.Output != nil || res.Counts != nil {
				t.Fatal("non-nil result alongside error")
			}
			if wantErr == nil {
				// Only a selection refusal may add a failure to Redact's.
				if k := errKind(err); k == "" || slices.Contains(kinds, k) {
					t.Fatalf("unexpected refusal %v for selection %v", err, kinds)
				}
			}
			return
		}
		if wantErr != nil {
			t.Fatalf("RedactWith succeeded where Redact failed: %v", wantErr)
		}
		if !bytes.Equal(res.Output, want.Output) {
			t.Fatal("RedactWith output differs from Redact")
		}
		for k := range res.Counts {
			if k != KindLabelLike && len(kinds) > 0 && !slices.Contains(kinds, k) {
				t.Fatalf("count for unselected kind %s", k)
			}
		}
	})
}

func TestRedactWithConcurrentSharedOptions(t *testing.T) {
	samples := kindSamples()
	opts := Options{Kinds: []Kind{KindGitHubToken, KindAWSAccessKey}}
	input := []byte(samples[KindGitHubToken] + "\n" + samples[KindAWSAccessKey])
	want, err := Redact(input)
	if err != nil {
		t.Fatal(err)
	}
	refused := []byte(samples[KindPrivateKey])

	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < 20; round++ {
				res, err := RedactWith(input, opts)
				if err != nil || !bytes.Equal(res.Output, want.Output) {
					t.Errorf("concurrent result differs (err=%v)", err)
					return
				}
				if _, err := RedactWith(refused, opts); !errors.Is(err, ErrVerificationFailed) {
					t.Errorf("concurrent refusal missing: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestRedactConcurrentUse(t *testing.T) {
	secrets := fuzzSecrets()
	inputs := make([][]byte, len(secrets))
	want := make([]Result, len(secrets))
	for i, s := range secrets {
		inputs[i] = []byte("pre " + s.embedded + " post " + s.embedded)
		res, err := Redact(inputs[i])
		if err != nil {
			t.Fatal(err)
		}
		want[i] = res
	}

	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < 20; round++ {
				for i, in := range inputs {
					res, err := Redact(in)
					if err != nil || !bytes.Equal(res.Output, want[i].Output) {
						t.Errorf("concurrent result differs for input %d (err=%v)", i, err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}

// adversarialInputs builds MaxInputSize inputs aimed at CPU blowup.
func adversarialInputs() map[string][]byte {
	g := newSecretGen(200)
	tile := func(unit string) []byte {
		return []byte(strings.Repeat(unit, MaxInputSize/len(unit)+1)[:MaxInputSize])
	}
	var dense bytes.Buffer
	for dense.Len() < MaxInputSize-30 {
		dense.WriteString(g.awsKeyID("AKIA"))
		dense.WriteByte('\n')
	}
	return map[string][]byte{
		"begin without end":     tile(pemMarker("BEGIN", "RSA") + "\n"),
		"end without begin":     tile(pemMarker("END", "RSA") + "\n"),
		"mismatched pairs":      tile(g.pemBlockWith("RSA", "EC", "\n") + "\n"),
		"repeated key prefixes": tile("AKIAAKIAAKIA"),
		"near-miss github":      tile(g.ghClassic('p', 35) + " "),
		"repeated label-like":   tile("[PRIVATE_KEY_1]"),
		"dense distinct keys":   dense.Bytes(),
		"aws secret name spam":  tile("aws_secret_access_key="),
		"dashes":                tile("-----"),
		// Verifier-heavy: no newline, so the bounded [^\n]{0,N} scans run long.
		"end marker prefix, no newline":   tile("-----END x "),
		"begin marker prefix, no newline": tile("-----BEGIN x "),
		"secret_access_key + 39 base64":   tile("secret_access_key" + g.from(base64Chars, 39)),
	}
}

const adversarialBudget = 5 * time.Second

func TestAdversarialInputsFinishWithinBudget(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing assertion skipped under -short and the race detector")
	}
	for name, input := range adversarialInputs() {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			res, err := Redact(input)
			elapsed := time.Since(start)
			if elapsed > adversarialBudget {
				t.Errorf("took %v, budget %v", elapsed, adversarialBudget)
			}
			// Failing closed on these inputs is acceptable; leaking is not.
			if err != nil && (!errors.Is(err, ErrVerificationFailed) || res.Output != nil || res.Counts != nil) {
				t.Errorf("unexpected failure shape: %v", err)
			}
		})
	}
}

// Under the race detector Redact is far slower, so 1 MiB prefixes keep this
// run short while still exercising the same code paths.
func TestAdversarialInputsDoNotPanicUnderRace(t *testing.T) {
	if testing.Short() || !raceEnabled {
		t.Skip("covered by the timing test outside -race")
	}
	for name, input := range adversarialInputs() {
		t.Run(name, func(t *testing.T) {
			if _, err := Redact(input[:1<<20]); err != nil && !errors.Is(err, ErrVerificationFailed) {
				t.Fatal(err)
			}
		})
	}
}

// peakHeapGrowth runs fn while sampling the heap and returns the largest
// growth over the starting heap. An aggressive GC percent keeps uncollected
// garbage from inflating the figure; it remains a sampled approximation.
func peakHeapGrowth(fn func()) uint64 {
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak.Load() {
				peak.Store(m.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	fn()
	close(stop)
	<-done
	return peak.Load() - min(peak.Load(), base.HeapAlloc)
}

// A failure here means re-measure (the figure is sampled and the margin is
// thin), not raise the budget: callers size memory from the 10x figure.
func TestDenseInputsPeakHeapStaysUnderTenTimesInput(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("memory assertion skipped under -short and the race detector")
	}
	inputs := adversarialInputs()
	for _, name := range []string{"dense distinct keys", "repeated label-like"} {
		t.Run(name, func(t *testing.T) {
			input := inputs[name]
			growth := peakHeapGrowth(func() {
				if _, err := Redact(input); err != nil {
					t.Error(err)
				}
			})
			t.Logf("peak heap growth %.1fx the %.1f MiB input", float64(growth)/float64(len(input)),
				float64(len(input))/(1<<20))
			if growth > uint64(10*len(input)) {
				t.Errorf("peak heap growth %d bytes, want under 10x input (%d)", growth, 10*len(input))
			}
		})
	}
}

func BenchmarkRedact(b *testing.B) {
	inputs := adversarialInputs()
	noMatch := bytes.Repeat([]byte("an ordinary log line with no secrets\n"), MaxInputSize/37)
	cases := []struct {
		name  string
		input []byte
	}{
		{"dense", inputs["dense distinct keys"]},
		{"no-match", noMatch},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(c.input)))
			for i := 0; i < b.N; i++ {
				if _, err := Redact(c.input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
