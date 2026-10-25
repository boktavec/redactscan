package redactor

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestRedactSizeCap(t *testing.T) {
	atCap := bytes.Repeat([]byte("a"), MaxInputSize)
	res, err := Redact(atCap)
	if err != nil {
		t.Fatalf("input of exactly MaxInputSize rejected: %v", err)
	}
	if len(res.Output) != MaxInputSize {
		t.Errorf("output length = %d, want %d", len(res.Output), MaxInputSize)
	}

	over := append(atCap, 'a')
	res, err = Redact(over)
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("err = %v, want ErrInputTooLarge", err)
	}
	assertNilResult(t, res)
}

func TestRedactEncodingGuard(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"nul at start", []byte{0, 'a'}, true},
		{"nul in middle", []byte("ab\x00cd"), true},
		{"nul at end", []byte("abc\x00"), true},
		{"utf-16 be bom", []byte{0xFE, 0xFF, 'a'}, true},
		{"utf-16 le bom", []byte{0xFF, 0xFE, 'a'}, true},
		{"bom only", []byte{0xFF, 0xFE}, true},
		{"utf-8 bom accepted", []byte{0xEF, 0xBB, 0xBF, 'a'}, false},
		{"invalid utf-8 accepted", []byte{0xFF, 'a', 0xC0}, false},
		{"fe ff not at start accepted", []byte{'a', 0xFE, 0xFF}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Redact(tt.input)
			if tt.wantErr {
				if !errors.Is(err, ErrUnsupportedEncoding) {
					t.Fatalf("err = %v, want ErrUnsupportedEncoding", err)
				}
				assertNilResult(t, res)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(res.Output, tt.input) {
				t.Error("output differs from input without secrets")
			}
		})
	}
}

func TestRedactSizeCapIsCheckedBeforeEncoding(t *testing.T) {
	input := append([]byte{0}, bytes.Repeat([]byte("a"), MaxInputSize)...)
	if _, err := Redact(input); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("err = %v, want ErrInputTooLarge", err)
	}
}

func TestRedactEmptyInput(t *testing.T) {
	for _, in := range [][]byte{nil, {}} {
		res, err := Redact(in)
		if err != nil {
			t.Fatal(err)
		}
		if res.Output == nil || len(res.Output) != 0 {
			t.Errorf("Output = %#v, want non-nil empty", res.Output)
		}
		if res.Counts == nil || len(res.Counts) != 0 {
			t.Errorf("Counts = %#v, want non-nil empty", res.Counts)
		}
	}
}

func TestRedactOutputNeverAliasesInput(t *testing.T) {
	g := newSecretGen(2)
	inputs := map[string][]byte{
		"no matches":   []byte("plain log line"),
		"with a match": []byte("key " + g.awsKeyID("AKIA") + " end"),
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			original := bytes.Clone(input)
			res, err := Redact(input)
			if err != nil {
				t.Fatal(err)
			}
			for i := range res.Output {
				res.Output[i] = '#'
			}
			if !bytes.Equal(input, original) {
				t.Error("mutating Output changed input")
			}
		})
	}
}

func TestErrorsAreConstantAndLeakNoInput(t *testing.T) {
	_, tooLarge := Redact(make([]byte, MaxInputSize+12345))
	_, encoding := Redact([]byte{0})
	for _, err := range []error{tooLarge, encoding} {
		if err == nil {
			t.Fatal("expected error")
		}
		if strings.ContainsAny(err.Error(), "0123456789") {
			t.Errorf("error text %q contains digits", err.Error())
		}
	}
	if strings.Contains(tooLarge.Error(), strconv.Itoa(MaxInputSize)) {
		t.Error("error text contains the size cap")
	}
}

func assertNilResult(t *testing.T, res Result) {
	t.Helper()
	if res.Output != nil || res.Counts != nil {
		t.Errorf("expected nil Output and Counts on error, got %v / %v", res.Output != nil, res.Counts != nil)
	}
}
