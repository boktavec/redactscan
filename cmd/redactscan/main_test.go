package main

import (
	"bytes"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"version"}, &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), version+"\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}
