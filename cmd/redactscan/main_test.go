package main

import (
	"bytes"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	run([]string{"version"}, &out)
	if got, want := out.String(), version+"\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}
