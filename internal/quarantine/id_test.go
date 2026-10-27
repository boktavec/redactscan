package quarantine

import (
	"strings"
	"testing"
)

func TestValidID(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	suffix := strings.Repeat("0f", 8)
	valid := hash + "-" + suffix

	tests := []struct {
		name string
		id   string
		want bool
	}{
		{"valid", valid, true},
		{"empty", "", false},
		{"parent traversal", "../x", false},
		{"absolute", "/abs", false},
		{"slash", "a/b", false},
		{"dot", ".", false},
		{"dotdot", "..", false},
		{"uppercase hex", strings.ToUpper(hash) + "-" + suffix, false},
		{"uppercase suffix", hash + "-" + strings.ToUpper(suffix), false},
		{"63 hex", hash[:63] + "-" + suffix, false},
		{"65 hex", hash + "a-" + suffix, false},
		{"short suffix", hash + "-" + suffix[:15], false},
		{"long suffix", hash + "-" + suffix + "0", false},
		{"missing suffix", hash, false},
		{"wrong separator", hash + "_" + suffix, false},
		{"NUL", valid[:10] + "\x00" + valid[11:], false},
		{"trailing newline", valid + "\n", false},
		{"non-hex letter", hash[:63] + "g-" + suffix, false},
		{"slash in hash", hash[:10] + "/" + hash[11:] + "-" + suffix, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidID(tt.id); got != tt.want {
				t.Errorf("ValidID(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

func TestOptionsWithDefaults(t *testing.T) {
	got, err := Options{}.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxEntrySize != DefaultMaxEntrySize || got.MaxStoreBytes != DefaultMaxStoreBytes || got.MaxEntries != DefaultMaxEntries {
		t.Errorf("defaults = %+v", got)
	}
	got, err = Options{MaxEntrySize: 1, MaxStoreBytes: 2, MaxEntries: 3}.withDefaults()
	if err != nil || got.MaxEntrySize != 1 || got.MaxStoreBytes != 2 || got.MaxEntries != 3 {
		t.Errorf("explicit = %+v, %v", got, err)
	}
	for _, o := range []Options{{MaxEntrySize: -1}, {MaxStoreBytes: -1}, {MaxEntries: -1}} {
		if _, err := o.withDefaults(); err != ErrInvalidOptions {
			t.Errorf("%+v: error = %v, want ErrInvalidOptions", o, err)
		}
	}
}
