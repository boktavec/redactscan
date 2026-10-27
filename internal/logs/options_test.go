package logs

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewFileSourceValidation(t *testing.T) {
	const okName, okPath = "app", "/var/log/app.log"
	tests := []struct {
		name  string
		label string
		path  string
		opts  FileOptions
		valid bool
	}{
		{"defaults", okName, okPath, FileOptions{}, true},
		{"poll 9ms", okName, okPath, FileOptions{PollInterval: 9 * time.Millisecond}, false},
		{"poll 10ms", okName, okPath, FileOptions{PollInterval: 10 * time.Millisecond}, true},
		{"poll 1m", okName, okPath, FileOptions{PollInterval: time.Minute}, true},
		{"poll 1m+1ns", okName, okPath, FileOptions{PollInterval: time.Minute + 1}, false},
		{"poll negative", okName, okPath, FileOptions{PollInterval: -1}, false},
		{"max line 1MiB", okName, okPath, FileOptions{MaxLineBytes: 1 << 20}, true},
		{"max line 1MiB+1", okName, okPath, FileOptions{MaxLineBytes: 1<<20 + 1}, false},
		{"max line negative", okName, okPath, FileOptions{MaxLineBytes: -1}, false},
		{"label empty", "", okPath, FileOptions{}, false},
		{"label 128 bytes", strings.Repeat("a", 128), okPath, FileOptions{}, true},
		{"label 129 bytes", strings.Repeat("a", 129), okPath, FileOptions{}, false},
		{"label invalid utf8", "ab\xffcd", okPath, FileOptions{}, false},
		{"label escape", "ab\x1bcd", okPath, FileOptions{}, false},
		{"label newline", "ab\ncd", okPath, FileOptions{}, false},
		{"label bidi override", "ab\u202ecd", okPath, FileOptions{}, false},
		{"label line separator", "ab\u2028cd", okPath, FileOptions{}, false},
		{"label paragraph separator", "ab\u2029cd", okPath, FileOptions{}, false},
		{"label unicode letters", "journal-é-日本", okPath, FileOptions{}, true},
		{"path empty", okName, "", FileOptions{}, false},
		{"path NUL", okName, "/var/log/a\x00b", FileOptions{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src, err := NewFileSource(tc.label, tc.path, tc.opts)
			if tc.valid {
				if err != nil {
					t.Fatalf("NewFileSource: %v", err)
				}
				if src.Name() != tc.label {
					t.Errorf("Name() = %q, want %q", src.Name(), tc.label)
				}
				return
			}
			if !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("err = %v, want ErrInvalidOptions", err)
			}
			if src != nil {
				t.Error("source is non-nil on error")
			}
			for _, leak := range []string{tc.label, tc.path} {
				if leak != "" && strings.Contains(err.Error(), leak) {
					t.Errorf("error text %q contains input %q", err, leak)
				}
			}
		})
	}
}

func TestNewFileSourceAppliesDefaults(t *testing.T) {
	src, err := NewFileSource("app", "/var/log/app.log", FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if src.opts.PollInterval != DefaultPollInterval || src.opts.MaxLineBytes != DefaultMaxLineBytes {
		t.Errorf("opts = %+v, want defaults", src.opts)
	}
}

func TestNameNeverReturnsPath(t *testing.T) {
	const path = "/home/someone/app.log"
	src, err := NewFileSource("app", path, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(src.Name(), "someone") {
		t.Errorf("Name() = %q leaks the path", src.Name())
	}
}
