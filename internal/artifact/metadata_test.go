package artifact

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

type namedString string

// secretShaped builds a secret-looking value at runtime, never as a literal.
func secretShaped() string {
	return strings.Join([]string{"sk", "live", "Zq8"}, "_") + strings.Repeat("A", 40)
}

func TestValidateMetadataAccepted(t *testing.T) {
	t.Parallel()
	many := map[string]any{}
	for i := 0; i < MaxMetadataEntries; i++ {
		many[strings.Repeat("k", i+1)] = i
	}
	tests := map[string]map[string]any{
		"nil":          nil,
		"empty":        {},
		"string":       {"k": "v"},
		"bool":         {"k": true},
		"int":          {"k": 1},
		"int64":        {"k": int64(1)},
		"float64":      {"k": 1.5},
		"max entries":  many,
		"max key":      {strings.Repeat("k", MaxMetadataKeyBytes): 1},
		"max value":    {"k": strings.Repeat("v", MaxMetadataValueBytes)},
		"empty string": {"k": ""},
	}
	for name, m := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateMetadata(m); err != nil {
				t.Errorf("ValidateMetadata() = %v", err)
			}
		})
	}
}

func TestValidateMetadataRejected(t *testing.T) {
	t.Parallel()
	tooMany := map[string]any{}
	for i := 0; i <= MaxMetadataEntries; i++ {
		tooMany[strings.Repeat("k", i+1)] = i
	}
	self := map[string]any{}
	self["self"] = self
	var nilErr error
	tests := []struct {
		name string
		m    map[string]any
		want string
	}{
		{"too many entries", tooMany, "33 entries"},
		{"empty key", map[string]any{"": 1}, "key is 0 bytes"},
		{"long key", map[string]any{strings.Repeat("k", MaxMetadataKeyBytes+1): 1}, "key is 65 bytes"},
		{"non-UTF-8 key", map[string]any{"k\xff": 1}, "key is not valid UTF-8"},
		{"long value", map[string]any{"k": strings.Repeat("v", MaxMetadataValueBytes+1)}, "value is 257 bytes"},
		{"non-UTF-8 value", map[string]any{"k": "v\xff"}, "value is not valid UTF-8"},
		{"key checked before value", map[string]any{strings.Repeat("k", MaxMetadataKeyBytes+1): []byte("x")}, "key is 65 bytes"},
		{"value length before UTF-8", map[string]any{"k": strings.Repeat("\xff", 300)}, "value is 300 bytes"},
		{"[]byte", map[string]any{"k": []byte("x")}, "unsupported kind slice"},
		{"nested map", map[string]any{"k": map[string]any{}}, "unsupported kind map"},
		{"[]any", map[string]any{"k": []any{}}, "unsupported kind slice"},
		{"[]string", map[string]any{"k": []string{}}, "unsupported kind slice"},
		{"pointer", map[string]any{"k": new(string)}, "unsupported kind ptr"},
		{"struct", map[string]any{"k": struct{}{}}, "unsupported kind struct"},
		{"named string", map[string]any{"k": namedString("x")}, "unsupported kind string"},
		{"error", map[string]any{"k": errors.New("x")}, "unsupported kind ptr"},
		{"nil error", map[string]any{"k": nilErr}, "unsupported kind nil"},
		{"nil", map[string]any{"k": nil}, "unsupported kind nil"},
		{"int32", map[string]any{"k": int32(1)}, "unsupported kind int32"},
		{"uint", map[string]any{"k": uint(1)}, "unsupported kind uint"},
		{"float32", map[string]any{"k": float32(1)}, "unsupported kind float32"},
		{"NaN", map[string]any{"k": math.NaN()}, "NaN or infinite"},
		{"+Inf", map[string]any{"k": math.Inf(1)}, "NaN or infinite"},
		{"-Inf", map[string]any{"k": math.Inf(-1)}, "NaN or infinite"},
		{"self-reference", self, "unsupported kind map"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateMetadata(tt.m)
			if !errors.Is(err, ErrInvalidMetadata) {
				t.Fatalf("err = %v, want ErrInvalidMetadata", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want substring %q", err, tt.want)
			}
		})
	}
}

// assertNoEcho fails if any 8-byte substring of secret appears in err.
func assertNoEcho(t *testing.T, err error, secret string) {
	t.Helper()
	if err == nil {
		t.Fatal("err = nil, want error")
	}
	msg := err.Error()
	for i := 0; i+8 <= len(secret); i++ {
		if strings.Contains(msg, secret[i:i+8]) {
			t.Fatalf("error echoes content: %q", msg)
		}
	}
}

func TestValidateMetadataDoesNotEchoContent(t *testing.T) {
	t.Parallel()
	secret := secretShaped()
	tagged := reflect.StructOf([]reflect.StructField{{
		Name: "F", Type: reflect.TypeOf(0), Tag: reflect.StructTag(`json:"` + secret + `"`),
	}})
	tests := map[string]map[string]any{
		"long key":       {secret + strings.Repeat("k", MaxMetadataKeyBytes): 1},
		"non-UTF-8 key":  {secret + "\xff": 1},
		"key, bad value": {secret: []byte(secret)},
		"long value":     {"k": secret + strings.Repeat("v", MaxMetadataValueBytes)},
		"bad UTF-8":      {"k": secret + "\xff"},
		"named string":   {"k": namedString(secret)},
		"runtime struct": {"k": reflect.New(tagged).Elem().Interface()},
	}
	for name, m := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assertNoEcho(t, ValidateMetadata(m), secret)
		})
	}
}
