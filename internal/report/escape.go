package report

import (
	"strconv"
	"unicode/utf8"

	"github.com/boktavec/redactscan/internal/textsafe"
)

const (
	hexDigits        = "0123456789abcdef"
	minDangerousJSON = 0x7f // below this encoding/json already escapes what matters
	maxBMP           = 0xffff
	jsonEscapeBMP    = 6  // \uXXXX
	jsonEscapePair   = 12 // \uXXXX\uXXXX
)

// appendText appends s with dangerous runes, invalid bytes and backslashes
// written as visible escapes.
func appendText(b []byte, s string) []byte { return appendEscaped(b, s, false) }

// appendQuotedText appends s between double quotes, escaping the quote too.
func appendQuotedText(b []byte, s string) []byte {
	return append(appendEscaped(append(b, '"'), s, true), '"')
}

func appendEscaped(b []byte, s string, escapeQuote bool) []byte {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b = append(b, '\\', 'x', hexDigits[s[i]>>4], hexDigits[s[i]&0xf])
		case r == '\\' || (escapeQuote && r == '"'):
			b = append(b, '\\', byte(r))
		case textsafe.IsDangerous(r):
			// ToASCII also escapes printable runes such as U+034F.
			q := strconv.QuoteRuneToASCII(r)
			b = append(b, q[1:len(q)-1]...)
		default:
			b = append(b, s[i:i+size]...)
		}
		i += size
	}
	return b
}

// escapeJSON replaces every dangerous rune at or above U+007F in the whole
// compact JSON text b with \uXXXX. That is safe because such runes only occur
// inside string literals. Invalid UTF-8 is an error: nothing is returned.
func escapeJSON(b []byte) ([]byte, error) {
	if !utf8.Valid(b) {
		return nil, ErrRender
	}
	extra := 0
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r >= minDangerousJSON && textsafe.IsDangerous(r) {
			extra += jsonEscapeLen(r) - size
		}
		i += size
	}
	out := make([]byte, 0, len(b)+extra)
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		switch {
		case r < minDangerousJSON || !textsafe.IsDangerous(r):
			out = append(out, b[i:i+size]...)
		case r <= maxBMP:
			out = appendUnit(out, uint16(r))
		default:
			u := uint32(r) - 0x10000
			out = appendUnit(out, 0xd800|uint16(u>>10&0x3ff))
			out = appendUnit(out, 0xdc00|uint16(u&0x3ff))
		}
		i += size
	}
	return out, nil
}

func jsonEscapeLen(r rune) int {
	if r <= maxBMP {
		return jsonEscapeBMP
	}
	return jsonEscapePair
}

func appendUnit(b []byte, u uint16) []byte {
	return append(b, '\\', 'u',
		hexDigits[u>>12], hexDigits[u>>8&0xf], hexDigits[u>>4&0xf], hexDigits[u&0xf])
}
