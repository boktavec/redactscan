package builtin

import "strings"

// extension returns the lowercase extension of name without the dot. Trailing
// ASCII spaces and dots are ignored (Windows does), a name whose only dot is
// its first byte (a dotfile) has none, and hasExt is false then. An extension
// with a non-ASCII byte is returned as "": it never matches the claim table,
// and is folded by hand because strings.ToLower maps U+212A (Kelvin sign) to k.
func extension(name string) (ext string, hasExt bool) {
	name = strings.TrimRight(name, " .")
	dot := strings.LastIndexByte(name, '.')
	if dot <= 0 {
		return "", false
	}
	raw := name[dot+1:]
	b := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c >= 0x80:
			return "", true
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b), true
}
