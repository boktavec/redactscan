package builtin

import (
	"strings"
	"unicode/utf8"

	"github.com/boktavec/redactscan/internal/textsafe"
)

// extension returns the lowercase extension of name without the dot. Trailing
// ASCII spaces and dots are ignored (Windows does), a name whose only dot is
// its first byte (a dotfile) has none, and hasExt is false then. An extension
// with a non-ASCII byte is returned as "": it never matches the claim table,
// and is folded by hand because strings.ToLower maps U+212A (Kelvin sign) to k.
func extension(name string) (ext string, hasExt bool) {
	return lastExtension(strings.TrimRight(name, " ."))
}

// lastExtension is extension without the trailing space and dot stripping.
func lastExtension(name string) (ext string, hasExt bool) {
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

// hasInvisibleRune reports whether name has a rune textsafe.IsDangerous flags
// (control, bidi, invisible) or an invalid UTF-8 byte.
func hasInvisibleRune(name string) bool {
	for i := 0; i < len(name); {
		r, size := utf8.DecodeRuneInString(name[i:])
		if (r == utf8.RuneError && size == 1) || textsafe.IsDangerous(r) {
			return true
		}
		i += size
	}
	return false
}

// docLike lists the zip-container document extensions that count as a
// document for the double-extension rule only. The claim table is unchanged
// (they claim zip there), and zip itself stays excluded so pack.zip.exe is not
// flagged.
var docLike = map[string]bool{"docx": true, "xlsx": true, "pptx": true, "odt": true, "ods": true, "odp": true, "epub": true}

// doubleExtension reports names like report.pdf.exe: a program or script
// extension (pe, native or script claim) after a text, image or document
// extension. Trailing spaces and dots before the last dot are ignored, so
// report.pdf..exe counts; a name whose only earlier dot is the first byte
// (.pdf.exe) has no inner extension.
func doubleExtension(name string) bool {
	name = strings.TrimRight(name, " .")
	final, ok := lastExtension(name)
	if !ok || !isProgramClaim(claims[final]) {
		return false
	}
	inner, ok := lastExtension(strings.TrimRight(name[:strings.LastIndexByte(name, '.')], " ."))
	if !ok {
		return false
	}
	switch claims[inner] {
	case claimText, claimImage, claimDocument:
		return true
	}
	return docLike[inner]
}

func isProgramClaim(claim string) bool {
	return claim == claimPE || claim == claimNative || claim == claimScript
}
