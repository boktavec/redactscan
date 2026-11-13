// Package textsafe holds the one rule for runes that must never reach a
// terminal or be trusted in a file name. It is pure computation: no I/O.
package textsafe

import (
	"strconv"
	"unicode"
)

// IsDangerous is the one rule both the report renderers and the file-name
// scanners use. strconv.IsPrint covers C0, DEL, C1, bidi, format, separator
// and non-ASCII space runes. It accepts invisible fillers and variation
// selectors, so those are added.
func IsDangerous(r rune) bool {
	return !strconv.IsPrint(r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) ||
		unicode.Is(unicode.Variation_Selector, r)
}
