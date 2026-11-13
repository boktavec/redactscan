package builtin

import "strings"

// Claim types an extension can make about content.
const (
	claimPE       = "pe"
	claimNative   = "native" // ELF or Mach-O
	claimZip      = "zip"
	claimGzip     = "gzip"
	claimScript   = "script"
	claimText     = "text"
	claimImage    = "image"
	claimDocument = "document"
)

// Extra claimed_type values for a mismatch with no table entry.
const (
	claimUnknown = "unknown"
	claimNone    = "none"
)

// claims maps a lowercase extension (no dot) to what it claims. It is a fixed
// table: the extension is never taken from the file name into a finding.
// msi is left out because it is an OLE container, not a PE file.
var claims = buildClaims(map[string]string{
	claimPE:       "exe dll sys scr efi com cpl",
	claimNative:   "so dylib bundle o ko elf",
	claimZip:      "zip jar war ear apk aab ipa xpi vsix whl nupkg docx xlsx pptx odt ods odp epub",
	claimGzip:     "gz tgz",
	claimScript:   "sh bash zsh ksh fish py pl rb php js mjs cjs ts lua tcl command",
	claimText:     "txt md csv tsv log json yaml yml xml toml ini cfg conf rtf html htm svg",
	claimImage:    "png jpg jpeg gif bmp webp ico tif tiff heic",
	claimDocument: "pdf doc xls ppt",
})

func buildClaims(byClaim map[string]string) map[string]string {
	out := make(map[string]string)
	for claim, exts := range byClaim {
		for _, ext := range strings.Fields(exts) {
			out[ext] = claim
		}
	}
	return out
}

// accepts reports whether content of the detected type fits the claim. The
// text, image and document claims accept none of the detected types.
func accepts(claim, detected string) bool {
	switch claim {
	case claimPE:
		return detected == typePE
	case claimNative:
		return detected == typeELF || detected == typeMachO
	case claimZip:
		return detected == typeZip
	case claimGzip:
		return detected == typeGzip
	case claimScript:
		return detected == typeScript
	}
	return false
}

// mismatch reports whether the extension contradicts the detected type, and
// the claimed_type to report. Unknown content never mismatches. An unlisted
// extension on an ELF, Mach-O or PE file is a mismatch. A missing extension is
// a mismatch only for PE; ELF, Mach-O, zip, gzip and script files may lack one.
func mismatch(ext string, hasExt bool, detected string) (claimed string, ok bool) {
	if detected == typeUnknown {
		return "", false
	}
	native := detected == typeELF || detected == typeMachO || detected == typePE
	if !hasExt {
		return claimNone, detected == typePE
	}
	claim, known := claims[ext]
	if !known {
		return claimUnknown, native
	}
	return claim, !accepts(claim, detected)
}
