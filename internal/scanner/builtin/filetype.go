package builtin

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
)

// Detected types, the closed set of detected_type values.
const (
	typeELF     = "elf"
	typeMachO   = "macho"
	typePE      = "pe"
	typeZip     = "zip"
	typeGzip    = "gzip"
	typeScript  = "script"
	typeUnknown = "unknown"
)

const (
	headerSize  = 512
	peMinSize   = 0x40 // DOS header with e_lfanew at 0x3C
	peMaxOffset = 4096 // the PE signature must lie in the first 4 KiB
	// A fat Mach-O has 1 to 44 architectures. Java class files share the
	// CAFEBABE magic and carry a major version of 45 or more in those bytes.
	maxFatArchs = 44
)

// Constant finding text for FileType, so no name or content reaches Title,
// Description or Category (checked by tests).
const (
	filetypeCategory = "filetype"

	detectedTitle       = "File type detected from content"
	detectedDescription = "The start of the file matches a known file signature."
	unknownDescription  = "No executable, archive or script signature was found at the start of the file."

	mismatchTitle       = "File content does not match its extension"
	mismatchDescription = "The bytes identify a different file type than the extension claims."

	deceptiveTitle       = "Deceptive file name"
	deceptiveDescription = "The file name has invisible or control characters, invalid text, or a document-style extension before a program extension."

	execBitTitle       = "Executable bit set on non-program content"
	execBitDescription = "The file mode has an executable bit set, but the content is an archive or has no recognized program signature."
)

// FileType detects the real type of a file from its first bytes and flags an
// extension that contradicts it. It only checks fixed-offset magic numbers; it
// parses nothing, and a signature after offset 0 (a polyglot, an appended
// archive) is not seen.
type FileType struct{}

func (FileType) Name() string                    { return "filetype" }
func (FileType) Supports(artifact.Artifact) bool { return true }

func (FileType) Scan(_ context.Context, a artifact.Artifact, r io.ReaderAt, size int64) ([]finding.Finding, error) {
	detected, err := detect(r, size)
	if err != nil {
		return nil, err
	}
	execBit := a.Mode&0o111 != 0
	newFinding := func(id string, sev finding.Severity, title, desc string, meta map[string]any) finding.Finding {
		return finding.Finding{
			ID: id, Severity: sev, Category: filetypeCategory, Title: title, Description: desc,
			ArtifactID: a.ID, File: a.RelativePath, Metadata: meta,
		}
	}

	desc := detectedDescription
	if detected == typeUnknown {
		desc = unknownDescription
	}
	found := []finding.Finding{newFinding("filetype.detected", finding.SeverityInfo, detectedTitle, desc,
		map[string]any{"detected_type": detected, "executable_bit": execBit})}

	sev := finding.SeverityMedium
	if detected == typeELF || detected == typeMachO || detected == typePE {
		sev = finding.SeverityHigh
	}

	ext, hasExt := extension(a.Name)
	if claimed, ok := mismatch(ext, hasExt, detected); ok {
		meta := map[string]any{"claimed_type": claimed, "detected_type": detected}
		if _, known := claims[ext]; known {
			meta["extension"] = "." + ext
		}
		found = append(found, newFinding("filetype.mismatch", sev, mismatchTitle, mismatchDescription, meta))
	}

	// Independent of the mismatch: a deceptive name can sit on honest content.
	invisible, double := hasInvisibleRune(a.Name), doubleExtension(a.Name)
	if invisible || double {
		found = append(found, newFinding("filetype.deceptive_name", sev, deceptiveTitle, deceptiveDescription,
			map[string]any{"invisible_rune": invisible, "double_extension": double, "detected_type": detected}))
	}

	if execBit && (detected == typeZip || detected == typeGzip || detected == typeUnknown) {
		found = append(found, newFinding("filetype.executable_bit", finding.SeverityLow, execBitTitle, execBitDescription,
			map[string]any{"detected_type": detected}))
	}
	return found, nil
}

// detect names the file type from the first bytes. It reads at most
// min(512, size) bytes at offset 0 and, for a possible PE file, 4 more at e_lfanew:
// two reads at most, never past size. A short read is an error, never unknown.
func detect(r io.ReaderAt, size int64) (string, error) {
	var buf [headerSize]byte
	h := buf[:min(int64(headerSize), size)]
	if len(h) > 0 {
		if err := readFull(r, h, 0); err != nil {
			return "", err
		}
	}

	switch {
	case hasPrefix(h, "\x7fELF"):
		return typeELF, nil
	case hasPrefix(h, "\xfe\xed\xfa\xce"), hasPrefix(h, "\xfe\xed\xfa\xcf"),
		hasPrefix(h, "\xce\xfa\xed\xfe"), hasPrefix(h, "\xcf\xfa\xed\xfe"):
		return typeMachO, nil
	case (hasPrefix(h, "\xca\xfe\xba\xbe") || hasPrefix(h, "\xca\xfe\xba\xbf")) && len(h) >= 8:
		if n := binary.BigEndian.Uint32(h[4:8]); n >= 1 && n <= maxFatArchs {
			return typeMachO, nil
		}
	case hasPrefix(h, "MZ"):
		return detectPE(r, h, size)
	case hasPrefix(h, "PK\x03\x04"), hasPrefix(h, "PK\x05\x06"), hasPrefix(h, "PK\x07\x08"):
		return typeZip, nil
	case hasPrefix(h, "\x1f\x8b\x08"):
		return typeGzip, nil
	case hasPrefix(h, "#!"):
		return typeScript, nil
	}
	return typeUnknown, nil
}

// detectPE confirms the PE signature at e_lfanew. Offsets are int64 before any
// arithmetic so a hostile 32-bit value cannot overflow.
func detectPE(r io.ReaderAt, h []byte, size int64) (string, error) {
	if size < peMinSize || len(h) < peMinSize {
		return typeUnknown, nil
	}
	lfanew := int64(binary.LittleEndian.Uint32(h[0x3C:0x40]))
	if lfanew < peMinSize || lfanew+4 > min(size, peMaxOffset) {
		return typeUnknown, nil
	}
	var sig [4]byte
	if err := readFull(r, sig[:], lfanew); err != nil {
		return "", err
	}
	if string(sig[:]) == "PE\x00\x00" {
		return typePE, nil
	}
	return typeUnknown, nil
}

func hasPrefix(h []byte, magic string) bool {
	return len(h) >= len(magic) && string(h[:len(magic)]) == magic
}
