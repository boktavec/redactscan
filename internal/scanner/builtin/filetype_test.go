package builtin

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/scanner"
	"github.com/boktavec/redactscan/internal/scanner/scannertest"
)

// Fixtures are built at runtime from magic numbers only.
func pad(head string, n int) []byte {
	return append([]byte(head), make([]byte, max(0, n-len(head)))...)
}

func fat(nfat uint32) []byte {
	b := pad("\xca\xfe\xba\xbe", 16)
	binary.BigEndian.PutUint32(b[4:], nfat)
	return b
}

// pe returns a size-byte file with "MZ", e_lfanew set and, if sig, "PE\0\0" there.
func pe(size int, lfanew uint32, sig bool) []byte {
	if !sig {
		return peWith(size, lfanew, "")
	}
	return peWith(size, lfanew, "PE\x00\x00")
}

// peWith writes sig at e_lfanew. It panics if sig would overwrite e_lfanew
// itself (0x3C-0x3F), which would silently turn a lower-bound test into an
// upper-bound one.
func peWith(size int, lfanew uint32, sig string) []byte {
	b := pad("MZ", size)
	if size >= 0x40 {
		binary.LittleEndian.PutUint32(b[0x3C:], lfanew)
	}
	end := int64(lfanew) + int64(len(sig))
	if sig != "" && lfanew < 0x40 && end > 0x3C {
		panic("fixture signature overlaps e_lfanew")
	}
	if sig != "" && end <= int64(size) {
		copy(b[lfanew:], sig)
	}
	return b
}

var (
	elfFile  = pad("\x7fELF", 64)
	gzipFile = pad("\x1f\x8b\x08", 32)
	zipFile  = pad("PK\x03\x04", 32)
	script   = []byte("#!/bin/sh\necho hi\n")
	plain    = []byte("just some text\n")
)

// recorder is an io.ReaderAt that records every call, for bounds checks.
type recorder struct {
	content []byte
	size    int64 // the claimed size; reads must stay inside it. Zero means len(content).
	calls   int
	bad     bool // a read outside [0, size)
	// firstLen is the length of the first read.
	firstLen int
}

func (r *recorder) ReadAt(p []byte, off int64) (int, error) {
	r.calls++
	if r.calls == 1 {
		r.firstLen = len(p)
	}
	size := r.size
	if size == 0 {
		size = int64(len(r.content))
	}
	if off < 0 || off+int64(len(p)) > size || (len(p) > 0 && off >= size) {
		r.bad = true
	}
	return bytes.NewReader(r.content).ReadAt(p, off)
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		want    string
	}{
		{"empty", nil, typeUnknown},
		{"1 byte", []byte("M"), typeUnknown},
		{"2 bytes MZ", []byte("MZ"), typeUnknown},
		{"3 bytes ELF prefix", []byte("\x7fEL"), typeUnknown},
		{"4 bytes ELF", []byte("\x7fELF"), typeELF},
		{"3 bytes gzip", []byte("\x1f\x8b\x08"), typeGzip},
		{"gzip wrong method", []byte("\x1f\x8b\x07"), typeUnknown},
		{"shebang", []byte("#!"), typeScript},
		{"hash only", []byte("#"), typeUnknown},
		{"zip local", []byte("PK\x03\x04"), typeZip},
		{"zip empty", []byte("PK\x05\x06"), typeZip},
		{"zip spanned", []byte("PK\x07\x08"), typeZip},
		{"macho 32", []byte("\xfe\xed\xfa\xce"), typeMachO},
		{"macho 64", []byte("\xfe\xed\xfa\xcf"), typeMachO},
		{"macho 32 reversed", []byte("\xce\xfa\xed\xfe"), typeMachO},
		{"macho 64 reversed", []byte("\xcf\xfa\xed\xfe"), typeMachO},
		{"fat 1", fat(1), typeMachO},
		{"fat 44", fat(44), typeMachO},
		{"fat 0", fat(0), typeUnknown},
		{"fat 45", fat(45), typeUnknown},
		{"fat 64-bit offsets", append([]byte("\xca\xfe\xba\xbf"), 0, 0, 0, 2), typeMachO},
		{"fat magic only", []byte("\xca\xfe\xba\xbe"), typeUnknown},
		{"java class", []byte("\xca\xfe\xba\xbe\x00\x00\x00\x34"), typeUnknown},
		{"pe", pe(0x100, 0x80, true), typePE},
		{"pe at 0x40", pe(0x100, 0x40, true), typePE},
		{"pe with zip appended", append(pe(0x100, 0x80, true), "PK\x03\x04"...), typePE},
		{"pe signature at 4092", pe(8192, 4092, true), typePE},
		{"pe signature at 4093", pe(8192, 4093, true), typeUnknown},
		{"MZ without PE", pe(0x100, 0x80, false), typeUnknown},
		{"MZ under 0x40 bytes", pe(0x3F, 0, false), typeUnknown},
		{"lfanew 0x3C", pe(0x100, 0x3C, false), typeUnknown},
		{"valid signature at lfanew 0x02", pe(0x100, 0x02, true), typeUnknown},
		{"valid signature at lfanew 0x10", pe(0x100, 0x10, true), typeUnknown},
		{"valid signature at lfanew 0x38", pe(0x100, 0x38, true), typeUnknown},
		{"lfanew 0x3F", pe(0x100, 0x3F, false), typeUnknown},
		{"signature PE 01 00", peWith(0x100, 0x80, "PE\x01\x00"), typeUnknown},
		{"signature PE 00 01", peWith(0x100, 0x80, "PE\x00\x01"), typeUnknown},
		{"signature MZ 00 00", peWith(0x100, 0x80, "MZ\x00\x00"), typeUnknown},
		{"lfanew 0xFFFFFFFF", pe(0x100, 0xFFFFFFFF, true), typeUnknown},
		{"lfanew 0x7FFFFFFF", pe(0x100, 0x7FFFFFFF, true), typeUnknown},
		{"lfanew size-3", pe(0x100, 0x100-3, false), typeUnknown},
		{"lfanew size-4", pe(0x100, 0x100-4, true), typePE},
		{"text", plain, typeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &recorder{content: tt.content}
			got, err := detect(r, int64(len(tt.content)))
			if err != nil || got != tt.want {
				t.Errorf("detect = %q, %v; want %q", got, err, tt.want)
			}
			if r.bad || r.calls > 2 {
				t.Errorf("reads: %d calls, out of bounds %v", r.calls, r.bad)
			}
		})
	}
}

// TestDetectRejectsWithoutSecondRead: an e_lfanew outside the allowed range, or
// a non-MZ file, is decided from the header alone, so only one read happens.
func TestDetectRejectsWithoutSecondRead(t *testing.T) {
	for name, content := range map[string][]byte{
		"lfanew 0x3C":         pe(0x100, 0x3C, false),
		"lfanew 0x10":         pe(0x100, 0x10, true),
		"lfanew 0x3F":         pe(0x100, 0x3F, false),
		"lfanew 0xFFFFFFFF":   pe(0x100, 0xFFFFFFFF, true),
		"lfanew size-3":       pe(0x100, 0x100-3, false),
		"lfanew 4093":         pe(8192, 4093, true),
		"under 0x40 bytes":    pe(0x3F, 0, false),
		"not MZ (ELF)":        elfFile,
		"not MZ (zip)":        zipFile,
		"not MZ (java)":       []byte("\xca\xfe\xba\xbe\x00\x00\x00\x34"),
		"not MZ (thin macho)": []byte("\xce\xfa\xed\xfe"),
	} {
		t.Run(name, func(t *testing.T) {
			r := &recorder{content: content}
			if _, err := detect(r, int64(len(content))); err != nil || r.calls != 1 || r.firstLen != min(headerSize, len(content)) {
				t.Errorf("err %v, %d reads, first read %d bytes", err, r.calls, r.firstLen)
			}
		})
	}
}

func TestDetectEmptyReadsNothing(t *testing.T) {
	r := &recorder{}
	if got, err := detect(r, 0); got != typeUnknown || err != nil || r.calls != 0 {
		t.Errorf("detect = %q, %v after %d reads", got, err, r.calls)
	}
}

// TestDetectShortReadIsAnError: a file that ends before its size is never
// reported as unknown.
func TestDetectShortReadIsAnError(t *testing.T) {
	tests := []struct {
		name    string
		have    []byte
		claimed int64
	}{
		{"header cut short", []byte("\x7fELF"), 100},
		{"nothing at all", nil, 1},
		{"PE signature past the content", pe(600, 4000, false), 8192},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := detect(bytes.NewReader(tt.have), tt.claimed); err != errTruncated || got != "" {
				t.Errorf("detect = %q, %v; want errTruncated", got, err)
			}
		})
	}
}

func FuzzDetect(f *testing.F) {
	for _, seed := range [][]byte{nil, elfFile, gzipFile, zipFile, script, plain, fat(0), fat(1), fat(44), fat(45),
		[]byte("\xfe\xed\xfa\xce"), []byte("\xcf\xfa\xed\xfe"), []byte("PK\x07\x08"), []byte("PK\x05\x06"),
		[]byte("\xca\xfe\xba\xbe\x00\x00\x00\x34"), []byte("MZ"), pe(0x40, 0x40, false),
		pe(0x100, 0x80, true), pe(0x100, 0x100-4, true), pe(0x100, 0x100-3, true), pe(0x100, 0xFFFFFFFF, true),
		pe(0x100, 0x7FFFFFFF, true), pe(0x100, 0x10, true), pe(0x100, 0x3C, false),
		pe(8192, 4092, true), pe(8192, 4093, true)} {
		f.Add(seed, uint16(0))
		f.Add(seed, uint16(5000)) // a claimed size larger than the content
	}
	types := map[string]bool{typeELF: true, typeMachO: true, typePE: true, typeZip: true, typeGzip: true, typeScript: true, typeUnknown: true}
	f.Fuzz(func(t *testing.T, content []byte, extra uint16) {
		size := int64(len(content)) + int64(extra)
		r := &recorder{content: content, size: size}
		got, err := detect(r, size)
		if err != nil && err != errTruncated {
			t.Fatalf("unexpected error %v", err)
		}
		if err == nil && !types[got] {
			t.Fatalf("type %q is not in the closed set", got)
		}
		if extra == 0 && err != nil {
			t.Fatalf("error %v on complete content", err)
		}
		if r.calls > 2 || r.bad {
			t.Fatalf("%d reads, out of bounds %v", r.calls, r.bad)
		}
		if size > 0 && int64(r.firstLen) != min(int64(headerSize), size) {
			t.Fatalf("first read %d bytes for size %d", r.firstLen, size)
		}
		if !bytes.HasPrefix(content, []byte("MZ")) && r.calls > 1 {
			t.Fatalf("%d reads for non-MZ content", r.calls)
		}
	})
}

func TestExtension(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		hasExt bool
	}{
		{"a.exe", "exe", true},
		{"a.EXE", "exe", true},
		{"a.ExE", "exe", true},
		{"a.exe.", "exe", true},
		{"a.exe ", "exe", true},
		{"a.exe. . ", "exe", true},
		{"a.tar.gz", "gz", true},
		{".bashrc", "", false},
		{".bashrc.", "", false},
		{"noext", "", false},
		{"", "", false},
		{".", "", false},
		{"..", "", false},
		{"a.", "", false},
		{"a.e\u212Aexe", "", true}, // Kelvin sign must not fold to k
		{"a.\u212A", "", true},
		{"a.\xff", "", true},
		{"a.\u202efdp", "", true},
		{"a.ex\x80", "", true},
		{"a.\x1b[31m", "\x1b[31m", true}, // ASCII control bytes are kept; never in the claim table
		{"ghp_" + strings.Repeat("A", 36), "", false},
		{"a.ghp_" + strings.Repeat("A", 36), "ghp_" + strings.Repeat("a", 36), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, has := extension(tt.name); got != tt.want || has != tt.hasExt {
				t.Errorf("extension(%q) = %q, %v; want %q, %v", tt.name, got, has, tt.want, tt.hasExt)
			}
		})
	}
}

// TestClaimTable restates the fixed table from the spec.
func TestClaimTable(t *testing.T) {
	want := map[string]string{
		"pe":       "exe dll sys scr efi com cpl",
		"native":   "so dylib bundle o ko elf",
		"zip":      "zip jar war ear apk aab ipa xpi vsix whl nupkg docx xlsx pptx odt ods odp epub",
		"gzip":     "gz tgz",
		"script":   "sh bash zsh ksh fish py pl rb php js mjs cjs ts lua tcl command",
		"text":     "txt md csv tsv log json yaml yml xml toml ini cfg conf rtf html htm svg",
		"image":    "png jpg jpeg gif bmp webp ico tif tiff heic",
		"document": "pdf doc xls ppt",
	}
	total := 0
	for claim, exts := range want {
		for _, ext := range strings.Fields(exts) {
			total++
			if claims[ext] != claim {
				t.Errorf("claims[%q] = %q, want %q", ext, claims[ext], claim)
			}
		}
	}
	if len(claims) != total {
		t.Errorf("table has %d entries, want %d", len(claims), total)
	}
	if _, ok := claims["msi"]; ok {
		t.Error("msi must stay out of the table")
	}
}

func TestMismatchMatrix(t *testing.T) {
	// exts holds one extension per claim.
	exts := map[string]string{
		claimPE: "exe", claimNative: "so", claimZip: "zip", claimGzip: "gz", claimScript: "sh",
		claimText: "txt", claimImage: "png", claimDocument: "pdf",
	}
	accepted := map[string][]string{
		claimPE: {typePE}, claimNative: {typeELF, typeMachO}, claimZip: {typeZip}, claimGzip: {typeGzip}, claimScript: {typeScript},
	}
	for claim, ext := range exts {
		for _, detected := range []string{typeELF, typeMachO, typePE, typeZip, typeGzip, typeScript, typeUnknown} {
			got, bad := mismatch(ext, true, detected)
			wantBad := detected != typeUnknown
			for _, ok := range accepted[claim] {
				if ok == detected {
					wantBad = false
				}
			}
			if bad != wantBad || (bad && got != claim) {
				t.Errorf("claim %s (.%s) vs %s: got %q, %v; want mismatch %v", claim, ext, detected, got, bad, wantBad)
			}
		}
	}
	for _, tt := range []struct {
		ext      string
		hasExt   bool
		detected string
		want     string
		bad      bool
	}{
		{"zzz", true, typeELF, claimUnknown, true},
		{"zzz", true, typeMachO, claimUnknown, true},
		{"", true, typePE, claimUnknown, true},
		{"zzz", true, typeZip, "", false},
		{"zzz", true, typeGzip, "", false},
		{"zzz", true, typeScript, "", false},
		{"zzz", true, typeUnknown, "", false},
		{"", false, typePE, claimNone, true},
		{"", false, typeELF, "", false},
		{"", false, typeMachO, "", false},
		{"", false, typeScript, "", false},
		{"", false, typeZip, "", false},
		{"", false, typeGzip, "", false},
	} {
		if got, bad := mismatch(tt.ext, tt.hasExt, tt.detected); bad != tt.bad || (bad && got != tt.want) {
			t.Errorf("mismatch(%q, %v, %s) = %q, %v; want %q, %v", tt.ext, tt.hasExt, tt.detected, got, bad, tt.want, tt.bad)
		}
	}
}

// runFileType scans through the production registry and returns the filetype
// findings by ID.
func runFileType(t *testing.T, name string, mode fs.FileMode, content []byte) map[string]finding.Finding {
	t.Helper()
	a := newArtifact(name, int64(len(content)))
	a.Mode = mode
	res := runAll(t, a, bytes.NewReader(content), int64(len(content)))
	if res.Incomplete() {
		t.Fatalf("name %q: incomplete: %v", name, res.Failures)
	}
	out := map[string]finding.Finding{}
	for _, f := range res.Findings {
		if f.Category == filetypeCategory {
			out[f.ID] = f
		}
	}
	return out
}

func TestFileTypeFindings(t *testing.T) {
	const (
		detected = "filetype.detected"
		mism     = "filetype.mismatch"
		execBit  = "filetype.executable_bit"
	)
	tests := []struct {
		name    string
		file    string
		mode    fs.FileMode
		content []byte
		ids     []string
		sev     finding.Severity // of the mismatch, if any
		meta    map[string]any   // expected mismatch metadata
		dType   string
		exec    bool
	}{
		{name: "pdf holding ELF", file: "invoice.pdf", mode: 0o755, content: elfFile, ids: []string{detected, mism},
			sev: finding.SeverityHigh, meta: map[string]any{"claimed_type": "document", "detected_type": "elf", "extension": ".pdf"},
			dType: "elf", exec: true},
		{name: "txt holding a script", file: "report.txt", mode: 0o644, content: script, ids: []string{detected, mism},
			sev: finding.SeverityMedium, meta: map[string]any{"claimed_type": "text", "detected_type": "script", "extension": ".txt"}, dType: "script"},
		{name: "exe holding gzip", file: "x.exe", mode: 0o644, content: gzipFile, ids: []string{detected, mism},
			sev: finding.SeverityMedium, meta: map[string]any{"claimed_type": "pe", "detected_type": "gzip", "extension": ".exe"}, dType: "gzip"},
		{name: "png holding macho", file: "a.png", content: []byte("\xcf\xfa\xed\xfe"), ids: []string{detected, mism},
			sev: finding.SeverityHigh, meta: map[string]any{"claimed_type": "image", "detected_type": "macho", "extension": ".png"}, dType: "macho"},
		{name: "exe holding PE", file: "x.exe", content: pe(0x100, 0x80, true), ids: []string{detected}, dType: "pe"},
		{name: "uppercase EXE holding PE", file: "X.EXE", content: pe(0x100, 0x80, true), ids: []string{detected}, dType: "pe"},
		{name: "PE without extension", file: "program", content: pe(0x100, 0x80, true), ids: []string{detected, mism},
			sev: finding.SeverityHigh, meta: map[string]any{"claimed_type": "none", "detected_type": "pe"}, dType: "pe"},
		{name: "ELF with unlisted extension", file: "a.zzz", content: elfFile, ids: []string{detected, mism},
			sev: finding.SeverityHigh, meta: map[string]any{"claimed_type": "unknown", "detected_type": "elf"}, dType: "elf"},
		{name: "PE with Kelvin-sign extension", file: "a.e\u212Aexe", content: pe(0x100, 0x80, true), ids: []string{detected, mism},
			sev: finding.SeverityHigh, meta: map[string]any{"claimed_type": "unknown", "detected_type": "pe"}, dType: "pe"},
		{name: "ELF without extension", file: "tool", mode: 0o755, content: elfFile, ids: []string{detected}, dType: "elf", exec: true},
		{name: "script without extension", file: "run", mode: 0o755, content: script, ids: []string{detected}, dType: "script", exec: true},
		{name: "zip with executable bit", file: "a.zip", mode: 0o755, content: zipFile, ids: []string{detected, execBit}, dType: "zip", exec: true},
		{name: "gzip with one executable bit", file: "a.gz", mode: 0o001, content: gzipFile, ids: []string{detected, execBit}, dType: "gzip", exec: true},
		{name: "unknown with executable bit", file: "notes.txt", mode: 0o010, content: plain, ids: []string{detected, execBit}, dType: "unknown", exec: true},
		{name: "unknown, no executable bit", file: "notes.txt", mode: 0o666, content: plain, ids: []string{detected}, dType: "unknown"},
		{name: "empty file", file: "empty.bin", content: nil, ids: []string{detected}, dType: "unknown"},
		{name: "java class is not macho", file: "A.class", content: []byte("\xca\xfe\xba\xbe\x00\x00\x00\x34"), ids: []string{detected}, dType: "unknown"},
		{name: "MZ without PE", file: "a.exe", content: pe(0x100, 0x80, false), ids: []string{detected}, dType: "unknown"},
		{name: "dotfile ELF", file: ".hidden", content: elfFile, ids: []string{detected}, dType: "elf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runFileType(t, tt.file, tt.mode, tt.content)
			if len(got) != len(tt.ids) {
				t.Fatalf("findings = %v, want %v", got, tt.ids)
			}
			for _, id := range tt.ids {
				if _, ok := got[id]; !ok {
					t.Fatalf("missing %s in %v", id, got)
				}
			}
			d := got[detected]
			if d.Severity != finding.SeverityInfo || d.Metadata["detected_type"] != tt.dType || d.Metadata["executable_bit"] != tt.exec ||
				d.File != tt.file || d.ArtifactID != "file-1" {
				t.Errorf("detected = %+v", d)
			}
			if m, ok := got[mism]; ok {
				if m.Severity != tt.sev || len(m.Metadata) != len(tt.meta) {
					t.Errorf("mismatch = %+v", m)
				}
				for k, v := range tt.meta {
					if m.Metadata[k] != v {
						t.Errorf("mismatch metadata %s = %v, want %v", k, m.Metadata[k], v)
					}
				}
			}
			if e, ok := got[execBit]; ok && (e.Severity != finding.SeverityLow || e.Metadata["detected_type"] != tt.dType) {
				t.Errorf("executable_bit = %+v", e)
			}
		})
	}
}

func TestFileTypeUnknownDescriptionDoesNotImplySafety(t *testing.T) {
	d := runFileType(t, "a.txt", 0, plain)["filetype.detected"]
	if d.Description != unknownDescription || strings.Contains(strings.ToLower(d.Description), "safe") {
		t.Errorf("description = %q", d.Description)
	}
}

// TestFileTypeFindingsAreConstant runs hostile names and varied content, and
// checks that fixed text and closed value sets are all that comes out.
func TestFileTypeFindingsAreConstant(t *testing.T) {
	names := []string{
		"plain.txt", "a\x1b[31m.exe", "x" + string(rune(0x202e)) + "fdp.exe", "\xff\xfe.pdf",
		"gh" + "p_" + strings.Repeat("A", 36) + ".exe", "a.e\u212Aexe", "[GITHUB_TOKEN_1].sh", ".exe",
	}
	contents := [][]byte{nil, elfFile, gzipFile, zipFile, script, plain, pe(0x100, 0x80, true), fat(2)}
	titles := map[string]string{
		"filetype.detected": detectedTitle, "filetype.mismatch": mismatchTitle, "filetype.executable_bit": execBitTitle}
	descs := map[string][]string{
		"filetype.detected": {detectedDescription, unknownDescription}, "filetype.mismatch": {mismatchDescription},
		"filetype.executable_bit": {execBitDescription}}
	types := map[any]bool{"elf": true, "macho": true, "pe": true, "zip": true, "gzip": true, "script": true, "unknown": true}
	claimed := map[any]bool{"unknown": true, "none": true}
	for _, c := range claims {
		claimed[c] = true
	}
	for _, name := range names {
		for _, content := range contents {
			for id, f := range runFileTypeLenient(t, name, content) {
				if f.Title != titles[id] || f.Category != "filetype" || !contains(descs[id], f.Description) {
					t.Errorf("%q %s: text varies: %+v", name, id, f)
				}
				if v, ok := f.Metadata["detected_type"]; !ok || !types[v] {
					t.Errorf("%q %s: detected_type %v", name, id, v)
				}
				if v, ok := f.Metadata["claimed_type"]; ok && !claimed[v] {
					t.Errorf("%q %s: claimed_type %v", name, id, v)
				}
				if v, ok := f.Metadata["extension"]; ok && claims[strings.TrimPrefix(v.(string), ".")] == "" {
					t.Errorf("%q %s: extension %v not in table", name, id, v)
				}
				for k, v := range f.Metadata {
					switch v.(type) {
					case string, bool:
					default:
						t.Errorf("%q %s: metadata %s has type %T", name, id, k, v)
					}
				}
			}
		}
	}
}

func contains(set []string, s string) bool {
	for _, v := range set {
		if v == s {
			return true
		}
	}
	return false
}

// runFileTypeLenient is runFileType for names the registry may reject.
func runFileTypeLenient(t *testing.T, name string, content []byte) map[string]finding.Finding {
	t.Helper()
	a := newArtifact(name, int64(len(content)))
	a.Mode = 0o755
	res := runAll(t, a, bytes.NewReader(content), int64(len(content)))
	out := map[string]finding.Finding{}
	for _, f := range res.Findings {
		if f.Category == filetypeCategory {
			out[f.ID] = f
		}
	}
	return out
}

// TestSecretShapedPathFailsClosedForBothScanners: the registry drops every
// finding whose File looks like a secret, so nothing is reported and the scan
// is incomplete.
func TestSecretShapedPathFailsClosedForBothScanners(t *testing.T) {
	name := "gh" + "p_" + strings.Repeat("A", 36) // built at runtime
	res := runAll(t, newArtifact(name, 4), strings.NewReader("abcd"), 4)
	want := []scanner.Failure{{Scanner: "hash", Reason: scanner.ReasonInvalidFinding}, {Scanner: "filetype", Reason: scanner.ReasonInvalidFinding}}
	if len(res.Findings) != 0 || len(res.Failures) != 2 || res.Failures[0] != want[0] || res.Failures[1] != want[1] {
		t.Errorf("result = %+v", res)
	}
}

func TestFileTypeShortReadIsIncomplete(t *testing.T) {
	// The file ends before its recorded size, as a sysfs file or a file
	// truncated during the scan does.
	reg, err := scanner.NewRegistry(FileType{})
	if err != nil {
		t.Fatal(err)
	}
	res := reg.Run(context.Background(), newArtifact("a.bin", 100), strings.NewReader("\x7fELF"), 100)
	if len(res.Findings) != 0 || len(res.Failures) == 0 || res.Failures[0] != (scanner.Failure{Scanner: "filetype", Reason: scanner.ReasonError}) {
		t.Errorf("result = %+v", res)
	}
}

func TestFileTypeScannerContract(t *testing.T) {
	a := newArtifact("a.pdf", int64(len(elfFile)))
	a.Mode = 0o755
	scannertest.AssertNoMutation(t, FileType{}, a, elfFile)
	scannertest.AssertNoMutation(t, FileType{}, newArtifact("a.exe", 0), nil)
}

var _ io.ReaderAt = (*recorder)(nil)
