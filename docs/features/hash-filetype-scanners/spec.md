# HashScanner and FileTypeScanner: spec

Status: approved by the user (design review, interview questions 1-7), with every `security-reviewer` design requirement (R1-R10, verdict PASS WITH REQUIREMENTS) folded in. R7 (`filetype.deceptive_name`) is in scope at the user's request.
Story: [REDACT-37](http://localhost:8080/issue/REDACT-37) "HashScanner and FileTypeScanner".
Branch: `feat/redact-37-hash-filetype` (five stacked PRs; see section 9). Create it before implementation; this spec was written on `main`.
Packages: changes to `internal/scanner`, `internal/scanner/scannertest`, `internal/artifact`, `internal/cli`, `internal/report`; new `internal/scanner/builtin` and `internal/textsafe`. Go standard library only, no new dependency.
Depends on (merged): REDACT-36 (scanner interface, registry, `scan FILE`), REDACT-35 (Artifact and Finding models), REDACT-38 (report output, ADR 0005), REDACT-10 (`safefs`).
Decision record: new ADR 0007 "Scanner reads through a bounded ReaderAt; 1 GiB cap" (supersedes ADR 0004 decisions 1-3; see section 5). ADR 0004 gets a "Superseded in part by ADR 0007" note.
Related: `docs/architecture.md` sections 5, 7 and 9, `docs/threat-model.md` (Scanner section), `docs/features/scanner-scan-file/spec.md` (D1a), `docs/features/artifact-finding-models/spec.md` (FR1).

> Spec text and tests never contain realistic secret values or literal control/bidi characters. Tests build secret-shaped and hostile input at runtime; this spec writes code points as `<U+XXXX>`.

## 1. Feature overview

**Purpose.** `redactscan scan FILE` reports the file's SHA-256 and its real type detected from bytes, and flags extension spoofing, executable bits on non-executable content, and deceptive names. These are the first production scanners, so after this story a scan of an ordinary file is complete (exit 0) instead of `no scanner ran`.

**Concrete example.**

```text
$ chmod +x invoice.pdf          # actually an ELF binary
$ redactscan scan ./invoice.pdf
redactscan scan report
status: complete

== high (1) ==
- filetype.mismatch: File content does not match its extension
  file: ./invoice.pdf
  category: filetype
  reasoning: The bytes identify a different file type than the extension claims.
  metadata: claimed_type="document", detected_type="elf", extension=".pdf"

== info (2) ==
- filetype.detected: File type detected from content
  ...
  metadata: detected_type="elf", executable_bit=true
- hash.sha256: SHA-256 of file content
  ...
  metadata: sha256="<64 hex>", size=8432
```

**Scope.**

- Scanner contract migration (ADR 0004 decision 2): `Scan(ctx, a, r io.ReaderAt, size int64)`, with `Run` wrapping the caller's reader in an opaque bounded type. `MaxContentSize` becomes 1 GiB (Assumed).
- `Artifact.Mode fs.FileMode` (permission bits only) filled from `f.Stat()` on the opened descriptor.
- CLI: open, fstat, run without reading into memory, then detect a change during the scan (re-fstat and a probe for extra bytes) and mark the result incomplete.
- New package `internal/scanner/builtin`: shared `readFull`, `hash` scanner, `filetype` scanner, `Default()` registry.
- `filetype` findings: `filetype.detected`, `filetype.mismatch`, `filetype.executable_bit`, `filetype.deceptive_name`.
- `internal/textsafe.IsDangerous`, extracted from `internal/report` so `builtin` and `report` share one definition.
- Docs: ADR 0007, ADR 0004 note, architecture sections 5, 7 and 9, threat model, artifact-finding-models spec.

**Non-goals.**

- A shared in-memory read helper (`MaxInMemoryRead`) for buffering scanners. Follow-up for ScriptScanner and SourceScanner (section 6, follow-ups).
- Filling `Artifact.SHA256` (scanners never mutate the artifact; the hash is a finding).
- Archive inspection, polyglot detection beyond offset 0, appended-ZIP detection, Mach-O/ELF/PE parsing beyond the magic check.
- Directory scans (`scan ./dir`, REDACT-39), per-scanner deadlines, an aggregate byte budget, SIGINT handling (REDACT-39 owns those).
- A findings exit code or policy (REDACT-50). Severities are input to policy, not decisions.
- MIME detection for text, images or documents. Only the six magic types are detected; everything else is `unknown`.

## 2. Functional requirements and acceptance criteria

### 2.1 Scanner contract (PR 1)

| ID | Requirement | Acceptance |
| --- | --- | --- |
| FR1 | `Scanner.Scan(ctx context.Context, a artifact.Artifact, r io.ReaderAt, size int64) ([]finding.Finding, error)`. `Registry.Run(ctx, a, r io.ReaderAt, size int64) Result`. | Compiles; every existing fake scanner and test is migrated. |
| FR2 (R9) | `Run` checks in this order before any read: `a.Validate()`, `size < 0`, `r == nil`, `a.Size != size` (all `{registry, invalid artifact}`), then `size > MaxContentSize` (`{registry, too large}`), all before wrapping. No `ReadAt` call happens on any of these paths. | Table test with a counting fake reader: each case records the expected failure and zero `ReadAt` calls, including `size == MaxContentSize+1`. |
| FR3 (R9) | `MaxContentSize = 1 << 30` (1 GiB, Assumed). Offsets and sizes are `int64` everywhere. | `task cross` passes for `GOARCH=386`. |
| FR4 (R1) | `Run` wraps `r` once in an unexported `boundedReader{r io.ReaderAt; size int64}` whose only exported method is `ReadAt`. `off < 0` returns `0, errBadOffset` (fixed text). `off >= size` returns `0, io.EOF`. Otherwise `p` is clipped to `size-off`; if the inner reader reports `n > len(clipped)` the call returns `0, errReadFailed`; an inner error other than `io.EOF` becomes `errReadFailed` (fixed text, never the OS error). A short clipped read returns `io.EOF` only if the inner reader did. Scanners never receive `*os.File` or `*io.SectionReader`. | Tests: the value passed to a fake scanner does not satisfy `interface{ Chmod(fs.FileMode) error }`, `interface{ Name() string }`, `interface{ Fd() uintptr }` or `interface{ Outer() (io.ReaderAt, int64, int64) }`; `ReadAt` at and past `size` returns `0, io.EOF`; negative offset rejected; inner reader returning more than `len(p)` yields an error; an inner `*fs.PathError` never appears in the returned error (`errors.As` fails and the text has no path). |
| FR5 (R9) | A typed-nil `*os.File` passed as `r` does not panic: every scanner's read fails, and the result is incomplete. | Test passes `(*os.File)(nil)` with `size > 0`: result incomplete, no panic. |
| FR6 (R5) | `artifact.Artifact` gains `Mode fs.FileMode` holding permission bits only (`Mode & ^fs.ModePerm == 0` by contract). Doc: filled from `f.Stat()` on the descriptor that is scanned; never from `Lstat` on a path. | Doc comment present; artifact-finding-models spec FR1 updated. |
| FR7 (R9) | `scannertest.AssertNoMutation(t, s, a, content []byte)` keeps its signature, builds a counting fake `io.ReaderAt` over `content`, calls `s.Scan` with `size = len(content)`, and fails if `a.Metadata` changed or any `ReadAt` call had `off < 0`, `off+len(p) > size`, or `len(p) > 0` with `off >= size`. | Self-tests in `scannertest_test.go`: a well-behaved fake passes; fakes that read past the end, at a negative offset, or mutate metadata fail. |
| FR8 (R1) | The scanner import allowlist adds `io` (and `io/fs` only if needed). `TestPackageImportsAreAllowed` skips `builtin` (which has its own test, FR19) as it skips `scannertest`. | Test passes; widening is a reviewed edit. |
| FR9 (R5) | CLI `openArtifact(path)` replaces `readArtifact`: `safefs.OpenRegular`, then `f.Stat()` once; `Size = fi.Size()`, `Mode = fi.Mode().Perm()`. The descriptor is kept open until after `Run` and the FR11/FR12 checks. Nothing is read into memory. | CLI tests: a 0755 file yields `Mode == 0o755`; a sparse file over the cap yields `too large` with no read. |

### 2.2 Change detection in the CLI (PR 2, R2)

| ID | Requirement | Acceptance |
| --- | --- | --- |
| FR10 | `scanner.ReasonChanged Reason = "changed"` is added. The package doc says `Run` never produces it; callers record it as `{registry, changed}` when the file changed during the scan. | Report golden test with a `changed` failure renders it. |
| FR11 | After `Run`, the CLI calls `f.Stat()` again on the same descriptor and compares size, mtime (ns) and ctime (ns, from `syscall.Stat_t`: `Ctimespec` on darwin, `Ctim` on linux, in per-OS files). Any difference, or a failing second fstat, appends `{registry, changed}`. | Seam test: a hook between `Run` and the second fstat rewrites the file, giving exit 1 and `changed`. An untouched file is complete. |
| FR12 | After `Run`, the CLI reads 1 byte at offset `size` with `f.ReadAt`. `n > 0` (bytes appended, or a procfs file with fstat size 0) or any error other than `io.EOF` appends `{registry, changed}`. | Test: an append during the seam gives `changed`. Linux-only test: `scan /proc/<pid>/status` (own pid) is incomplete (never reported complete). |
| FR13 | Docs (threat model, scanner package doc): the hash is of the bytes as read during this scan, not proof of identity. Quarantine and policy must re-hash their own copy. | Text present. |

### 2.3 Shared read helper and HashScanner (PR 3)

| ID | Requirement | Acceptance |
| --- | --- | --- |
| FR14 (R3) | `builtin.readFull(r io.ReaderAt, p []byte, off int64) error`: success when `n == len(p)` and the error is nil or `io.EOF`; a full read with any other error is `errTruncated` too. `n < len(p)` returns `errTruncated` (fixed text "content shorter than its size"). Never returns or wraps the reader's error. | Fakes: `(len, io.EOF)` succeeds; `(short, nil)`, `(short, EIO)`, `(0, io.EOF)` at offset 0 with `size > 0` all give `errTruncated`; the error text never contains a path from a `*fs.PathError` fake. |
| FR15 (R8) | `hash` scanner (`Name() == "hash"`, `Supports` always true): a manual loop over a single 64 KiB buffer (no `io.Copy`/`io.CopyBuffer`, so no `WriterTo`/`ReaderFrom` bypass), `readFull` for each chunk, `ctx.Err()` checked before each chunk. Exactly `size` bytes are hashed. | Vectors: empty content gives `e3b0c442...b855`; `abc` gives `ba7816bf...15ad`. A cancelled ctx gives `{hash, canceled}` through `Run`. |
| FR16 | One finding: ID `hash.sha256`, severity info, Category `hash`, Title "SHA-256 of file content", Description "SHA-256 digest of the bytes read during this scan.", `ArtifactID = a.ID`, `File = a.RelativePath`, Metadata `{sha256: <lowercase hex>, size: int64(size)}`. | Through `Registry.Run`: `sha256` matches `^[0-9a-f]{64}$`; `size` is an `int64` equal to the input size. |
| FR17 | A large file is hashed without being read into memory. | A sparse temp file of 512 MiB is hashed through `Run` and matches a reference hash computed in the test with `io.Copy`; allocations (`runtime.MemStats` delta or `testing.AllocsPerRun`) are the same for 1 MiB and 512 MiB within a small constant. Skipped with `-short`. `BenchmarkHash` reports MB/s. |
| FR18 | `builtin.Default()` returns `scanner.NewRegistry(Hash{}, FileType{})` (PR 3 registers only `Hash{}`; PR 4 adds `FileType{}`). `scanner.Default` is removed; `cli.defaultRegistry = builtin.Default`. `builtin` imports `scanner`, never the reverse. | CLI test: a real `scan` of a small file is complete and shows `hash.sha256`. |
| FR19 (R1) | `builtin` has its own import-allowlist test: `bytes`, `context`, `crypto/sha256`, `encoding/binary`, `encoding/hex`, `errors`, `io`, `strings`, `unicode/utf8`, `internal/artifact`, `internal/finding`, `internal/scanner`, `internal/textsafe` (from PR 5). Forbidden, as for `scanner`: `os`, `os/exec`, `syscall`, `net`, `plugin`, `unsafe`, `log`, `internal/safefs`, plus `debug/*`, `archive/*`, `compress/*`. | Test passes, plus a negative self-test like `TestDisallowedImportsDetectsBadImports`. |

### 2.4 FileTypeScanner (PR 4)

| ID | Requirement | Acceptance |
| --- | --- | --- |
| FR20 (R3) | `filetype` scanner (`Name() == "filetype"`, `Supports` always true). It reads `min(512, size)` bytes at offset 0 with `readFull`. A short read is an error (`{filetype, error}`, incomplete), never `unknown`. `size == 0` reads nothing and detects `unknown`. | Fakes from FR14 through `Run`. |
| FR21 (R4) | Detection from header `h` (every check is length-checked first), first match wins. **ELF**: `len>=4` and `7F 45 4C 46`. **Mach-O thin**: `len>=4` and one of `FE ED FA CE`, `FE ED FA CF`, `CE FA ED FE`, `CF FA ED FE`. **Mach-O fat**: `size>=8`, `len>=8`, `CA FE BA BE` or `CA FE BA BF`, and big-endian `nfat = uint32(h[4:8])` with `1 <= nfat < 45` (Java class files have major version >= 45 there). **PE**: `size >= 0x40`, `h[0:2] == "MZ"`, `lfanew := int64(binary.LittleEndian.Uint32(h[0x3C:0x40]))`, require `lfanew >= 0x40` and `lfanew+4 <= min(size, 4096)`, then exactly one extra 4-byte `readFull` at `lfanew` equal to `"PE\x00\x00"`. `MZ` without a valid PE signature is `unknown`. **ZIP**: `len>=4` and `PK\x03\x04`, `PK\x05\x06` or `PK\x07\x08`. **gzip**: `len>=3` and `1F 8B 08`. **script**: `len>=2` and `#!`. Otherwise `unknown`. | Fixtures: 0-4 byte files; each magic; `e_lfanew` = `0xFFFFFFFF`, `0x7FFFFFFF`, `size-3`, `4093` (and `4092` passes); `nfat` = 0, 44, 45; a Java class header (`CAFEBABE 0000 0034`); a PE with a ZIP appended detects `pe`. |
| FR22 (R4) | Fuzz test `FuzzDetect(testing.F)` over content: no panic, at most 2 `ReadAt` calls, no read past `size` (counting fake). Seeded with every fixture. | `go test` runs the seed corpus; a short local fuzz run (`-fuzztime=30s`) is reported in the PR description. |
| FR23 (R6) | Extension: take `a.Name`, strip trailing ASCII spaces and dots (Windows ignores them), then take the bytes after the last `.`. A name whose only `.` is at index 0 (dotfile) has no extension. The extension is lowercased with byte-level ASCII folding only (`A-Z` to `a-z`); any non-ASCII byte means "unknown extension". Never `strings.ToLower` (the Kelvin sign U+212A folds to `k`). | Tests: `a.EXE`, `x.exe.`, `x.exe ` (all claim pe), `.bashrc` (none), `x.e<U+212A>e` (unknown), invalid UTF-8, `<U+202E>`, an ANSI escape, `ghp_` + 36 letters in the stem. |
| FR24 | Fixed claim table (extension to claimed type). `pe`: exe dll sys scr efi com cpl. `native` (ELF or Mach-O): so dylib bundle o ko elf. `zip`: zip jar war ear apk aab ipa xpi vsix whl nupkg docx xlsx pptx odt ods odp epub. `gzip`: gz tgz. `script`: sh bash zsh ksh fish py pl rb php js mjs cjs ts lua tcl command. `text`: txt md csv tsv log json yaml yml xml toml ini cfg conf rtf html htm svg. `image`: png jpg jpeg gif bmp webp ico tif tiff heic. `document`: pdf doc xls ppt. (`msi` is an OLE container and is left out.) The extension string in Metadata is the table key with a leading `.`, a constant. | Table-driven test over every entry. |
| FR25 | Compatibility: claim `pe` accepts `pe`; `native` accepts `elf`, `macho`; `zip`, `gzip`, `script` accept themselves; `text`, `image`, `document` accept none of the six. Detected `unknown` never causes a mismatch. A known extension whose claim does not accept the detected type is a mismatch. An extension not in the table on `elf`/`macho`/`pe` is a mismatch with `claimed_type: "unknown"`. No extension on `elf`/`macho`/`script` is fine; no extension on `pe` is a mismatch with `claimed_type: "none"`. An unknown or missing extension on `zip`/`gzip`/`script` is not a mismatch. | Matrix test over (claim, detected). |
| FR26 | Findings (constant Title, Description and Category `filetype`; `File = a.RelativePath`). **`filetype.detected`**: info, always exactly one; Metadata `detected_type`, `executable_bit` (bool, `a.Mode&0o111 != 0`). **`filetype.mismatch`**: high if detected is `elf`/`macho`/`pe`, else medium; Metadata `claimed_type`, `detected_type`, `extension` (only when in the table). **`filetype.executable_bit`**: low, when the exec bit is set and detected is `zip`, `gzip` or `unknown`; Metadata `detected_type`. Wording is "executable bit set", never "executable". The `detected` Description for `unknown` must not imply safety: "No executable, archive or script signature was found at the start of the file." | Through `Registry.Run`, per variant. |

### 2.5 Deceptive names and shared escaping rule (PR 5, R7)

| ID | Requirement | Acceptance |
| --- | --- | --- |
| FR27 | New package `internal/textsafe` with `IsDangerous(r rune) bool`, moved verbatim from `report/escape.go` (`!strconv.IsPrint(r)` or `Other_Default_Ignorable_Code_Point` or `Variation_Selector`). `report` calls it; report behaviour and golden files are unchanged. | Existing report tests pass unchanged; report import allowlist updated. |
| FR28 | **`filetype.deceptive_name`**: emitted once when `a.Name` contains a rune with `textsafe.IsDangerous` or an invalid UTF-8 byte, or has a double extension: the final extension claims `pe`, `native` or `script` and the segment before it (after stripping trailing ASCII spaces) is a table key claiming `text`, `image` or `document` (`report.pdf.exe`, `photo.jpg.sh`). Severity high if detected is `elf`/`macho`/`pe`, else medium. Metadata `invisible_rune` (bool), `double_extension` (bool), `detected_type`. No name bytes in Metadata. | `invoice<U+202E>fdp.exe` holding PE: high, `invisible_rune=true`; `report.pdf.exe`: `double_extension=true`; `notes.txt`: none; `<U+200B>` inside a name on `unknown` content: medium. |

### 2.6 Cross-cutting (R10, R6, R8)

| ID | Requirement | Acceptance |
| --- | --- | --- |
| FR29 (R10) | Every finding variant from both scanners has constant Title, Description and Category (ADR 0005 requirement). | One test per scanner runs it over hostile inputs (names with `<U+202E>`, ANSI, `ghp_`-shaped stems; varied content) and asserts Title/Description/Category belong to the fixed set declared in the scanner. |
| FR30 (R10) | `detected_type` belongs to `{elf, macho, pe, zip, gzip, script, unknown}`; `claimed_type` to the claim types plus `{unknown, none}`; `executable_bit`, `invisible_rune`, `double_extension` are `bool`; `size` is `int64`. | Assertions in the end-to-end tests through `Registry.Run`. |
| FR31 (R10) | All assertions in FR16, FR26 and FR28-FR30 go through `Registry.Run`, so the registry's finding checks run. | Tests use `builtin.Default()` or `scanner.NewRegistry(...)`. |
| FR32 (R6) | A secret-shaped `RelativePath` (for example `ghp_` + 36 letters built at runtime) makes the registry drop every finding of both scanners as invalid, so the result is incomplete (fail closed). Documented in the threat model. | CLI test: exit 1, failures `hash: invalid finding` and `filetype: invalid finding`. |
| FR33 (R8) | The scanner package doc and threat model say: future buffering scanners keep their own small cap and never `make([]byte, size)`; an aggregate byte budget and a per-scan deadline via ctx belong to REDACT-39; no per-scanner timeout, SIGINT handling, or protection against network/FUSE reads that block (accepted). | Text present. |

## 3. Technical design

### 3.1 Data flow

```text
cli.runScan
  safefs.OpenRegular(path) -> f
  fi := f.Stat()                          (size, mtime, ctime, Mode().Perm())
  a := Artifact{ID: "file-1", Size, Mode, Name, RelativePath, ...}
  res := reg.Run(ctx, a, f, fi.Size())
      Run: validate a, size, r, a.Size==size, cap   (no reads)
           br := &boundedReader{f, size}            (opaque, ReadAt only)
           for each scanner: Scan(ctx, a, br, size) (isolated as today)
  afterRun()                                         (test seam)
  changed := restat(f) differs  ||  f.ReadAt(1 byte, size) gives data or a non-EOF error
  if changed: res.Failures += {registry, changed}
  f.Close()
  render(res)
```

### 3.2 `internal/scanner`

- `scanner.go`: interface change; `MaxContentSize = 1 << 30`; `ReasonChanged`; package doc updated (read only through `ReadAt`, never keep `r` after `Scan` returns, never `make([]byte, size)`, fixed-text errors, the hash is of bytes as read).
- `bounded.go` (new): `boundedReader`, `errBadOffset`, `errReadFailed`.
- `run.go`: new pre-checks (FR2) and wrapping (FR4). Isolation, checks and sorting are unchanged.
- `registry.go`: `Default` removed (PR 3).
- `scannertest`: a counting fake reader, exported as `scannertest.NewReader(content) *Reader` with `Calls()`, used by `AssertNoMutation` and by scanner tests (FR22) to count reads.

### 3.3 `internal/cli`

- `scan.go`: `openArtifact` returns `(a, f, fi, code)`; `runScan` defers `f.Close()` and calls `checkUnchanged(f, fi, size)` after `Run`.
- `filestate_darwin.go`, `filestate_linux.go`: `ctimeNS(fi fs.FileInfo) (int64, bool)` from `syscall.Stat_t`. `filestate_other.go` returns `false`, which `checkUnchanged` treats as changed (fail closed; `safefs.OpenRegular` already refuses those platforms).
- Seam `afterRun func()` (tests replace it to modify the file between `Run` and the checks; production never changes it), like `afterLstat` in `safefs`.

### 3.4 `internal/scanner/builtin`

- `read.go`: `readFull`, `errTruncated`.
- `hash.go`: `Hash struct{}`; one 64 KiB buffer per `Scan`.
- `filetype.go`: `FileType struct{}`, `detect(r, size) (string, error)`, finding builders.
- `claims.go`: the claim table (unexported `map[string]string`) and the compatibility function.
- `name.go`: `extension(name) (ext string, known, present bool)`; `doubleExtension` and `hasDeceptiveRune` in PR 5.
- `builtin.go`: `Default()` and the declared constant-text sets used by the FR29 tests.

### 3.5 `internal/textsafe`

One file holding `IsDangerous` and its doc comment, plus the rune-class tests moved from `report/escape_test.go`. Imports `strconv` and `unicode`.

## 4. Data/API changes and migrations

- The `scanner.Scanner.Scan` and `Registry.Run` signatures change (internal API, no external consumers). `scanner.Default` moves to `builtin.Default`.
- `artifact.Artifact` gains `Mode fs.FileMode`. Its zero value (no permission bits) reads as "executable bit not set".
- `scanner.MaxContentSize` changes from 10 MiB to 1 GiB; `scanner.ReasonChanged` is new.
- Report JSON stays `schema_version` 1: new findings and a new failure reason are data, not schema.
- No persisted data, no migration.

## 5. Engineering decisions and rationale

| # | Decision | Rationale | Alternatives | ADR |
| --- | --- | --- | --- | --- |
| D1 | `io.ReaderAt` plus `size`, wrapped by `Run` in an opaque bounded type (Q1 = A, R1). | Meets "hash large files without full read"; it is the migration ADR 0004 planned; the wrapper stops scanners reaching the `*os.File` (`SectionReader.Outer()` would expose it). | Caller hashes while reading (special case for over-cap files); keep `[]byte` (fails the AC). | 0007 |
| D2 | `MaxContentSize` 1 GiB, Assumed (Q4 = A). | Measured with `BenchmarkHash` on an idle machine: 950-1003 MB/s on darwin/arm64 (about 1.1 s per GiB) and 3.15-3.26 GB/s on linux/arm64 (about 0.33 s per GiB); ADR 0007 records the command and hardware. A CI-runner figure is pending. Easy to raise later. | 4 GiB; no cap; keep 10 MiB. | 0007 |
| D3 | `Artifact.Mode`: permission bits from `f.Stat()` on the scanned fd (Q2 = A, R5). | Typed, from the same fd as the bytes; ingest can fill it later. | Metadata key; extra `Scan` argument. | 0007 |
| D4 | Change detection in the CLI by re-fstat (size, mtime ns, ctime ns) and a 1-byte probe at `size` (R2). | Live reads lose the old single-snapshot property. This catches appends, truncation, most rewrites and procfs files, and fails closed. | No detection (silent wrong hash); hash-while-copy to a private snapshot (doubles I/O and needs temp storage). | 0007 |
| D5 | The hash is an info finding `hash.sha256` (Q3 = A). | No Result or schema change; escaped and checked like every finding. | `Result` field and schema v2; filling `Artifact.SHA256`. | - |
| D6 | Fixed claim table; an unknown extension on native executables is a mismatch; no extension is allowed for ELF/Mach-O/script (Q5 = B, R6). | Deterministic; no untrusted text in Metadata; targets the spoofing case. | Known extensions only; the `mime` package (host-dependent). | - |
| D7 | Finding set and severities per FR26 (Q6 = A), plus `deceptive_name` (R7, user decision). | Matches the story; policy re-weights later. | Mismatch-only output. | - |
| D8 | Scanners live in `internal/scanner/builtin`, which owns `Default()`. | `scanner` stays scanner-agnostic; no import cycle; a separate allowlist for `crypto/sha256` and `encoding/binary`. | Scanners inside `scanner` (widens its allowlist); `Default` in `cli`. | - |
| D9 | `IsDangerous` moves to `internal/textsafe` (R7). | One rule for report escaping and deceptive-name detection; `builtin` must not import `report`. | Copy the function (two rules drift). | - |
| D10 | Magic bytes at offset 0 only; no stdlib `debug/*` or `archive/*` parsers. | Smallest attack surface on untrusted bytes; parsers belong to a later BinaryMetadataScanner/ArchiveScanner. | `debug/elf`, `debug/pe`, `debug/macho` (large parsers on hostile input). | - |
| D11 | No `MaxInMemoryRead` helper in this story (Q7). | No caller needs it; speculative. | Add it now. | - |

D1-D4 have long-term impact and go into ADR 0007, which supersedes ADR 0004 decisions 1-3 (the `[]byte` contract, the planned migration, the 10 MiB over-cap rule) and records the opaque wrapper. ADR 0004 decisions 4-7 stand.

**Verified and Assumed third-party facts.**

- ELF magic `"\177ELF"`: Verified with `go doc debug/elf ELFMAG` (go1.27.2).
- Mach-O `Magic32 0xfeedface`, `Magic64 0xfeedfacf`, `MagicFat 0xcafebabe`: Verified with `go doc debug/macho` (go1.27.2). The byte-swapped thin forms `CE FA ED FE` / `CF FA ED FE` and fat64 `CA FE BA BF` are Assumed (Apple `<mach-o/loader.h>` and `<mach-o/fat.h>`; `debug/macho` does not define fat64). The `nfat < 45` rule that separates fat Mach-O from Java class files is Assumed (class major version 45 is JDK 1.1).
- gzip `1F 8B` with CM 8: Verified in `compress/gzip/gunzip.go` (`gzipID1`, `gzipID2`, `gzipDeflate`, go1.27.2).
- ZIP signatures `0x04034b50`, `0x06054b50`, `0x08074b50`: Verified in `archive/zip/struct.go` (go1.27.2).
- PE `e_lfanew` as a little-endian uint32 at `0x3C`, followed by `"PE\0\0"`: Verified in `debug/pe/file.go`, which reads `binary.LittleEndian.Uint32(dosheader[0x3c:])` (go1.27.2).
- `syscall.Stat_t` ctime fields: `Ctimespec` on darwin (Verified, `go doc syscall.Stat_t` on darwin/arm64) and `Ctim` on linux (Verified, `syscall/ztypes_linux_amd64.go`).
- `(*os.File)(nil).ReadAt` returns `os.ErrInvalid` without panicking: Assumed; FR5 tests it.
- SHA-256 throughput: Verified by `BenchmarkHash` (`go test -run xxx -bench Hash -count 10 ./internal/scanner/builtin/`) on an idle machine, Go 1.27.2: 950-1003 MB/s on darwin/arm64 (Apple M5 Pro) and 3.15-3.26 GB/s on linux/arm64 in a `golang:1.27` container (ADR 0007). A CI-runner figure is still pending.

## 6. Risks and failure modes

| Risk / failure | Handling |
| --- | --- |
| File rewritten in place with the same size, mtime and ctime | Undetectable without a snapshot. Accepted residual risk (threat model). Best effort: an unprivileged writer can also evade the check within the filesystem timestamp granularity (coarse clocks, HFS+ 1 s, FAT/exFAT, some NFS/FUSE) or through a shared writable mmap; only a private snapshot closes it. |
| Scanners see different bytes if the file changes mid-scan | FR11/FR12 mark the scan incomplete for any detected change. |
| Truncation during the scan | `readFull` returns `errTruncated`; `Run` records `error`; FR11 also records `changed`. |
| procfs/sysfs files with fstat size 0 but content | The FR12 probe gives `changed`; incomplete. |
| Network/FUSE filesystem blocks in `ReadAt` | Accepted: no per-scanner timeout and no SIGINT handling (REDACT-39). Documented. |
| A 1 GiB file takes seconds | Bounded by the cap; the benchmark figure is recorded. |
| The exec bit is not the same as "executable" (ACLs, `noexec` mounts, FAT/SMB reporting 0777, no bit on Windows) | Wording "executable bit set"; caveats documented; low severity. |
| Offset-0 magic misses polyglots and appended ZIPs; `MZ` without PE is `unknown` | Documented residual risk; ArchiveScanner/BinaryMetadataScanner later. |
| A secret-shaped path drops every finding | Fail closed: incomplete with `invalid finding` (FR32). Documented. |
| A fat Mach-O with 45 or more architectures is detected as `unknown` | Accepted; no real binary has that many. |
| Typed-nil or misbehaving reader | FR4/FR5: no panic, fixed errors, incomplete. |
| Invalid-finding floods (threat-model item deferred "to REDACT-37 or REDACT-39") | Not changed by these scanners (at most 5 findings per artifact). The threat-model entry is updated to defer it to REDACT-39 only. |
| `filetype.detected` with `unknown` and no exec bit stays info | Its Description must not imply safety (FR26). |

**Follow-ups (documented, not built):** a `MaxInMemoryRead`-style helper for ScriptScanner/SourceScanner; a per-scan deadline and aggregate byte budget (REDACT-39); SIGINT cancellation; ingest filling `Artifact.Mode` for directory scans (REDACT-39); polyglot and appended-archive detection.

## 7. Security

- **Untrusted content.** Bytes are read only through the bounded wrapper. No parsing beyond fixed-offset magic checks, each length-checked first. All offsets are `int64`. Detection is fuzzed (FR22).
- **Path and fd handling.** The file is opened once through `safefs.OpenRegular`. Scanners never see the `*os.File` (FR4), never open anything, and the `builtin` allowlist forbids `os`, `syscall` and `internal/safefs`. Mode and size come only from `f.Stat()` on that fd.
- **Fail closed.** Every read error, short read, change during the scan, over-cap file, invalid finding and cancellation makes the result incomplete (exit 1).
- **No secret or path leakage.** Errors are fixed text; `readFull` and `boundedReader` never return OS errors (which carry paths). Metadata holds only constants, bools, the hex digest and the size, never name bytes (FR24, FR28). The report escapes `File`. A lowercase 64-hex digest matches no redactor pattern (checked against `internal/redactor/detect.go`).
- **Hash semantics.** The digest describes the bytes read during this scan; quarantine and policy must re-hash their own copy (FR13).
- **Deceptive names.** Bidi, invisible and control runes, invalid UTF-8, and document-before-executable double extensions are flagged (FR28), using the same rule as the report's escaping (FR27).
- **Threat model updates.** In the Scanner section: live-read TOCTOU and the D4 checks; remove the obsolete wording "reads at most `MaxContentSize+1` bytes"; the new 1 GiB cap; the residual risks from section 6; exec-bit caveats; secret-shaped path behaviour; the buffering-scanner rule (FR33).

## 8. Performance/scalability

- Memory per scan: one 64 KiB hash buffer, a 512-byte header and a 4-byte PE probe, independent of file size (FR17).
- Time: one sequential read of the file for the hash, up to two small reads for filetype, and one 1-byte probe. The worst case is about 1 GiB of SHA-256 (about 1.1 s on the measured darwin/arm64 host and about 0.33 s on linux/arm64; ADR 0007).
- Each artifact produces at most 5 findings, far below `MaxFindings`.
- Directory scans and worker pools belong to REDACT-39.

## 9. Implementation steps

Five stacked PRs on `feat/redact-37-hash-filetype`; each PR branches from the previous one. The story estimate was about 350 lines. The security requirements (R1-R10) and R7 roughly double that, so the work is split to keep every PR under about 500 changed lines including tests. R7 alone would push a combined filetype PR to about 650 lines, which is why deceptive names get their own PR 5. R2 is likewise split out of the contract PR (PR 2).

| PR | Contents | Estimate | Depends on |
| --- | --- | --- | --- |
| PR 1 | Scanner contract: ReaderAt, `boundedReader`, `Run` pre-checks, 1 GiB cap, `Artifact.Mode`, `scannertest` rework, fake-scanner migration, CLI `openArtifact` (fstat, no read), ADR 0007, ADR 0004 note, architecture s5/s7, artifact-finding-models spec. | about 450 | - |
| PR 2 | CLI change detection: `ReasonChanged`, re-fstat, 1-byte probe, per-OS ctime, `afterRun` seam, procfs test, threat model (TOCTOU, residual risks, hash semantics). | about 250 | PR 1 |
| PR 3 | `builtin` package: `readFull`, `Hash`, `Default()` (hash only), CLI wiring, removal of `scanner.Default`, allowlist test, large-file and allocation tests, benchmark. | about 300 | PR 2 |
| PR 4 | `FileType`: header read, detection, claim table, extension derivation, mismatch, exec bit, detected finding, fuzz test, constant-text tests; registered in `Default()`. | about 450 | PR 3 |
| PR 5 | `internal/textsafe` extraction (report unchanged), `filetype.deceptive_name` and its tests, threat model and architecture s9 notes. | about 200 | PR 4 |

### Steps

1. **PR 1, step 1: `Artifact.Mode`.** Add the field and doc comment (FR6); update the artifact tests. Expected: `task test` passes. Tests: zero value; field list matches the updated artifact-finding-models spec.
2. **PR 1, step 2: bounded reader.** `internal/scanner/bounded.go` (FR4). Tests: the FR4 table with fakes (negative offset, at/after size, clipping, an inner reader that over-reports, a hidden `*fs.PathError`) and the interface-assertion tests.
3. **PR 1, step 3: interface and `Run`.** Change `Scanner` and `Run` (FR1-FR3, FR5); update the package doc; add `io` to the allowlist and skip `builtin` (FR8). Migrate the `scanner_test.go` fakes. Tests: the FR2 table with zero `ReadAt` calls; typed-nil `*os.File`; every existing isolation test still passes.
4. **PR 1, step 4: `scannertest`.** Counting reader and reworked `AssertNoMutation` (FR7). Tests: self-tests for good and bad fakes.
5. **PR 1, step 5: CLI open.** `openArtifact` (FR9); keep the fd open across `Run`. Tests: Mode 0755; a sparse over-cap file gives `too large` with zero reads; existing CLI tests migrated. `scanner.Default` is still empty in this PR, so real scans still report `no scanner ran`.
6. **PR 1, step 6: docs.** ADR 0007, the ADR 0004 note, architecture s5 (Mode) and s7 (contract, cap), artifact-finding-models spec FR1. Run `task verify`.
7. **PR 2, step 7: change detection.** `ReasonChanged` (FR10), `checkUnchanged` with per-OS ctime (FR11), the probe (FR12), the `afterRun` seam. Tests: a rewrite, an append and a truncation through the seam each give exit 1 and `changed`; an untouched file has no `changed`; Linux-only `/proc/<pid>/status` is incomplete; a report golden for `changed`. Run `task cross`.
8. **PR 2, step 8: threat model.** Scanner section per section 7. Run `task verify`.
9. **PR 3, step 9: `readFull`.** FR14, with the fakes listed there.
10. **PR 3, step 10: `Hash`.** FR15-FR17. Tests: vectors, cancellation, `AssertNoMutation`, constant text (FR29), metadata types (FR30), the 512 MiB sparse file (skipped with `-short`), allocation independence, `BenchmarkHash`.
11. **PR 3, step 11: `Default()` and wiring.** FR18, FR19; remove `scanner.Default`; update CLI tests that expected `no scanner ran` from the real registry. Tests: a real scan is complete and shows `hash.sha256`; FR32 secret-shaped path (hash only at this point). Record the CI benchmark figure in ADR 0007. Run `task verify`.
12. **PR 4, step 12: detection.** `detect` (FR20, FR21). Tests: every FR21 fixture; the short-read error; at most 2 reads.
13. **PR 4, step 13: claims and extension.** `claims.go`, and `extension` in `name.go` (FR23-FR25). Tests: every table entry, the compatibility matrix, the name edge cases.
14. **PR 4, step 14: findings and registration.** FR26; add `FileType{}` to `Default()`. Tests: each variant through `Run`, FR29, FR30, FR32 extended to both scanners, `AssertNoMutation`, `FuzzDetect` (FR22). Run `task verify`.
15. **PR 5, step 15: `textsafe`.** FR27; `report` uses it; move the rune-class tests. Report goldens stay unchanged.
16. **PR 5, step 16: deceptive names.** FR28 in `name.go` and `filetype.go`. Tests: the FR28 cases, FR29 extended. Docs: threat model and architecture s9. Run `task verify`.

## 10. Testing strategy

- **Unit:** `boundedReader`, `readFull`, `detect`, extension derivation, the claim matrix and the deceptive-name rules, all table-driven with fakes.
- **Contract:** `scannertest.AssertNoMutation` with the counting reader for both scanners; import allowlists for `scanner` and `builtin`.
- **End to end through `Registry.Run`:** every finding variant, constant text, closed value sets and Metadata types (FR29-FR31).
- **CLI integration:** real temp files (0644 and 0755), a sparse large file, a sparse over-cap file, the change-during-scan seam, Linux procfs, a secret-shaped path.
- **Fuzz:** `FuzzDetect` with the fixture seeds.
- **Regression:** the existing scanner isolation, report golden and CLI tests keep passing after migration.
- **Performance:** `BenchmarkHash` and the allocation-independence test.
- **Failure paths:** short reads, read errors, cancellation, typed-nil reader, over-reporting reader, changed file.
- Tests build secret-shaped strings and hostile runes at runtime; no realistic secret values or literal bidi characters in fixtures or source.

## 11. Observability, deployment, rollback

- No logging (CLI tool; the scanner packages forbid `log`). Outcomes are visible only in the report: findings and failures with fixed reasons.
- Deployment ships with the binary. Visible behaviour changes: real scans of ordinary files become complete (exit 0); files up to 1 GiB are scanned instead of refused above 10 MiB; a file that changes during the scan is incomplete (`changed`).
- Rollback: revert the PRs in reverse order. There is no persisted state.

## 12. Definition of done

- Every FR met and tested. `task test` during development; `task cross` passes (386 included); `task verify` succeeds before each PR is marked ready.
- ADR 0007 written; the ADR 0004 note added; `docs/architecture.md` s5, s7 and s9 and the `docs/threat-model.md` Scanner section and residual risks updated; artifact-finding-models spec FR1 updated.
- `security-reviewer` runs on each PR diff (file handling, untrusted parsing), alongside `staff-engineering-reviewer`, per the AGENTS.md pipeline.
- PR descriptions follow `.github/pull_request_template.md`, including manual steps: `chmod +x` a renamed ELF and scan it; scan a `report.pdf.exe`; append to a file during a scan (or scan `/proc/<pid>/status` of a running process on Linux (`/proc/self` is a symlink and is refused)); scan a sparse file over 1 GiB and see `too large`.
- No new dependencies.
