# Quarantine store: spec

Story: REDACT-56 "Quarantine store: layout, metadata and permissions".
Status: approved design (user, 2026-10-27), security-reviewer findings incorporated.
Depends on: REDACT-35 (artifact/finding models), REDACT-10 (safefs).
Consumers: REDACT-57 (list/inspect), REDACT-58 (release/delete), REDACT-59/60 (watcher routing), REDACT-49 (policy).
Visual plan: `plans/quarantine-store/plan.mdx`.
ADR: 0005 (draft notes in section 5.1; written in PR 1).

Claims about Go, OS or library behaviour are labelled **Verified** (with how) or **Assumed**.

## 1. Feature overview

### Purpose

Suspicious content (scan decision `review` or `block`) must be kept somewhere inert: not executable, not readable by other local users, never mistaken for a complete entry when it is only half written, and described by metadata that later commands can trust only after strict validation.

### Scope

New package `internal/quarantine` (darwin and linux; other platforms return `ErrUnsupportedPlatform`):

- `Open`: create or verify `<base>/{incoming,quarantine,scans}` at 0700 (default base `~/.redactscan`), repairing loose modes on directories it owns and refusing symlinks, foreign owners and euid 0.
- `Put`: copy one file opened through `safefs.OpenRegular` into a new content-addressed entry with metadata JSON (hash, size, source, name, findings, decision, created time).
- `Read`: strict, fail-closed metadata read for one ID.
- `Verify`: re-hash stored content against the metadata (used by REDACT-58 before release).
- `ValidID`: the ID grammar, checked before any filesystem call.
- One new safefs primitive, `safefs.OpenRegularIn(root, name)`.
- One exported redactor helper, `redactor.IsClean(s)`, moved out of `internal/scanner`.

### Non-goals (deferred)

- CLI commands (`quarantine list/inspect/release/delete`): REDACT-57/58.
- Listing entries, release, delete, cleanup of incomplete entries and orphan `.tmp-*` files: REDACT-58 plus a follow-up issue for orphan temp files (file it with PR 3).
- Watcher routing and anything inside `incoming/` or `scans/` beyond creating the directories: REDACT-59/60.
- A shared `internal/policy.Decision`: REDACT-49 (section 5, D5).
- Encryption at rest, retention policy, Time Machine exclusion (accepted risks, section 6).
- Cross-process locking of the store budget (accepted risk, section 6).
- Windows support.
- Updating the architecture doc's `~/.sentinel` naming outside section 12.

## 2. Functional requirements and acceptance criteria

| # | Requirement | Acceptance (test) |
|---|---|---|
| FR1 | `Open` creates missing `base`, `incoming`, `quarantine`, `scans` with mode exactly 0700 regardless of umask. | Fresh temp base with umask 022 and 077: all four are 0700, owned by euid. |
| FR2 | `Open` validates `base` before any I/O: non-empty, no NUL, absolute, equal to `filepath.Clean(base)`, not `/`; the parent must already exist (no `MkdirAll`). Default base is `os.UserHomeDir() + "/.redactscan"`; an empty/relative `HOME` is `ErrInvalidBase`. | Table test: `""`, `"rel"`, `"/a/../b"`, `"/"`, `"/x\x00"`, missing parent: `ErrInvalidBase`, nothing created. |
| FR3 | `Open` refuses a symlink at `base` or any of the three subdirectories (`ErrUnsafeDir`). Symlinks above `base` (in its parent path) are allowed. | Symlinked base, symlinked `quarantine`: refused, link target untouched. Base under a symlinked parent: opens. |
| FR4 | `Open` refuses a store directory not owned by euid (`ErrUnsafeDir`). | Linux container test with a directory chowned to another uid (skip when not root-capable); seam test for the uid comparison. |
| FR5 | `Open` repairs a store directory owned by euid whose mode is not exactly 0700 (any group/other bit, setuid, setgid or sticky) by `fchmod(0700)` on the pinned descriptor and reports it via `Store.Repaired()`. | Pre-created at 0755, 0750, 01700, 02700: after `Open` each is 0700 and `Repaired()` names it; already-0700 store reports nothing. |
| FR6 | `Open` refuses to run as euid 0 (`ErrRunningAsRoot`) unless `Options.AllowRoot` is true. | Seam on `geteuid`: 0 without opt-in is refused before any I/O; with opt-in proceeds. |
| FR7 | On darwin `Open` creates an empty 0600 `<base>/.metadata_never_index` if missing (best effort; failure does not fail `Open`). | darwin-only test: file exists, 0600. |
| FR8 | `ValidID(id)` is true only for `^[0-9a-f]{64}-[0-9a-f]{16}$`. Every ID-taking function checks it first and returns `ErrInvalidID` with no filesystem call. | Table: `../x`, `/abs`, `a/b`, uppercase hex, 63/65 hex, missing suffix, NUL, `.`, `..`, trailing newline, valid ID. A test seam counts filesystem calls: zero for invalid IDs. |
| FR9 | `Put` validates all input before any I/O (section 3.5). Failures return `ErrInvalidInput` or `ErrSensitiveInput`; nothing is created. | Table tests per rule; directory listing unchanged after each. |
| FR10 | `Put` refuses Name or URI containing anything the redactor flags (`ErrSensitiveInput`), Name over 4096 bytes, URI over 8192 bytes, a URI with userinfo (including opaque forms), query, fragment, a scheme other than https/http/file, or that does not parse (`ErrInvalidInput`). | Name `AKIA...` style key, URI `https://user:pw@host/x`, `?token=`, `#frag`: refused; nothing written. |
| FR11 | `Put` marshals the final metadata (fixed-width placeholders for ID, hash, time) before creating anything; over `MaxMetadataBytes` gives `ErrMetadataTooLarge`. `Put` and `Read` share `MaxMetadataBytes`. | 1000 max-size findings plus an escape-heavy name (control characters, `"`, `\`, bidi) either round-trips exactly or is refused with `ErrMetadataTooLarge` and the store directory is unchanged. |
| FR12 | `Put` refuses a source that is not a regular file, larger than `Options.MaxEntrySize` by fstat (`ErrTooLarge`), whose bytes read differ from its fstat size (`ErrSourceChanged`), or that would exceed the store budget (`ErrStoreFull`). On `ErrTooLarge`(by fstat), `ErrStoreFull` and validation errors nothing is created; on `ErrSourceChanged` the temp file is removed. | Grow/shrink the source between fstat and read via a reader seam; over-limit by one byte; budget full by bytes and by entry count. |
| FR13 | Stored `content` is a new 0600 file owned by euid, never the source's mode: execute, setuid, setgid and sticky bits never reach the store. | Source with 0755 and 04755 (where settable): stored content is 0600. |
| FR14 | Same content stored twice gives two distinct entries with the same hash prefix. ID suffix collisions retry up to 10 times then `ErrIDExhausted`. | Seam forcing the random suffix: first collides, second succeeds; all 10 collide: `ErrIDExhausted`, no stray files. |
| FR15 | Entry publication is atomic per FR16: `content` is placed with a no-replace `Root.Link`, then `metadata.json` with a no-replace `Root.Link`; an existing target is never replaced (`ErrEntryExists`). | Pre-planted `id/content` (via suffix seam) is refused and left byte-for-byte unchanged; same for `metadata.json`. Run on darwin and Linux. |
| FR16 | An entry is complete only if `metadata.json` exists. `Read` returns `ErrIncomplete` for an entry dir without it, and for `content` that is missing, not regular, not euid-owned, not exactly 0600, or whose size differs from `metadata.size`. | Entry dir with content only; content removed; content 0644; content truncated by one byte: `ErrIncomplete`. |
| FR17 | `Read` refuses (never repairs) an entry dir that is a symlink, not a directory, not euid-owned, or not exactly 0700 including setuid/setgid/sticky (`ErrUnsafeDir`). | Entry at 0750, 01700, 02700, symlink to a real entry: `ErrUnsafeDir`, mode unchanged. |
| FR18 | `Read` accepts metadata only if all hold, else `ErrCorruptMetadata` and a zero `Metadata`: regular file opened via `safefs.OpenRegularIn`, euid-owned, exactly 0600, at most `MaxMetadataBytes`, valid strict JSON (no unknown, duplicate or case-variant members, no trailing data), `schema_version == 1`, decision `review` or `block`, every field within the bounds of section 3.5, `id` equal to the directory name, `sha256` equal to the ID prefix, `created_at` in the exact stored format. | Table of corruptions: truncated, trailing `{}`, unknown field, duplicate `decision`, `"Decision"`, version 2, `allow`, oversize title, invalid severity name, id mismatch, sha mismatch, 0644 file, symlink, FIFO, over-cap file. |
| FR19 | Metadata round-trips exactly: `Read(Put(x))` equals the normalized input, including finding metadata value types (`string`, `bool`, `int`, `int64`, `float64`) and integers above 2^53. | Round-trip test with every type, `math.MaxInt64`, `-0.0`-free floats, empty findings, 1000 findings. |
| FR20 | `Verify(id)` opens `content` through `safefs.OpenRegularIn`, requires euid owner and exactly 0600, fstat size equal to `metadata.size`, reads through `io.LimitReader(f, size+1)`, and compares the count and SHA-256 with metadata and the ID prefix. Any mismatch is `ErrVerifyFailed`. | Flip one byte, append one byte, swap content for a symlink/FIFO/other file between Lstat and open (mirroring `TestOpenChildDirDetectsSwap`): all fail. Untouched entry passes. |
| FR21 | No error text contains a path, base, ID, name, URI, finding text or OS error text; OS errors unwrap to a bare `syscall.Errno`. | Marker-name test (as `assertSafeErrorText` in safefs) over every `Open`, `Put`, `Read` and `Verify` failure path. |

## 3. Technical design

### 3.1 Layout on disk

```
<base>/                         0700  default ~/.redactscan
  .metadata_never_index         0600  darwin only, best effort
  incoming/                     0700  created only (REDACT-59/60)
  scans/                        0700  created only
  quarantine/                   0700
    .tmp-<16 hex>               0600  in-flight content; never an entry
    <sha256 hex>-<16 hex>/      0700  one directory per quarantine event
      content                   0600  exact bytes of the source
      metadata.json             0600  present => entry complete
      .meta-<16 hex>.tmp        0600  transient
```

The ID grammar `^[0-9a-f]{64}-[0-9a-f]{16}$` cannot express `.`, `..`, `/` or NUL, and neither temp pattern matches it, so no reader can confuse a temp file with an entry.

### 3.2 API

```go
package quarantine // //go:build darwin || linux; other.go returns ErrUnsupportedPlatform

const (
    SchemaVersion        = 1
    MaxMetadataBytes     = 4 << 20   // Assumed placeholder; shared by Put and Read
    DefaultMaxEntrySize  = 256 << 20 // Assumed placeholder (section 5, D1)
    DefaultMaxStoreBytes = 4 << 30   // Assumed placeholder
    DefaultMaxEntries    = 1000      // Assumed placeholder
    MaxNameBytes         = 4096
    MaxURIBytes          = 8192
    MaxCategoryBytes     = 64
    MaxDescriptionBytes  = 1024
)

type Decision string
const (
    Review Decision = "review"
    Block  Decision = "block"
)

type Options struct {
    MaxEntrySize  int64 // 0 => default; negative => ErrInvalidOptions
    MaxStoreBytes int64 // 0 => default
    MaxEntries    int   // 0 => default
    AllowRoot     bool  // permit euid 0 (explicit opt-in)
}

type Input struct {
    Source   artifact.SourceMetadata // Type must be an artifact.Source* constant
    Name     string                  // untrusted, display only
    Decision Decision
    Findings []finding.Finding
}

type Metadata struct {
    SchemaVersion int
    ID, SHA256    string
    Size          int64
    CreatedAt     time.Time // UTC, second precision
    Source        artifact.SourceMetadata
    Name          string
    Decision      Decision
    Findings      []finding.Finding
}

func Open(base string, opts Options) (*Store, error) // base "" => UserHomeDir()/.redactscan
func (s *Store) Close() error
func (s *Store) Repaired() []string          // fixed names: "base", "incoming", "quarantine", "scans"
func (s *Store) Put(src *os.File, in Input) (id string, err error)
func (s *Store) Read(id string) (Metadata, error)
func (s *Store) Verify(id string) error
func ValidID(id string) bool

var (
    ErrUnsupportedPlatform, ErrInvalidBase, ErrInvalidOptions, ErrRunningAsRoot,
    ErrUnsafeDir, ErrInvalidID, ErrNotFound, ErrIncomplete, ErrCorruptMetadata,
    ErrMetadataTooLarge, ErrInvalidInput, ErrSensitiveInput, ErrTooLarge,
    ErrStoreFull, ErrSourceChanged, ErrIDExhausted, ErrEntryExists, ErrVerifyFailed error
)
```

A `Store` holds the pinned `os.Root` for `quarantine/` (and closes the base and sibling roots after `Open`). It is safe for sequential use; concurrent `Put` from one process is allowed (all names are exclusive) but the budget check is not serialized (section 6).

Package doc must state: Name, URI and finding strings in `Metadata` are untrusted; output code escapes them; never format `Metadata` with `%v`/slog/JSON into errors or logs (log the ID only); content bytes are never returned by `Read`.

### 3.3 `Open`

1. `geteuid()` (test seam) is 0 and `!opts.AllowRoot`: `ErrRunningAsRoot`. Validate options and base (FR2) before any I/O.
2. `parent, name := filepath.Split(base)`; `os.OpenRoot(parent)` (path resolution follows symlinks: allowed above base, decision D4). Missing parent: `ErrInvalidBase`.
3. For `base` in the parent root, then `incoming`, `quarantine`, `scans` in the base root, `ensureDir(root, name)`:
   - `root.Mkdir(name, 0o700)`; `EEXIST` is fine.
   - `root.Lstat(name)`: symlink or not a directory: `ErrUnsafeDir`.
   - `safefs.OpenChildDir(root, name, fi)` (no-follow, `O_DIRECTORY|O_NONBLOCK`, `SameFile`).
   - `fstat`: `Stat_t.Uid != euid`: `ErrUnsafeDir`.
   - If `mode & (ModePerm|ModeSetuid|ModeSetgid|ModeSticky) != 0o700`: `f.Chmod(0o700)` on the descriptor (never by path); record the fixed name in `Repaired`; re-`fstat` and require 0700 (fail closed if the filesystem ignores chmod).
4. darwin: create `.metadata_never_index` in the base root with `O_CREATE|O_EXCL`, fchmod 0600; ignore `EEXIST` and other errors.
5. Keep the `quarantine` root and its `*os.File` (for directory fsync and listing).

### 3.4 `Put`

Order is security-relevant. Nothing touches the filesystem until step 4.

1. `validateInput(in)` (section 3.5). Finding metadata values keep their Go type (the typed encoding in section 3.6 preserves it).
2. `src.Stat()`: not regular: `ErrInvalidInput`; `Size() > MaxEntrySize`: `ErrTooLarge`.
3. Build `Metadata` with placeholder `ID` (81 `0`/`-` chars), `SHA256` (64 `0`), real `Size`, `CreatedAt = now().UTC().Truncate(time.Second)`; marshal. Length > `MaxMetadataBytes`: `ErrMetadataTooLarge`. The real marshal later has identical length because ID, hash and time are fixed-width.
4. Budget: list `quarantine/` names in batches (`Readdirnames(256)`), stopping once more than `MaxEntries` entry names are seen; for each valid-ID name `Lstat(id + "/content")` and add its size (missing: 0); for each `.tmp-*` name add its `Lstat` size. If entries `>= MaxEntries` or `used + Size > MaxStoreBytes`: `ErrStoreFull`. Unknown names are ignored. Nothing has been created.
5. Copy: create `.tmp-<rand16>` in the quarantine root with `O_WRONLY|O_CREATE|O_EXCL` (10 tries, then `ErrIDExhausted`), `fchmod(0o600)`, `io.Copy` from `io.LimitReader(src, Size+1)` into `io.MultiWriter(tmp, sha256)`. Count `!= Size`: `ErrSourceChanged`. `fsync`, `close`. Any error: remove the temp file.
6. Reserve: `id = hex(sum) + "-" + rand16()`; `Mkdir(id, 0o700)`; `EEXIST`: new suffix (10 tries, then `ErrIDExhausted`). `OpenChildDir`, `fchmod(0o700)`, fsync the quarantine directory.
7. Place content: `qroot.Link(tmp, id+"/content")` (no-replace; `EEXIST`: `ErrEntryExists`), remove the temp name, fsync the entry directory.
8. Publish: marshal the real metadata; in the entry root create `.meta-<rand16>.tmp` `O_EXCL`, `fchmod(0o600)`, write, fsync, close; `entryRoot.Link(tmp, "metadata.json")` (no-replace; `EEXIST`: `ErrEntryExists`); remove the temp name; fsync the entry directory.
9. On failure after step 6: best-effort removal of what this call created (meta temp, `content`, the entry directory, the content temp), never anything else. If removal fails the entry stays incomplete and `Read` reports `ErrIncomplete`.

Random suffixes come from `crypto/rand` through a test seam (as `safefs.tempName`).

### 3.5 Validation rules (shared by Put and Read)

One function `validateRecord(m Metadata) error` used by both sides, plus Put-only checks.

| Field | Rule |
|---|---|
| `Decision` | `review` or `block` only. |
| `Source.Type` | one of `artifact.SourceFile/Directory/Archive/Git/Download`. |
| `Source.URI` | empty, or at most `MaxURIBytes`, valid UTF-8, no `?` or `#` anywhere, `url.Parse` succeeds, `User == nil`, empty `Opaque` (`url.Parse` fills `User` only after `//`, so opaque forms like `https:user:pw@host` must be refused), scheme `https`, `http` or `file`, and a non-empty `Host` for `http(s)`. Put-only: `redactor.IsClean`. |
| `Name` | at most `MaxNameBytes`, valid UTF-8. Put-only: `redactor.IsClean`. |
| `Findings` | at most `scanner.MaxFindings`. |
| each finding | `finding.Validate()` (severity, evidence, metadata); `ID` 1..`scanner.MaxIDBytes`; `Title` <= `scanner.MaxTitleBytes`; `File` <= `scanner.MaxFileBytes`; `Category` <= `MaxCategoryBytes`; `Description` <= `MaxDescriptionBytes`; `ArtifactID` <= `scanner.MaxIDBytes`; all valid UTF-8; `Line >= 0`. |
| Read-only | `SchemaVersion == 1`; `ValidID(ID)`; `ID` equals directory name; `SHA256` equals `ID[:64]`; `size` present and `>= 0`; `CreatedAt` parsed from exactly `2006-01-02T15:04:05Z`. |

`redactor.IsClean(s string) bool` is the current `scanner.redactorClean` moved and exported (redactor accepts the input and reports nothing except `KindLabelLike`); the scanner calls it. Put-only checks are not re-run on Read: a stored value was clean when written, and Read must not depend on redactor rule changes (re-checking would make old entries unreadable after a rule update).

Findings from callers are expected to come from `scanner.Registry.Run`, which already redactor-checks ID, Title, File and Evidence. Quarantine does not re-run that check (caller constraint, section 7).

### 3.6 Metadata JSON v1

Encoded and decoded with `encoding/json/v2` (standard library). **Verified** on macOS (go1.27.1) and Linux (`golang:1.27`, go1.27.3) with a scratch probe: v2 `Unmarshal` with `json.RejectUnknownMembers(true)` rejects duplicate members, rejects a case-variant member name (`"A"` for `json:"a"`), and rejects trailing data, while v1 `encoding/json` silently accepts all three (duplicate: last wins; case-insensitive match). v2 is used for both marshal and unmarshal.

```json
{
  "schema_version": 1,
  "id": "<64 hex>-<16 hex>",
  "sha256": "<64 hex>",
  "size": 1234,
  "created_at": "2026-10-27T10:00:00Z",
  "source": {"type": "download", "uri": "https://example.com/tool.zip"},
  "name": "tool.zip",
  "decision": "block",
  "findings": [{
    "id": "script-curl-pipe-sh", "severity": "high", "category": "script",
    "title": "...", "description": "...", "artifact_id": "a-1",
    "file": "install.sh", "line": 12, "evidence": "...",
    "metadata": [{"key": "count", "type": "int", "value": 3}]
  }]
}
```

- Private DTO structs with explicit `json` tags; `Metadata`/`finding.Finding` are converted, never marshalled directly.
- Severity is stored as `Severity.String()` and decoded by exact match on the five names (not `finding.ParseSeverity`, which is for trusted config only); anything else is `ErrCorruptMetadata`.
- Finding metadata is a list of `{key, type, value}` sorted by key, `type` one of `string|bool|int|int64|float64`; the value is decoded into exactly that Go type (no float64 detour, so integers above 2^53 round-trip). Duplicate keys or an unknown type are corrupt. The rebuilt map is then checked by `artifact.ValidateMetadata`.
- `findings` is always an array (empty, not null) on write; null or absent is corrupt.

### 3.7 `Read`

1. `ValidID(id)` else `ErrInvalidID` (no I/O).
2. `qroot.Lstat(id)`: not found: `ErrNotFound`; symlink or not a directory: `ErrUnsafeDir`. `safefs.OpenChildDir`; `fstat`: not euid or mode not exactly 0700 (including special bits): `ErrUnsafeDir`. No repair.
3. `safefs.OpenRegularIn(entryRoot, "metadata.json")`: not found: `ErrIncomplete`; symlink, not regular, changed: `ErrCorruptMetadata`. `fstat`: not euid, mode not exactly 0600, or size > `MaxMetadataBytes`: `ErrCorruptMetadata`.
4. Read through `io.LimitReader(f, MaxMetadataBytes+1)`; over cap: `ErrCorruptMetadata`. Strict decode and `validateRecord` (section 3.5).
5. `entryRoot.Lstat("content")`: missing, not regular, not euid, mode not exactly 0600, or `Size() != metadata.Size`: `ErrIncomplete`.
6. Return the `Metadata`. Content is never re-hashed here.

### 3.8 `Verify`

Steps 1-4 of `Read`, then `safefs.OpenRegularIn(entryRoot, "content")`, `fstat` owner/mode/size checks, hash `io.LimitReader(f, Size+1)`; count must equal `Size` and `hex(sum)` must equal `metadata.SHA256` (and therefore the ID prefix). Any failure after the metadata is accepted is `ErrVerifyFailed`. The hashing is in an unexported `verifyContent(f *os.File, m Metadata) error` so REDACT-58 can verify and copy from the same descriptor.

### 3.9 `safefs.OpenRegularIn(root *os.Root, name string) (*os.File, error)`

Single component only (`ErrInvalidName` for `""`, `.`, `..`, `/`, NUL). `root.Lstat(name)`: symlink: `ErrSymlink`; not regular: `*NotRegularError`. `root.OpenFile(name, O_RDONLY|O_NONBLOCK|O_NOCTTY, 0)`; `fstat`; `os.SameFile` with the Lstat result else `ErrChanged`; regular else `*NotRegularError`; `Stat_t.Uid == euid` else `ErrNotOwned` (new sentinel); restore blocking mode (`setBlocking`). Errors via `newOpError`. It needs the `SameFile` check because `Root.OpenFile` follows an in-root symlink on the final component and ignores `O_NOFOLLOW` (ADR 0004, Verified there). `dir_other.go`/`open_other.go` stub returns `ErrUnsupportedPlatform`.

### 3.10 Files

| File | PR | Change |
|---|---|---|
| `internal/safefs/openin_unix.go`, `openin_other.go`, `openin_test.go` | 1 | `OpenRegularIn`, `ErrNotOwned`, swap tests. |
| `internal/quarantine/quarantine.go` | 1 | Package doc, constants, errors, `Options`, `Decision`, `ValidID`. |
| `internal/quarantine/store_unix.go`, `store_other.go` | 1 | `Store`, `Open`, `ensureDir`, `Repaired`, `Close`, seams (`geteuid`, `randSuffix`, `now`). |
| `internal/quarantine/store_test.go`, `id_test.go` | 1 | FR1-FR8. |
| `internal/redactor/clean.go`, `internal/scanner/check.go` | 2 | `IsClean` moved and exported; scanner uses it. |
| `internal/quarantine/metadata.go`, `validate.go`, `metadata_test.go` | 2 | DTOs, encode, strict decode, `validateRecord`, Put-only input checks. FR9-FR11, FR18-FR19 (pure, no I/O). |
| `internal/quarantine/put_unix.go`, `put_test.go` | 3 | `Put`, budget, copy, reserve, link, publish. FR12-FR15. |
| `internal/quarantine/read_unix.go`, `read_test.go` | 4 | `Read`, `Verify`, `verifyContent`. FR16-FR21. |
| `docs/adr/0006-quarantine-store.md` | 1 | ADR (section 5.1). |
| `docs/architecture.md` | 1 | Section 12: `~/.redactscan`, layout tree, link to spec/ADR. |
| `docs/threat-model.md` | 4 | New "Quarantine store" section (section 7). |

## 4. Data/API changes and migrations

- New on-disk format: `metadata.json` schema version 1 and the layout of section 3.1. It is a long-lived contract for REDACT-57..60 (ADR 0006). A future version bump must be readable by a new decoder; v1 readers refuse other versions (fail closed).
- New exported API: `internal/quarantine` (section 3.2), `safefs.OpenRegularIn`, `safefs.ErrNotOwned`, `redactor.IsClean`.
- No migration: no store exists yet. `incoming/` and `scans/` are created empty.

## 5. Engineering decisions and rationale

| # | Decision (user-decided unless noted) | Rationale |
|---|---|---|
| D1 | One directory per quarantine event, ID = `<sha256>-<16 hex>`. | Content-addressed name plus collision safety; each entry self-contained so list/inspect/release/delete touch one directory; strict regex makes traversal impossible by construction. Cost: identical bytes stored twice. |
| D2 | Content streamed from a `safefs.OpenRegular` file, hashed while copying, configurable `MaxEntrySize`; `ErrSourceChanged` if bytes read differ from fstat size. | One code path for every caller; recorded hash always matches stored bytes; source mode never copied. Default lowered to 256 MiB (**Assumed** placeholder: covers typical source archives and CLI tool downloads while bounding copy time and disk use; not measured). |
| D3 | Repair store directories owned by euid to exactly 0700; refuse symlinks and foreign owners; entry directories are checked and refused, never repaired. `Repaired()` lets the CLI warn. | Loose mode on our own directory is usually umask; tightening only reduces exposure. An entry directory with a wrong mode was not made by `Put` and is a tamper or corruption signal. |
| D4 | Base = `os.UserHomeDir()/.redactscan` or explicit argument; no env override; no-symlink rule from base down; base validated before I/O; no `MkdirAll`. | Works with symlinked home paths (for example `/home -> /var/home`); env override would let any process that sets the environment redirect quarantine writes. |
| D5 | Local `quarantine.Decision` with only `review`/`block`; migrate to or map from `internal/policy.Decision` when REDACT-49 lands. | Fail-closed closed enum; keeps the on-disk format independent of a package that does not exist yet. |
| D6 | Strict structural validation on every read; re-hash only in `Verify`. | Cheap checks always; the O(size) check where it matters (release). |
| D7 | Reserve ID with exclusive `Mkdir`; content and metadata placed with no-replace `Root.Link`; entry complete only when `metadata.json` exists. | Atomic and stdlib-only. A plain `Rename` would replace an existing file; `link` refuses. |
| D8 | Store budget (`MaxStoreBytes`, `MaxEntries`) checked before any write. | Bounds disk use from a flood of suspicious downloads (watcher). Not serialized across processes (accepted). |
| D9 | Name and URI redactor-checked on Put and refused on a hit; bounded; URI userinfo/query/fragment refused. | Metadata is plaintext at rest and later shown to users and possibly MCP; refusing is fail-closed, whereas redacting would silently change the record. |
| D10 | euid 0 refused unless `Options.AllowRoot`. | A root-owned store under a user home breaks the ownership model and invites privilege confusion. |
| D11 (planner) | `encoding/json/v2` for strict decode. | Stdlib; rejects duplicate and case-variant members and trailing data (Verified, section 3.6). No new dependency. |
| D12 (planner) | Typed finding metadata encoding. | Exact round-trip of value types and large integers without `UseNumber` heuristics. |
| D13 (planner) | Four stacked PRs instead of three. | The security additions push the third PR well over 500 lines; see section 9. |

### 5.1 ADR 0006 draft notes (write `docs/adr/0006-quarantine-store.md` in PR 1)

- Title: "Quarantine store: on-disk format, trust boundary and atomic publish". Status Accepted. Spec link. Builds on ADR 0002, 0003, 0004.
- Context: hostile content at rest in the user's home; other local users and hostile scanned content are adversaries; same-uid processes are out of scope.
- Decisions: D1, D3, D4, D6, D7, D8, D9, D10, D11, D12 as above, plus fixed-text errors and the ID grammar.
- Verified behaviour (scratch probe, macOS go1.27.1 and Linux `golang:1.27` go1.27.3): `Root.Link(tmp, "id/content")` succeeds with a two-component in-root target; `Root.Link` onto an existing name returns `EEXIST` and leaves it unchanged; `Root.Link` through an escaping symlink returns "path escapes from parent"; `Root.Mkdir` on an existing name returns `EEXIST`; json v1 vs v2 strictness (section 3.6). PR 1/3 tests pin these on both OSes; the probe was run as root in the container and must be repeated as non-root in tests.
- Alternatives: dedup by sha256 only; shared blobs with refcount; random-only IDs; move/rename from `incoming`; `[]byte` input; temp directory plus rename (replace race, needs per-OS no-replace syscalls); lenient JSON; env override; repairing entry directories.
- Accepted risks (user-accepted, record verbatim in ADR and threat model): raw secrets at rest unencrypted, included in backups, no retention policy; sha256 exposed in every ID (offline guessing of low-entropy content by anyone who can see the name, which needs our uid given 0700); orphan `.tmp-*` files holding raw content after a crash, cleanup deferred to a follow-up issue.
- Consequences and caller constraints (section 7).

## 6. Risks and failure modes

| Risk | Handling |
|---|---|
| Crash mid-Put | Orphan `.tmp-*` (raw content, 0600) or an entry dir without `metadata.json`; never a valid-looking entry. Counted in the budget. Cleanup deferred (REDACT-58 for incomplete entries, follow-up issue for temp files). Accepted (D4 of user). |
| Source modified while copying | `ErrSourceChanged` when the count differs from fstat size. Same-size in-place modification is not detected; the stored hash still matches the stored bytes, which is the invariant that matters. |
| Concurrent Puts overshoot budget | Budget check is not locked; N concurrent Puts can exceed by up to N entries. Accepted for v1; the watcher (59/60) should serialize. Recorded in threat model. |
| Disk full / I/O error | Fixed error, best-effort cleanup of this call's files only. |
| Filesystem ignores chmod (some FUSE/network mounts) | Re-fstat after repair; still loose: `ErrUnsafeDir` (fail closed). |
| Hard links into an entry | Not refused (nlink may legitimately be 2 if a temp removal failed). Requires the same uid, which is out of scope. Recorded. |
| macOS Spotlight indexing | `.metadata_never_index` best effort. Whether current macOS honours it for a non-volume-root folder is **Assumed** (not verified); noted as a residual risk. |
| json/v2 API drift | **Verified** present and default-enabled in go1.27 (probe built with empty `GOEXPERIMENT`). If a future toolchain changes it, tests in PR 2 fail. |
| Running tests as root in Linux container | `Open` refuses euid 0: run the container with `--user 1000:1000 -e HOME=/tmp`; root-only tests (chown) run in a separate root invocation with `AllowRoot`. |
| Metadata cap too low for real findings | `ErrMetadataTooLarge` at Put (fail closed, caller reports incomplete). 4 MiB is **Assumed**; revisit with real scanner output. |

## 7. Security

Trust boundary: the store directory tree under `base`, owned by the invoking user. Adversaries: hostile scanned content (bytes, file names, URIs, findings derived from it) and other local users. Out of scope: processes running as the same uid (they can already read 0700/0600), root.

Controls:
- Permissions: directories exactly 0700, files exactly 0600, set by `fchmod` on descriptors (never by path, never relying on umask); special bits cleared or refused. Execute bits stripped by construction.
- Symlinks: refused at `base` and below; every directory pinned with `safefs.OpenChildDir`, every file opened with `safefs.OpenRegularIn` (Lstat + SameFile). All operations are single-component or in-root multi-component calls through `os.Root`, which refuses escapes (Verified for `Link`).
- Ownership: every directory and file checked against euid on fstat.
- IDs: grammar checked before any I/O; no user-supplied string is ever a path component (Name/URI are display only).
- Fail closed: every unexpected state is a fixed sentinel; `Read` returns no partial metadata; incomplete entries never look complete.
- Input bounds and redactor check on Name/URI; metadata size checked before any write.
- No secrets in errors or logs: fixed error text, `Errno`-only unwrap, marker tests.
- Root refusal unless opted in.

Caller constraints (record in `docs/threat-model.md`):
- REDACT-58 never derives a release path from stored Name or URI; it chooses the destination independently and calls `verifyContent` on the same descriptor it copies from.
- Name, URI and finding strings are untrusted: CLI output escapes them; MCP marks them as untrusted quoted data.
- Neither `Read` nor any future MCP tool returns content bytes.
- `ErrStoreFull`, `ErrMetadataTooLarge` and every other Put failure are reported as "not quarantined / incomplete", never as clean, and callers never clean the store to make room.
- Findings passed to `Put` come from `scanner.Registry.Run` (redactor-checked); other producers must apply the same checks.

Accepted risks (user-accepted): macOS extended/inherited ACLs are not inspected or cleared (an inheritable allow-read ACE can expose entries despite 0700/0600; see ADR 0006; the PR 4 threat-model section must record the same risk); unencrypted raw content at rest including backups and no retention; sha256 visible in IDs; orphan temp files with raw content; unserialized budget; hard links by same uid; Spotlight marker best effort.

## 8. Performance/scalability

- Put: one sequential copy plus SHA-256 (bounded by `MaxEntrySize`), budget listing O(entries) Lstat calls (bounded by `MaxEntries` = 1000 default), three fsyncs of directories plus two of files.
- Read: one metadata file of at most 4 MiB, decoded once. Verify: O(size).
- Memory: metadata is built in memory (at most `MaxMetadataBytes` plus the decoded structure); content is streamed with a fixed buffer.
- No caching, no goroutines.

## 9. Implementation steps

Four stacked PRs (each targets <= ~500 changed lines including tests; split again if one exceeds it and tell the user).

**PR 1: layout and permissions (~450 lines + ADR)**
1. `safefs.OpenRegularIn` + `ErrNotOwned` + stubs. Tests: regular file, symlink, FIFO (no block), directory, swap between Lstat and open (mirror `TestOpenChildDirDetectsSwap`), foreign owner via seam, invalid names, marker-free error text. Expected: `task test`, `task cross` green.
2. `quarantine.go`: package doc, constants, errors, `Decision`, `Options` validation, `ValidID`. Tests: FR8 table.
3. `store_unix.go`: `Open`, `ensureDir`, `Repaired`, `Close`, darwin marker, seams. Depends on 1-2. Tests: FR1-FR7, symlinked parent allowed, marker-free errors.
4. ADR 0006 and architecture section 12 update. Linux container run (`--user 1000:1000`).

**PR 2: metadata v1 (~450 lines, no I/O)**
5. `redactor.IsClean` (move from scanner, scanner uses it; existing scanner tests unchanged and green).
6. DTOs, typed finding metadata, encode, strict v2 decode, `validateRecord`, Put-only input checks. Tests: FR9-FR11 (pure parts), FR18 corruption table on bytes, FR19 round-trip, the 1000-max-findings size test, duplicate/case-variant/trailing rejections.

**PR 3: Put (~480 lines)**
7. `Put`: input validation, fstat, pre-marshal, budget, copy, reserve, link, publish, cleanup. Depends on PR 1-2.
8. Tests: FR12-FR15, FR13 mode stripping, budget by bytes and count, crash simulation via seams (fail after each step: no valid entry; only expected leftovers), pre-planted `content`/`metadata.json` left unchanged, Linux run. File the orphan-temp cleanup follow-up issue.

**PR 4: Read, Verify, threat model (~400 lines + docs)**
9. `Read`, `Verify`, `verifyContent`. Depends on PR 3.
10. Tests: FR16-FR21 including swap tests and the marker-name test over all Put/Read/Verify paths.
11. `docs/threat-model.md` Quarantine section (controls, caller constraints, accepted risks). Linux run.

## 10. Testing strategy

- Unit tests per FR in section 2; table-driven where possible; test seams (`geteuid`, `randSuffix`, `now`, reader wrapper, step-failure hooks) as package variables like safefs.
- Regression guards (break-the-guard, then revert; each must fail a test): drop the `ValidID` check; drop `fchmod` on content; use `Rename` instead of `Link` for content; skip the owner check; repair entry dirs instead of refusing; decode with v1 `encoding/json`; drop the redactor check on Name; skip the pre-marshal size check.
- Linux: `docker run --rm --user 1000:1000 -e HOME=/tmp -v "$PWD":/src -w /src golang:1.27 go test ./...` in every PR (CI runs no Go tests); root-only ownership tests in a separate root run. Record results in the PR.
- No test writes to the real `~/.redactscan`: every test passes an explicit `t.TempDir()`-based base.
- Follow `.agents/skills/test-writing/SKILL.md`.

## 11. Observability, deployment, rollback

- No logging inside the package. Callers may log the ID and the error sentinel only. `Repaired()` lets the CLI print a fixed warning naming the repaired directory kinds.
- Deployment: library only; nothing calls it until REDACT-57..60. Rollback is reverting the PRs; any `~/.redactscan` created by manual testing can be deleted by the user.

## 12. Definition of done

- All FRs covered by tests; break-the-guard checks done.
- `task test` during development; `task verify` (fmt, lint, test, cross, security, secrets) passes before each PR is marked ready.
- Linux container run recorded in each PR.
- ADR 0006, architecture section 12 and the threat-model Quarantine section updated.
- Follow-up issue filed for orphan `.tmp-*` cleanup; REDACT-58 notes updated with the `Verify`/`verifyContent` and release-path constraints; REDACT-49 note on `Decision` migration.
- `staff-engineering-reviewer` and `security-reviewer` pass on each PR.
