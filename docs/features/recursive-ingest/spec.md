# Recursive directory ingestion: spec

Status: approved design (user-approved after `security-reviewer` design review; findings R1-R7 and advisories incorporated).
Story: [REDACT-39](http://localhost:8080/issue/REDACT-39) "Recursive directory ingestion with safe traversal". Depends on REDACT-35 (merged: `internal/artifact`, `internal/finding`) and REDACT-10 (merged: `internal/safefs`, ADR 0002; ADR 0003 for the pinned-root pattern).
Branch: `feat/redact-39-recursive-ingest`. Delivered as three stacked PRs (section 9).
Packages: new `internal/ingest`; additions to `internal/safefs` and `internal/artifact`. Go standard library only, no new dependency.
Related: `docs/architecture.md` section 8; `docs/threat-model.md`; ADR 0002, ADR 0003. New ADR 0004 (PR 1).
Visual plan: `plans/recursive-ingest/plan.mdx`.

> Spec text and tests never contain realistic secret values. Tests build any secret-shaped input at runtime.

## 1. Feature overview

**Purpose.** Give RedactScan a safe way to turn a directory tree (a cloned repo, an extracted archive, a project folder) into a list of `artifact.Artifact` values for later scanning, so that `scan ./project` can be built on it. The tree is untrusted: it may contain symlinks pointing outside it, symlink loops, FIFOs, devices, sockets, absurdly deep or wide directories, and entries that are swapped while the walk runs. The walker must never follow a symlink, never hang, never leave the root, keep its memory bounded, and never let a partial walk look like a complete one.

**Concrete example.** A cloned repo `./project` contains `src/main.go`, `docs -> ../../.ssh` (a symlink escaping the repo), `loop -> loop`, a FIFO `build/pipe`, and a 70-level-deep directory chain. `ingest.Walk("./project", ingest.Limits{})` returns:

- Artifacts for `src/main.go` and every other regular file within the limits, with `Path` = `./project/src/main.go`.
- Findings: `ingest-symlink` (medium, `link_kind=escape`) for `docs`, `ingest-symlink` (low, `link_kind=loop`) for `loop`, `ingest-special-file` (low, `file_type=fifo`) for `build/pipe`, and one `ingest-incomplete` (medium, `depth_skipped=1`).
- The error `ingest.ErrIncomplete`, because the depth limit was hit. A caller that writes `if err != nil { return err }` stops: fail closed by default.

**In scope**

- `internal/safefs`: `OpenDirRoot` (pin the walk root, no symlink in any typed component), `OpenChildDir` (open one child directory through a parent root without blocking or following a symlink), shared `rootFromDir` helper (refactored out of `WriteSibling`), `ErrNotDir`, non-Unix stubs.
- `internal/artifact`: typed `SourceMetadata.Type` constants (deferred to this story by the REDACT-35 spec).
- `internal/ingest`: `Walk(root, Limits) (Result, error)` producing Artifacts for regular files and Findings for everything skipped; symlink classification; depth, entry-count and path-length limits; `ErrIncomplete` contract.
- ADR 0004; `docs/threat-model.md` sections; `docs/architecture.md` section 8 note.

**Non-goals**

- A `scan` CLI command or any output/report format (later story, once a scanner exists).
- Reading file contents: `MIMEType` and `SHA256` stay empty; no hashing, no type sniffing.
- `.git` special handling: `.git` is walked as an ordinary directory (deferred).
- Single-file ingest (`scan file.sh`), archives, git clone, downloads, URLs.
- `context.Context` / cancellation / timeouts (user decision; follow-up).
- Staying on one filesystem (`-xdev`), an info Finding on `st_dev` change, `dev`/`ino`/`nlink` in Metadata (follow-ups).
- A total path-bytes memory budget (user decision: document the worst case instead).
- Windows and other non-Unix platforms (stub returns `ErrUnsupportedPlatform`, as in ADR 0002).
- Escaping control/ANSI/bidi characters in names (output/report story).

## 2. Functional requirements and acceptance criteria

| ID | Requirement | Acceptance criteria |
| --- | --- | --- |
| FR1 | Root validation before any I/O. | `root == ""` or containing `\x00` returns `ErrInvalidRoot` and an empty `Result`, with no syscall (test: no fd change, hook never called). |
| FR2 | Root pinned without following symlinks. | Root reached through a symlink in any typed component (final or parent) returns `safefs.ErrSymlink`. Regular-file root returns `safefs.ErrNotDir`. FIFO root returns `safefs.ErrNotDir` within 2 s (no hang). `/` works. On macOS `/tmp/` works and `/tmp` (no trailing slash) is refused with `ErrSymlink` (documented, per ADR 0002 decision 3). All are fatal: empty `Result`, error is not `ErrIncomplete`. |
| FR3 | Limits. | `Limits{}` uses `MaxDepth=64`, `MaxEntries=100000`. Negative field, `MaxDepth > 256` or `MaxEntries > 1000000` returns `ErrInvalidLimits` before any I/O. |
| FR4 | Regular files become Artifacts. | For each regular file: `ID = "a-<n>"` (n from 1, walk order); `Path` = root path (see 3.4) + `/` + `RelativePath`; `RelativePath` = slash-joined names from the root; `Name` = last component; `RelativePath` and `Name` are substrings of `Path`; `Size` from `Lstat`; `MIMEType`, `SHA256`, `Source.URI` empty; `Source.Type = artifact.SourceDirectory`; `Metadata` nil. Every Artifact's `Path` opens with `safefs.OpenRegular` in tests. |
| FR5 | Deterministic order. | For a fixed tree within the limits, two walks return identical Artifacts and Findings (same IDs, same order). Entries in each directory are processed in byte order of name, depth-first. |
| FR6 | Symlinks are never followed and are classified (acceptance 1). | Every symlink gives one `ingest-symlink` Finding and no Artifact; nothing under it is listed. `Metadata["link_kind"]` and severity: `escape` medium, `loop` low, `dangling` info, `in-root` info, `unknown` medium (plus `Metadata["errno"]` int when known). Link target text never appears in any Finding field or error. Table test per 3.6. |
| FR7 | Special files skipped with a Finding (acceptance 2). | FIFO, character/block device, socket and other irregular modes give `ingest-special-file` (low) with `Metadata["file_type"]` = `fifo`, `device`, `socket` or `irregular`; never opened; no Artifact. |
| FR8 | Depth limit (acceptance 3). | An entry's depth = number of components in its `RelativePath`. A directory at depth `== MaxDepth` is counted but not opened or listed; each such directory increments `depth_skipped`. Walk continues with siblings. |
| FR9 | Entry limit (acceptance 3). | Every name read from any directory (files, directories, symlinks, special files) counts. When the count would exceed `MaxEntries`, at most `MaxEntries` entries are processed in total, `entries_capped=true`, and no further directory is listed. Which entries survive a cut inside one directory depends on filesystem order (documented). |
| FR10 | Path length cap. | `MaxPathBytes = 1024` with headroom: an entry is accepted only when `len(Path) + len("/private") < MaxPathBytes`, so the longest accepted `Path` is 1015 bytes (one byte for the NUL and 8 for the macOS rewrite of a `/tmp`, `/var` or `/etc` root to `/private/...`). The same rule applies on every OS. An entry that fails it gives `ingest-path-too-long` (medium), no Artifact, is not descended, increments `path_too_long`. |
| FR11 | Changed entries. | A directory replaced between `Lstat` and open (by a FIFO, a symlink to a FIFO, a symlink to a directory, a different directory) gives `ingest-changed` (medium), increments `changed`, returns within 2 s, leaks no fd. |
| FR12 | Read errors. | Failure to open or list a directory: `ingest-read-error` (medium, `Metadata["op"]` = `open dir` or `list dir`). `Lstat` failure on an entry: `ingest-read-error` (low, `op` = `lstat`). Each increments `read_errors`. A listing error after a partial batch: the error is recorded first, then the names already read are processed (section 3.5). |
| FR13 | Incomplete contract (acceptance 3). | If any of `depth_skipped`, `entries_capped`, `read_errors`, `changed`, `path_too_long` is non-zero/true: `Walk` returns the partial `Result` and an error with `errors.Is(err, ErrIncomplete)`, and `Result.Findings` contains exactly one `ingest-incomplete` Finding (medium, last in the list) whose Metadata holds all five counters (`entries_capped` bool, others int). Otherwise the error is nil and there is no `ingest-incomplete` Finding. Symlinks and special files alone do not make the walk incomplete. |
| FR14 | Produced values are valid. | Every Artifact and Finding is passed through `Validate` before it is appended. A failure returns `ErrInternal` with an empty `Result` (never a silent drop, never `ErrIncomplete`). Test: every Finding/Artifact in every test result validates. |
| FR15 | No path, name or OS text in errors. | No error returned by `Walk`, `OpenDirRoot` or `OpenChildDir` contains the root path, any entry name, a link target or OS error text (marker-name test on every error path). |
| FR16 | Bounded resources. | Open descriptors at any time are at most about `depth + 2`; after `Walk` returns (any outcome) the process fd count equals the count before. Memory per Artifact measured by benchmark and documented. |

## 3. Technical design

### 3.1 Layout

```text
internal/safefs/
  safefs.go           + ErrNotDir
  dir_unix.go         + OpenDirRoot, OpenChildDir, rootFromDir (darwin || linux)   [new]
  dir_other.go        + stubs returning ErrUnsupportedPlatform                     [new]
  write_unix.go       WriteSibling uses rootFromDir (behavior unchanged)
  dir_test.go         [new]
  root_semantics_test.go  pins the os.Root behaviors this design relies on       [new]
internal/artifact/
  artifact.go         + SourceFile, SourceDirectory, SourceArchive, SourceGit, SourceDownload
internal/ingest/      [new]
  ingest.go           package doc, Limits, Result, errors, Walk
  walk.go             walker state, directory listing, entry handling
  symlink.go          classification (PR 3)
  ingest_test.go, walk_test.go, symlink_test.go, bench_test.go
docs/adr/0004-directory-ingest-pinned-root.md   [new, PR 1]
```

File split is a suggestion; the implementer may merge `walk.go` into `ingest.go` if smaller.

### 3.2 `internal/safefs` additions

```go
var ErrNotDir = errors.New("safefs: not a directory")

// OpenDirRoot opens path as a directory reached without a symlink in any
// typed component (same rules and macOS system-link handling as OpenRegular)
// and returns the verified directory and an os.Root pinned to it. The caller
// closes both. The *os.File is for listing only; it is non-blocking.
func OpenDirRoot(path string) (*os.File, *os.Root, error)

// OpenChildDir opens the single component name in parent as a directory and
// returns it and a Root pinned to it, only if it is the same file as want
// (the caller's Lstat result). It never blocks on a FIFO.
func OpenChildDir(parent *os.Root, name string, want fs.FileInfo) (*os.File, *os.Root, error)
```

**`OpenDirRoot(path)`** (darwin, linux):

1. `p := normalizePath(path)`.
2. `f, err := openNoFollow(p, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK)` (macOS: `O_NOFOLLOW_ANY`; Linux: `openat` walk, as in ADR 0002).
3. Error mapping: `isSymlinkRefusal(p, err)` gives `ErrSymlink`; `ENOTDIR` gives `ErrNotDir`; anything else `newOpError("open dir", err)`.
4. `r, err := rootFromDir(f)`; on error close `f`.

**`OpenChildDir(parent, name, want)`**:

1. Reject `name` that is `""`, `.`, `..`, or contains `/` or `\x00` with `ErrInvalidName` (defensive; `Readdirnames` never returns these).
2. `f, err := parent.OpenFile(name, O_RDONLY|O_DIRECTORY|O_NONBLOCK, 0)`. `O_DIRECTORY` makes a FIFO (or symlink to one) fail with `ENOTDIR` instead of blocking. Errors: `ENOTDIR`, `ELOOP`, `ENOENT` and an `os.Root` escape give `ErrChanged` (the caller just saw a directory there); other errors `newOpError("open dir", err)`.
3. `st := f.Stat()`; if `!os.SameFile(st, want)` close and return `ErrChanged`. This catches a directory swapped for an in-root symlink to a directory, which `Root.OpenFile` follows.
4. `r, err := rootFromDir(f)`; on error close `f`.

**`rootFromDir(f)`**: `os.OpenRoot(fmt.Sprintf("%s/%d", fdDir, f.Fd()))` then `sameAsRoot(f, r)` (else close and `ErrChanged`); errors `newOpError("open root", err)`. Extracted from `WriteSibling` lines that do exactly this; `WriteSibling` keeps its `beforeOpenRoot` hook before the call and its behavior and tests are unchanged.

**Never use `Root.OpenRoot(name)` for traversal.** It opens without `O_DIRECTORY`/`O_NONBLOCK` and blocks forever on a FIFO swapped in for a directory (Verified on macOS go1.27.2: hangs > 2 s). ADR 0004 records this.

`dir_other.go`: both functions return `nil, nil, ErrUnsupportedPlatform`.

### 3.3 `internal/artifact` additions

```go
// Source types for SourceMetadata.Type.
const (
	SourceFile      = "file"
	SourceDirectory = "directory"
	SourceArchive   = "archive"
	SourceGit       = "git"
	SourceDownload  = "download"
)
```

Untyped string constants so `SourceMetadata.Type string` is unchanged. Update the field comment to point at them.

### 3.4 `internal/ingest` API

```go
// Package ingest turns inputs into artifacts. Walk lists a directory tree
// without following symlinks or leaving the root. It reads no file contents.
//
// Fail closed: a Walk that returns an error matching ErrIncomplete returned a
// partial result. Callers must never treat it as a complete or clean scan.
//
// Untrusted fields: Artifact.RelativePath, Artifact.Name and Finding.File are
// file names from the scanned tree. They may contain control, ANSI and bidi
// characters and invalid UTF-8 (distinct names can look identical once
// escaped). Display only; output code must escape them. Never join them to a
// directory or pass them to a filesystem call; open Artifact.Path with
// safefs.OpenRegular.
//
// A relative root is resolved against the current directory, which is not
// itself checked (as in safefs).
package ingest

const (
	DefaultMaxDepth   = 64
	DefaultMaxEntries = 100_000
	MaxMaxDepth       = 256       // one open descriptor per level
	MaxMaxEntries     = 1_000_000
	MaxPathBytes      = 1024      // macOS PATH_MAX incl. NUL, minus "/private" headroom; every OS
)

type Limits struct {
	MaxDepth   int // 0 means DefaultMaxDepth
	MaxEntries int // 0 means DefaultMaxEntries; counts every directory entry
}

type Result struct {
	Artifacts []artifact.Artifact
	Findings  []finding.Finding
}

var (
	ErrIncomplete    = errors.New("ingest: scan incomplete")
	ErrInvalidLimits = errors.New("ingest: invalid limits")
	ErrInvalidRoot   = errors.New("ingest: invalid root")
	ErrInternal      = errors.New("ingest: internal error")
)

func Walk(root string, lim Limits) (Result, error)
```

Fatal errors (empty `Result`): `ErrInvalidRoot`, `ErrInvalidLimits`, `ErrInternal`, and whatever `safefs.OpenDirRoot` returns (`ErrSymlink`, `ErrNotDir`, `ErrChanged`, `ErrUnsupportedPlatform`, opError). The only non-fatal error is `ErrIncomplete`.

**Root path for building `Path`.** The typed `root` is passed to `OpenDirRoot` unchanged. For joining only: if `root` consists only of `/` characters, the prefix is `/` and `Path = "/" + rel`; otherwise trailing `/` are trimmed and `Path = trimmed + "/" + rel`. No `filepath.Clean` (it would change the `/tmp/` prefix rule and `..` semantics that `OpenRegular` relies on).

### 3.5 Walk algorithm

State: top root (`*os.Root` from `OpenDirRoot`, kept open for the whole walk, used for symlink classification), counters (`entries`, `depthSkipped`, `entriesCapped`, `readErrors`, `changed`, `pathTooLong`), artifact and finding sequence numbers, result slices.

`walkDir(dirFile *os.File, r *os.Root, rel string, depth int)`, where `depth` is the depth of the directory (root = 0) and `r` is pinned to it:

1. **List.** `names := readNames(dirFile, remaining+1)` where `remaining = MaxEntries - entries`: call `dirFile.Readdirnames(1024)` (or less, to not exceed `remaining+1`) until EOF, an error, or `remaining+1` names. Handle short batches without EOF by looping. On an error, keep the names already read, record `ingest-read-error` (medium, `op=list dir`, `File=rel`), and continue with those names. Then **close `dirFile`** (so at most one listing handle is open at a time).
2. **Cap.** If `len(names) > remaining`: sort, keep the first `remaining`, set `entriesCapped`. `entries += len(names)`.
3. **Sort** `names` in byte order (`slices.Sort`).
4. For each `name` (child depth `d = depth+1`, `childRel = rel + "/" + name` or `name` at the top):
   1. `path := prefix + "/" + childRel` (3.4). If `len(path) + len("/private") >= MaxPathBytes` (FR10): `ingest-path-too-long`, `pathTooLong++`, continue.
   2. `fi, err := r.Lstat(name)`. Error: `ingest-read-error` (low, `op=lstat`), `readErrors++`, continue.
   3. Switch on `fi.Mode().Type()`:
      - **Regular:** append Artifact (FR4).
      - **Symlink:** append the symlink Finding (3.6). Never opened, never listed.
      - **Directory:** if `d >= MaxDepth`: `depthSkipped++`, continue. If `entriesCapped`: continue (no further listing). Else `beforeChildOpen(name)` (test hook), `cf, cr, err := safefs.OpenChildDir(r, name, fi)`. `ErrChanged`: `ingest-changed`, `changed++`. Other error: `ingest-read-error` (medium, `op=open dir`), `readErrors++`. Success: `walkDir(cf, cr, childRel, d)`, then `cr.Close()`.
      - **Other:** `ingest-special-file` (low, `file_type` from `safefs` file-type mapping: fifo, device, socket, irregular).
5. Recursion depth is bounded by `MaxDepth <= 256`; open descriptors are one `*os.Root` per level plus the top root plus at most one listing file.

After the top-level `walkDir` returns: close the top root; if any counter is non-zero/true, append `ingest-incomplete` and return `ErrIncomplete`.

`appendArtifact` / `appendFinding` call `Validate`; failure aborts the walk with `ErrInternal` and an empty `Result` (FR14).

Test seams (unexported package vars, no-op in production, restored with `t.Cleanup`, tests using them do not run in parallel): `beforeChildOpen func(name string)`, `readNames` (the listing function, so a test can inject a partial batch plus error).

`safefs` file-type mapping: export a small helper or reuse `safefs.FileType` constants via a local switch on `fs.FileMode` in ingest (implementer's choice; prefer exporting `safefs.TypeOf(fs.FileMode) FileType` if under 5 lines to avoid duplicating knowledge).

### 3.6 Symlink classification (PR 3)

`classify(top *os.Root, rel string) (linkKind, int)` uses `top.Stat(rel)` with the slash-joined path from the **top** root, so a link `a/b/c -> ../x` is resolved relative to its own directory but confined to the whole tree (classifying against the child root would wrongly report in-root sibling links as escapes):

| `top.Stat(rel)` result | kind | severity |
| --- | --- | --- |
| nil | `in-root` | info |
| `errors.Is(err, syscall.ELOOP)` | `loop` | low |
| `errors.Is(err, fs.ErrNotExist)` | `dangling` | info |
| `*fs.PathError` whose inner error is not a `syscall.Errno`, or is `syscall.EXDEV` | `escape` | medium |
| any other error | `unknown` (+ `errno` int when the inner error is a `syscall.Errno`) | medium |

Verified on macOS go1.27.2 (scratch probe): in-root target returns nil; dangling matches `fs.ErrNotExist`; self-loop and two-link loop match `ELOOP`; relative, absolute, chained, and missing-target escapes return a `*fs.PathError` wrapping an unexported `*errors.errorString` "path escapes from parent" (not an `Errno`). Assumed (Linux unverified; step 1 checks): Linux gives the same results; `EXDEV` is mapped to `escape` in case Linux's implementation reports escapes that way. If step 1 finds a different behavior that the table cannot classify, stop and return to planning.

Documented edge cases: `ELOOP` also covers chains longer than the kernel/`os.Root` link limit (reported as `loop`); a symlink with an empty target returns a non-`Errno` "empty path" error and is reported as `escape`; an in-root link whose resolution needs a directory without search permission reports `unknown` with `errno=EACCES`. Assumed: `os.Root` resolves links component by component and refuses an escape before touching anything outside the root, so classification causes no metadata access outside the tree (consistent with the probe returning "escapes" for a missing outside target).

Finding: `ID "ingest-symlink-<n>"`, `Category "ingest"`, `Title "symlink not followed"`, `File = rel`, `Metadata{"link_kind": kind}` plus `"errno": errno` for `unknown` when known. Never the link target.

In PR 2 (before classification lands) every symlink gives `ingest-symlink` at **medium** with no `link_kind` (fail closed); PR 3 replaces this.

### 3.7 Findings catalog

| Kind | Severity | Metadata | Makes walk incomplete |
| --- | --- | --- | --- |
| `ingest-symlink` | per 3.6 | `link_kind`, optional `errno` | no |
| `ingest-special-file` | low | `file_type` | no |
| `ingest-read-error` | medium (`open dir`, `list dir`), low (`lstat`) | `op` | yes |
| `ingest-changed` | medium | none | yes |
| `ingest-path-too-long` | medium | none | yes |
| `ingest-incomplete` | medium | `depth_skipped`, `entries_capped`, `read_errors`, `changed`, `path_too_long` | (summary; exactly one when incomplete) |

All: `ID = "<kind>-<n>"` (n is a per-walk Finding counter starting at 1), `Category = "ingest"`, fixed `Title`/`Description` per kind, `ArtifactID = ""` (skipped entries have no Artifact), `File` = relative path (`""` for `ingest-incomplete`), `Line = 0`, `Evidence = ""`. Depth-skipped directories get no per-directory Finding (only the counter), to avoid flooding.

## 4. Data/API changes and migrations

- New exported API: `safefs.OpenDirRoot`, `safefs.OpenChildDir`, `safefs.ErrNotDir`; `artifact.Source*` constants; package `ingest` (section 3.4).
- `WriteSibling` refactored to use `rootFromDir`; no behavior change.
- No persisted data, no config, no CLI change, no migrations.

## 5. Engineering decisions and rationale

| Decision | Rationale | Alternatives rejected |
| --- | --- | --- |
| Library only, no `scan` command (user) | No scanner yet; avoids freezing output/exit-code rules before the report story. | Minimal `scan` command (output and exit design, ~2 PRs more); hidden debug command. |
| Traverse through a pinned `os.Root`, children opened with `O_DIRECTORY|O_NONBLOCK` plus `SameFile`, child root built from the verified fd (user + security R1) | Escapes refused even mid-walk; a FIFO swap cannot hang; an in-root symlink swap is detected; listing uses the same verified descriptor, so no swap window between check and list. Standard library only; same pattern as ADR 0003. | `filepath.WalkDir` (a mid-walk symlink swap redirects outside the root); `Root.OpenRoot(name)` (blocks on FIFO, follows final in-root symlink); per-OS `openat` walker (strongest, but much more code). |
| Classify symlinks against the top root (user + R4) | Escapes and loops are the suspicious cases; reporting every link keeps coverage visible; top-root resolution is correct for nested sibling links. | One generic Finding; report only escapes/loops; child-root classification (false escapes). |
| Partial `Result` plus `ErrIncomplete`, plus exactly one medium `ingest-incomplete` Finding (user + R2) | Default Go error handling fails closed; partial Findings are kept; the summary Finding keeps reports honest even when a caller handles the error. | Flag only (easy to ignore); error only (loses partial Findings); per-limit Findings (more kinds, same information). |
| Limits 64 / 100,000 counting every entry; zero = default; negative or above caps 256 / 1,000,000 rejected (user + advisory) | Counting every entry bounds work for trees of empty dirs, links or FIFOs; caps bound descriptors and memory; an unset field never means "unlimited". | Count only files (unbounded on non-file trees); 32 / 10,000 (too tight for monorepos). |
| `MaxPathBytes = 1024` on every OS, with `len("/private")` headroom, so the longest accepted `Path` is 1015; over-cap entries reported and skipped (R3) | Every Artifact `Path` stays openable by `OpenRegular` even when a typed `/tmp/` root is rewritten to `/private/tmp/` and `PATH_MAX` (1024) counts the NUL; memory per entry is bounded. One rule is simpler than per-OS values or a safefs helper. | Per-OS caps (4096 on Linux); no cap (16 KiB paths, `ENAMETOOLONG` later). |
| No total path-bytes budget; document the worst case: about 215 MB allocated, about 126 MiB retained (user) | Comparable to the redactor's ~100 MiB per-call budget; one less knob. | `Limits.MaxPathBytesTotal`. |
| Full directory read (up to budget+1), close, byte-order sort, process (R6) | Deterministic output and IDs; at most one listing handle open; `Readdirnames` avoids the per-entry `lstat` and silent `ENOENT` skip of `ReadDir` on a Root-opened file. | Batch-local sort (non-deterministic); `ReadDir`. |
| Artifact IDs `a-<n>` per walk | Generated, unique, stable for an unchanged tree because of sorting; no hashing of names. | Hash of relative path (stable across tree changes, more reasoning about collisions). |
| Directory root required; file root returns `ErrNotDir` | Single-file ingest is a separate input type per architecture section 8. | Accept a file and emit one Artifact (scope creep). |
| `Validate` failure is fatal `ErrInternal` (user + R6) | A produced value failing its contract is a bug; failing loudly is fail-closed and never drops output silently. | Count as incomplete. |
| No `context.Context` now (user) | Cannot interrupt a blocked syscall anyway; internal API, cheap to add later. | Add now. |

**ADR 0004** (PR 1): "Directory ingestion traverses through a pinned `os.Root`." Records: why `os.Root` is right for traversal while ADR 0002 rejected it for opening one typed path (traversal needs confinement to the tree; the single-file case needs "no symlink at all"; here symlinks are never followed anyway because every entry is `Lstat`ed first and children are opened with a `SameFile` check); the `Root.OpenRoot` FIFO hazard and the `O_DIRECTORY|O_NONBLOCK` + fd-pinned child root rule; the `ErrIncomplete` fail-closed contract; and the accepted risks in section 6.

## 6. Risks and failure modes

| Risk / failure | Handling |
| --- | --- |
| Directory swapped for FIFO / symlink to FIFO mid-walk | `O_DIRECTORY` gives `ENOTDIR`, no block; `ingest-changed`; tested with hook and 2 s timeout (R1). |
| Directory swapped for an in-root symlink to a directory | `Root.OpenFile` follows it, `SameFile` with the `Lstat` result fails; `ingest-changed` (Verified on macOS). |
| Symlink pointing outside the root, or swapped in to do so | Never followed: entries are `Lstat`ed; child opens are confined by `os.Root` (escape gives `ErrChanged`). |
| Directory moved outside the root while its descriptor is held | Accepted: it is listed (once) under its old relative path. The walk never resolves a path outside the root by name. |
| Hard links to files outside the tree | Accepted (existing threat-model risk): listed as regular files. Constraint for the future archive extractor: refuse hard links and absolute or escaping link targets. |
| Mount points inside the tree | Accepted: the walk crosses them. Scanning `/` reaches `/proc` (e.g. `/proc/self/environ` listed as a regular file) and `/dev` (devices skipped). Listing reads no content; a later content reader goes through `OpenRegular` and its own policy. `-xdev` is a follow-up. |
| Hung network filesystem | Accepted: no timeout; a blocking syscall can hang the walk (no `context`). |
| Symlink classification CPU cost | Accepted by the user. `Root.Stat` resolves targets in user space: one `openat(O_NOFOLLOW\|O_DIRECTORY)` plus close per target component, across up to 8 chained links. Cost is bounded by target length times hops, not by `MaxDepth` or `MaxEntries` (deep directories are skipped by the walker but still exist and `Stat` walks them). Hostile tree: about 480 nested directories plus up to about 100,000 links each pointing deep. Measured per link: macOS arm64 21.7 ms (480-level target) vs 4.8 us short (about 4,500x; 5,000 links = 108 s); Linux `golang:1.27` 270 us vs 3.3 us (about 80x). Extrapolated to 100,000 links: about 36 min macOS, about 27 s Linux (multi-hop chaining multiplies further: assumed, not measured). No confidentiality or integrity impact; a CI job that times out fails closed. Recommended future hardening before untrusted uploads or an MCP service: a classification step budget (deterministic step count; remaining links become `unknown`, medium) together with the `context`/timeout follow-up. |
| Ancestor swapped or moved mid-walk | A link can only be mislabelled: classification re-resolves from the top root and stays confined, so no escape. |
| Stale `Size` | Informational only; content readers re-check. |
| Entries cut inside a directory by `MaxEntries` | Which entries survive depends on filesystem order; the walk is reported incomplete. |
| Memory | Bounded by `MaxEntries` and `MaxPathBytes`. Measured allocation (`go test -bench`, macOS arm64): about 1.04 KiB (1.07 kB) per Artifact with short paths, about 2.1 KiB at 1015-byte paths, so about 215 MB allocated over a walk of 100,000 maximum-length Artifacts (allocation, mostly garbage-collectable, not retained). Findings are similar in size and also bounded by `MaxEntries`. Retained heap, measured with `runtime.ReadMemStats` after a GC: about 275 B per Artifact with short paths; with 1015-byte paths about 1.25 KiB, so about 126 MiB retained at the cap (extrapolated from the measured 275 B plus the path bytes; not measured at 100,000). |
| Descriptor exhaustion | At most `MaxDepth + 2` (<= 258) descriptors; macOS default soft limit is 256 (Assumed), so `MaxDepth` near 256 may hit `EMFILE`, which surfaces as `ingest-read-error` (incomplete), not a crash. Default 64 is far below. During symlink classification the count is briefly `MaxDepth + 4`; an `EMFILE` there degrades the label to `unknown` (errno 24, medium) and does not make the walk incomplete. |
| Linux `os.Root` behavior differs from macOS | Step 1 pins the behavior with tests in a Linux container; stop and re-plan if the classification table cannot cover it. |
| Test hooks misused | Unexported, no-op by default, restored in `t.Cleanup`. |

## 7. Security

- Trust boundary: the root path is user-supplied; everything below it is attacker-controlled.
- Never opens or lists through a symlink (classification only resolves it, confined to the root); never opens a non-directory except through `Lstat` (no content read at all in this story); never blocks on a FIFO; never leaves the root, even under concurrent modification.
- Fail closed: any unexpected condition becomes a Finding plus `ErrIncomplete`, or a fatal error; a bug in produced values is fatal (`ErrInternal`).
- Error text is fixed: no path, name, link target or OS text (FR15). `os.Root` errors contain the name (`openat out: ...`), so they are always wrapped with `newOpError` or mapped to a sentinel.
- Findings carry only fixed text, counters, the `link_kind`/`file_type`/`op` enums and an integer errno. `File` carries the untrusted relative path (display only, consumers escape).
- No new dependency.
- `security-reviewer` reviews every PR (path handling, symlinks).

## 8. Performance/scalability

- Symlink classification is not bounded by `MaxDepth` or `MaxEntries`; its cost is target length times link hops (accepted risk, section 6).
- Per entry: one `lstat` (plus one `Stat` for symlinks, which costs one `openat` per target component, one `open`+`fstat`+`open root`+`fstat` per directory). No content reads.
- Memory bounded by `MaxEntries` (names are held per directory only until processed; Artifacts are kept). Benchmarks report allocations per Artifact (10,000 short-path files; 1,000 maximum-length paths); the measured figures are in section 6 and the threat model.
- Single goroutine; no concurrency.

## 9. Implementation steps

Three stacked PRs; each branches from the previous. Estimated sizes: PR 1 about 350 changed lines plus ADR, PR 2 about 480, PR 3 about 280 including docs. If PR 2 lands well under budget, PR 3's code may fold into it.

**PR 1: safefs directory primitives**

1. **Pin the `os.Root` behaviors (both OSes).** `internal/safefs/root_semantics_test.go`: tests that assert, on a temp tree, `Root.Stat` results for in-root, dangling, loop, two-link loop, relative/absolute/missing escape, empty-target link; `Root.OpenFile(name, O_RDONLY|O_DIRECTORY|O_NONBLOCK)` returns `ENOTDIR` for a FIFO and a symlink to a FIFO within 2 s; `Readdirnames(1024)` batches work on that descriptor; `os.OpenRoot(fdDir/N)` works. Run on macOS and in a Linux container (`docker run --rm -v "$PWD":/src -w /src golang:1.27 go test ./internal/safefs/...`). Depends on nothing. Expected: green on both, or **stop and return to planning** with the observed Linux behavior.
2. **`rootFromDir`, `ErrNotDir`, `OpenDirRoot`, `OpenChildDir`, stubs.** `safefs.go`, `dir_unix.go`, `dir_other.go`, `write_unix.go` refactor. Depends on 1. Expected: existing `safefs` tests unchanged and green; `task cross` green.
3. **Tests for the new primitives.** `dir_test.go`: `OpenDirRoot` on a dir, `/`, a file (`ErrNotDir`), a FIFO (`ErrNotDir`, 2 s timeout), a symlinked root and symlinked parent (`ErrSymlink`), macOS `/tmp/` vs `/tmp`; `OpenChildDir` with a dir, a dir swapped for FIFO, symlink to FIFO, in-root symlink to dir, different dir (all `ErrChanged`), invalid names; fd counts unchanged after every case; error text contains no marker name. Depends on 2.
4. **Docs for PR 1.** ADR 0004 (section 5); threat-model "Safe file opening" section: add the two functions and the `Root.OpenRoot` FIFO rule. Depends on 2-3.

**PR 2: ingest walker**

5. **`artifact.Source*` constants.** Plus field comment update and a trivial test. Depends on nothing.
6. **`ingest` API, validation and walk.** `ingest.go`, `walk.go` per 3.4, 3.5 and 3.7; symlinks emit the interim medium `ingest-symlink` without `link_kind`. Depends on PR 1 and 5.
7. **Walker tests and benchmark.** `ingest_test.go`, `walk_test.go`, `bench_test.go`: FR1-FR5, FR7-FR16 (mode-000 subdir skipped as root; forced list error via `readNames`; forced change via `beforeChildOpen` swapping dir to FIFO and to symlink-to-FIFO with 2 s timeout; path just over / at 1024 bytes; depth exactly at and past `MaxDepth`; `MaxEntries` cut inside one directory and across directories; `ErrIncomplete` + exactly one `ingest-incomplete` with correct counters; no `ingest-incomplete` on a clean tree with symlinks and FIFOs; every Artifact/Finding validates; every Artifact `Path` opens with `OpenRegular`; deterministic repeat; fd counts; marker names absent from errors; `ErrInternal` path via a seam or a unit test of `appendFinding` with an invalid Finding). Benchmark: 10,000-file tree, `ReportAllocs`. Linux container run. Depends on 6.

**PR 3: symlink classification and docs**

8. **Classification.** `symlink.go` per 3.6, replacing the interim Finding. Depends on PR 2.
9. **Classification tests.** `symlink_test.go` table: nested sibling in-root (`a/b/c -> ../d`), `../../..` escape, absolute escape, dangling in-root, self-loop, two-link loop, empty target (escape), EACCES middle component (`unknown`, `errno` set; skipped as root); no Finding field contains the link target; severities. Linux container run. Depends on 8.
10. **Docs.** `docs/threat-model.md`: new "Directory ingestion (`internal/ingest`)" section with controls, caller constraints (incomplete is never clean; untrusted names; open `Path` only via `OpenRegular`), accepted risks from section 6, the archive-extractor constraint, measured memory; `docs/architecture.md` section 8: short note that directory ingest exists, its limits and the `ErrIncomplete` contract. Depends on 8-9.

## 10. Testing strategy

- Real temp trees (`t.TempDir()` resolved with `filepath.EvalSymlinks` where a symlink-free base is needed), real symlinks, FIFOs (`syscall.Mkfifo`), a Unix socket (`net.Listen("unix", ...)` in a short path), mode-000 dirs.
- Anything that could block runs in a goroutine with a 2 s timeout and fails on timeout.
- fd leak checks: count entries in `/dev/fd` (macOS) or `/proc/self/fd` (Linux) before and after, as existing `safefs` tests do.
- Hook tests: no `t.Parallel`, hooks restored in `t.Cleanup`.
- Every test that gets a `Result` validates all Artifacts and Findings.
- Error-text regression: entry names and link targets use a marker string that must not appear in any `err.Error()`.
- Permission tests skip when `os.Geteuid() == 0`.
- Linux: CI runs no Go tests, so each PR records a Linux container run of `go test ./...` (`docker run --rm -v "$PWD":/src -w /src golang:1.27 go test ./...`).
- Break-the-guard check (manual, then revert): remove `O_DIRECTORY` from `OpenChildDir` (`TestOpenChildDirDoesNotOpenFIFO` must fail; `O_NONBLOCK` plus `SameFile` also reject a swapped FIFO, so the swap tests alone still pass: `O_DIRECTORY`'s unique job is refusing the open before it happens; removing both `O_DIRECTORY` and `O_NONBLOCK` makes the swap tests hang), remove the `SameFile` check (in-root symlink swap test fails), classify against the child root (nested sibling test fails), drop the `ingest-incomplete` Finding (FR13 test fails).

## 11. Observability, deployment, rollback

- No logging; results are the only signal (consistent with the CLI). No flags, no migrations, no user-visible change until a `scan` command exists.
- Rollback: revert the PRs in reverse order. PR 1 also changes `WriteSibling` internals; reverting it restores the previous code.

## 12. Definition of done

- FR1-FR16 covered by passing tests; acceptance criteria 1-3 of REDACT-39 demonstrated by named tests (symlink escape/loop table, special-file test, depth/entry limit tests with `ErrIncomplete`).
- `task test` during development; `task verify` (fmt, lint, test, cross, gosec, govulncheck, gitleaks) passes before each PR is marked ready.
- Linux container test run passes and is recorded in each PR.
- ADR 0004 added (PR 1); `docs/threat-model.md` updated (PR 1 and PR 3); `docs/architecture.md` section 8 updated (PR 3).
- Each PR uses `.github/pull_request_template.md`, links REDACT-39, this spec and ADR 0004, and lists manual steps: build a temp tree with an escaping symlink, a loop, a FIFO and a deep chain, run a small `go test -run` or example that prints Finding kinds and counters, and confirm `ErrIncomplete` and no hang.
- `staff-engineering-reviewer` and `security-reviewer` pass on each PR.
