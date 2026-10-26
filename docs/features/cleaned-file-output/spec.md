# Cleaned file output: spec

Status: approved by the user. Designed from the interview and the `security-reviewer` design review (disposition REQUIREMENTS, no blockers); PR 1 review findings are folded in below.
Story: [REDACT-11](http://localhost:8080/issue/REDACT-11). The story text needs updating (section 13). Depends on REDACT-2 (`redactscan redact`) and REDACT-10 (`internal/safefs`), both merged.
Branch: `feat/redact-11-cleaned-file-output` (stacked PR 2 branches from PR 1; see section 9).
Packages: `internal/safefs` (new write function), `internal/cli` (default output change, flags, messages). Go standard library only, no new dependency.
Related: `docs/threat-model.md` (Constraints for callers; Safe file opening; CLI), ADR 0001, ADR 0002, `docs/features/redact-command/spec.md`, `docs/features/safe-input-open/spec.md`. New ADR 0003.

> Spec text and tests never contain realistic secret values. Tests build secret-shaped input at runtime.

## 1. Feature overview

**Purpose.** `redactscan redact app.log` writes the redacted result to `app_cleaned.log` in the same directory as `app.log`. The file is written only after redaction succeeds, through a temp file and an atomic link or rename, so a failure never leaves partial or raw output, and concurrent runs never produce a mixed file.

**Concrete example.**

```
$ redactscan redact logs/app.log
redactscan: wrote "logs/app_cleaned.log"
redactscan: note: output may still contain uncovered secret formats
$ redactscan redact logs/app.log
redactscan: cannot write "logs/app_cleaned.log": already exists (use -force to replace)
$ redactscan redact -force logs/app.log          # replaces atomically
$ redactscan redact -stdout logs/app.log | less  # REDACT-2 behavior
$ cat logs/app.log | redactscan redact           # stdin still goes to stdout
```

**Scope.**

- File output is the default when FILE is given: `<name>_cleaned<ext>` next to FILE, mode 0600, no clobber.
- `-force` replaces an existing regular destination atomically.
- `-stdout` restores REDACT-2 behavior for FILE.
- Stdin (`-` or no argument) is unchanged and still goes to stdout.
- New `safefs` write function that pins the output directory and binds it to the input's directory.

**Breaking change (user decided, accepted).** `redact FILE` used to print to stdout. Now it writes a file and stdout is empty with exit 0, so `redact f | cmd` and `redact f > out` silently get nothing. ADR 0003 records this.

**Non-goals.**

- `-o PATH` (explicit output path). It can be a later story.
- Signal handling to remove the temp file on SIGINT or SIGTERM.
- `golang.org/x/sys`, `openat2` or `renameat2`.
- Checking `.gitignore` or calling `git check-ignore`. Never shell out.
- Windows and other platforms. They keep `ErrUnsupportedPlatform`; the input open fails first.
- Detecting that FILE is already a `_cleaned` file.
- Fixing the "Sentinel" naming in `docs/architecture.md` (already a separate follow-up).

**Wording.** Help, README and messages never call the output safe, or safe to commit or share. On every file write, stderr gets the fixed note `redactscan: note: output may still contain uncovered secret formats`.

## 2. Functional requirements and acceptance criteria

| ID | Requirement | Acceptance criteria |
| --- | --- | --- |
| FR1 | **Stderr contents superseded by `docs/features/redaction-summary/spec.md` (REDACT-13): `-quiet` and `-json` change what success prints.** `redact FILE` writes `<derived name>` in FILE's directory. | Exit 0. Stdout is empty. The destination contains exactly `Redact(content).Output`, and an empty output gives an empty file. Stderr is `[summary line]` + `redactscan: wrote "<out>"` + the note line, in that order. |
| FR2 | Naming (section 3.4). | Table test: `app.log`→`app_cleaned.log`, `a.2024.log`→`a.2024_cleaned.log`, `x.tar.gz`→`x.tar_cleaned.gz`, `Makefile`→`Makefile_cleaned`, `.env`→`.env_cleaned`, `.env.local`→`.env_cleaned.local`, `.config.yml`→`.config_cleaned.yml`, `x.`→`x_cleaned.`, `..foo`→`..foo_cleaned`, `app_cleaned.log`→`app_cleaned_cleaned.log`. |
| FR3 | The destination is in the directory of the typed input path, which must be the directory the input was read from. | Paths: `app.log` → dir `.`; `/app.log` → dir `/`; `logs/app.log` → dir `logs`. The `<out>` in messages uses the typed spelling (`logs/app_cleaned.log`), never an OS-resolved path. If the directory or the input's entry in it changed between the input open and the write: exit 3, `file changed during write`, nothing created. |
| FR4 | No clobber by default. | Existing destination of any type: exit 3, `cannot write "<out>": already exists (use -force to replace)`. The destination is unchanged and no temp file is left. |
| FR5 | `-force` replaces a regular destination atomically. | Destination replaced, mode 0600, owned by the invoking user. A destination that is a symlink gives `symlink refused` and its target is unchanged. A directory, FIFO, device or socket gives `not a regular file (<type>)`. All are exit 3. |
| FR6 | Output mode is exactly 0600. | Checked under umask 000 and 077, with and without `-force`. The owner is the current uid. |
| FR7 | Nothing is created until `Redact` succeeds. | The directory listing is unchanged after a verifier failure, oversize input, unsupported encoding, open failure or read failure (exits 1 and 3). |
| FR8 | Failure at any point leaves no output file and no temp file. | Injected failures at create temp, write (short write and ENOSPC), sync, close, link and rename: exit 3, fixed reason, destination absent or unchanged, no `.redactscan-*.tmp` left. If temp removal itself fails, stderr adds `redactscan: temporary file may remain` (no name). |
| FR9 | Concurrent runs do not corrupt output. | N parallel runs with different inputs writing the same destination with `-force`: the final file equals exactly one run's full output. Without `-force`, exactly one run succeeds and the others get `already exists`. No temp files remain. |
| FR10 | `-stdout` restores stdout output for FILE. | `redact -stdout FILE` behaves exactly as REDACT-2 FR1/FR7 (one stdout write, nothing on non-zero exit) and creates no file. `redact FILE -stdout` stays a usage error (flags must come before FILE). |
| FR11 | Stdin is unchanged. | `redact`, `redact -` and `redact -stdout -` write stdout as before and create no file. `-force` with stdin or `-stdout` is accepted and has no effect. |
| FR12 | Fixed, quoted messages. | `<in>` and `<out>` are `strconv.Quote`d. A filename with ESC, a newline or U+202E appears escaped. No OS error text, `Readlink` result or resolved path is ever printed. Reasons come from the fixed set in section 3.6. |
| FR13 | Hard-link-less filesystems fail closed. | A link that fails with "not supported" errnos gives exit 3, `no-clobber write not supported on this filesystem`, and no temp left. `-force` (rename) still works there. Covered by an error-injection unit test, plus a manual check if a FAT or exFAT volume is available. |
| FR14 | The success path never removes the destination. | After the link or rename succeeds, a later failure (temp unlink after link, dir fsync) does not remove or alter the destination and does not change exit 0. A failed temp unlink after link prints the "may remain" line. |
| FR15 | Help and README. | Help documents the new default, `-stdout`, `-force`, the naming rule, 0600, "flags before FILE", and exit codes as in section 3.6. The test from REDACT-2 FR13 (no "safe to share" or "safely") still passes, and help does not say the output is safe to commit or share. |

## 3. Technical design

### 3.1 Layout

| File | Change |
| --- | --- |
| `internal/safefs/write_unix.go` (darwin, linux) | New: `WriteSibling` and the test seams `beforeOpenRoot`, `beforeCommit`, `tempName`, `wrapTemp`, `removeEntry`. |
| `internal/safefs/write_other.go` | New: stub returning `ErrUnsupportedPlatform`. |
| `internal/safefs/safefs.go` | Package doc covers input and output. `newOpError` also strips `*os.LinkError` and `*os.SyscallError`. `ErrInvalidName` and `ErrTempNames`. `tempLeft` is a bool result, not a sentinel. |
| `internal/safefs/nofollow_linux.go` | `openNoFollow` handles a path with no components (`"."`, `"/"`) by opening the start directory itself instead of returning `ENOENT`. |
| `internal/safefs/write_unix_test.go`, `spike_darwin_test.go` | New tests (section 10). |
| `internal/cli/redact.go` | Flags, default mode, naming, write call, messages, error mapping. |
| `internal/cli/name.go` | `cleanedName(name string) string`. Product policy stays in `cli`. |
| `internal/cli/cli.go` | Usage text. |
| `internal/cli/cli_test.go` | Existing FILE→stdout tests move to `-stdout` or assert the file. New tests. |
| Docs | README, threat model, ADR 0003, ADR 0002 amended note, redact-command spec superseded note. |

### 3.2 Public API (`internal/safefs`)

```go
// WriteSibling writes data to a new file named outName in the directory that
// holds the input file at inputPath (the path as typed). input is the FileInfo
// of the already-open input descriptor (from f.Stat after OpenRegular).
// outName must be a single path component. With replace false an existing
// outName is never replaced; with replace true a regular file is replaced
// atomically. On error nothing is created or replaced. tempLeft reports that
// the temp file could not be removed (on success or failure).
func WriteSibling(inputPath string, input fs.FileInfo, outName string, data []byte, replace bool) (tempLeft bool, err error)
```

Errors keep the REDACT-10 rules: fixed text, never a path or OS text, unwrapping to a bare `syscall.Errno`.

- `ErrSymlink`: the destination is a symlink (with `replace`).
- `*NotRegularError`: the destination is not a regular file (with `replace`).
- `ErrChanged`: the directory or input binding failed.
- `opError` with the step names `open dir`, `open root`, `lstat`, `create temp`, `chmod`, `write`, `sync`, `close`, `link`, `rename`, wrapping the errno. An existing destination unwraps to `EEXIST` (`fs.ErrExist`).
- `ErrInvalidName`: `outName` is empty, `.` or `..`, or contains `/` or NUL. This is a programming error and maps to "internal error".
- `ErrTempNames`: temp name collisions ran out of retries.

### 3.3 `WriteSibling` algorithm (darwin, linux)

1. **Split the typed path** at the last `/`, with no `filepath.Clean`. There is no slash for `app.log` (dir `.`), the dir is `/` for `/app.log`, and otherwise it is the prefix (`logs//app.log` gives dir `logs/`, which the walk tolerates). The base name must equal the base of the typed input path; an empty base is refused as `ErrInvalidName`.
2. **Open the directory without symlinks.** Apply the same macOS `normalizePath` to the full typed input path before splitting, so `/tmp/x/app.log` uses `/private/tmp/x`. Then call `openNoFollow(dir, O_RDONLY|O_DIRECTORY)` (`O_NOFOLLOW_ANY` on macOS, the `openat` walk on Linux), giving `dirFile`.
3. **Pin the root.** Open the root through the verified descriptor, `os.OpenRoot("/proc/self/fd/<n>")` on Linux and `"/dev/fd/<n>"` on macOS, not through the path: a path would be resolved again, and a directory swapped for a FIFO would block forever. If the fd directory is missing the open fails closed. Still require `os.SameFile(dirFile.Stat(), root.Stat("."))`, otherwise `ErrChanged` (defense in depth).
4. **Bind to the input.** Require `os.SameFile(root.Lstat(base), input)`, otherwise `ErrChanged`. This is a consistency check, not proof: a lookalike directory holding a hard link to the input passes it. The guarantee comes from the no-follow directory open, the pinned descriptor and the re-verify in step 9.
5. **Destination pre-check (UX only).** Call `root.Lstat(outName)`:
   - Missing: continue.
   - Exists and `!replace`: `EEXIST`.
   - Symlink: `ErrSymlink`.
   - Not regular: `NotRegularError`.
   - Regular and `replace`: continue.

   This check is not the guarantee (see 3.5).
6. **Create the temp file.** Use `root.OpenFile(".redactscan-<16 hex from crypto/rand>.tmp", O_WRONLY|O_CREATE|O_EXCL, 0600)`. On `EEXIST`, retry up to 10 times, then `ErrTempNames`. Then call `f.Chmod(0600)` on the open descriptor (not `Root.Chmod` or `os.Chmod`) so umask cannot change the mode.
7. **Write.** `f.Write(data)`, checking the error and that `n == len(data)`; then `f.Sync()` and `f.Close()`, each error checked.
8. **Test hook** `beforeCommit()` (a no-op in production).
9. **Re-verify the directory** (detects a swap of the typed path). Open the directory path again with `openNoFollow`; require `SameFile` with `root.Stat(".")`, else `ErrChanged`. A swap after this point still cannot redirect the output, because every operation goes through the pinned root.
10. **Commit.**
    - `!replace`: `root.Link(temp, outName)` (atomic; `EEXIST` if anything, including a symlink, now exists), then `root.Remove(temp)`. If that remove fails, return `tempLeft=true, err=nil`.
    - `replace`: `root.Rename(temp, outName)`.
11. **Sync the directory.** `dirFile.Sync()`, best effort, error ignored.
12. **Clean up on any error in steps 6-10 before commit:** close the file if open, call `root.Remove(temp)`, and set `tempLeft` if that fails. Never touch `outName` after a successful commit. Always close `dirFile` and `root`.

### 3.4 Naming (`internal/cli/name.go`)

`cleanedName(name)`:

1. Split off any leading dots as a prefix.
2. In the rest, find the last `.`. If there is one, insert `_cleaned` before it; otherwise append `_cleaned`.
3. If the rest is empty (for example `...`), append `_cleaned`.

The CLI derives the typed output path for messages by replacing the base of the typed input path, using the same last-`/` split. Names longer than NAME_MAX (255 bytes) fail at the destination pre-check `lstat` with `ENAMETOOLONG`, which maps to `name too long`. The CLI maps errors by errno or sentinel, never by `opError` step name. The name fails before any temp file exists. Test: a 250-byte input name.

### 3.5 Why the guarantees hold

| Threat | Guarantee |
| --- | --- |
| Partial or raw output | Nothing is created before `Redact` succeeds. The destination appears only through an atomic link or rename of a fully written, fsynced file. |
| Concurrent runs | Each run has its own `O_EXCL` temp file (Verified: Go 1.27.1 `os.CreateTemp` and `Root.OpenFile` pass flags straight to `open`/`openat`). `link` is atomic no-clobber, so exactly one run wins. `rename` is atomic replace, so the last one wins with a whole file. |
| Symlink at the destination | A symlink is refused by the pre-check. One swapped in later: `link` gives `EEXIST` (`link(2)` does not follow newpath), and `rename` replaces the link itself and never writes through it (`rename(2)`). Its target is unchanged. |
| Directory, FIFO or device at the destination | `rename` over a directory fails with `EEXIST` (verified through `Root.Rename`), which `WriteSibling` reports as `ErrChanged` when `replace` is true. A FIFO or device entry is only replaced, never opened. |
| Symlink in a parent directory (static, in content) | The input open (REDACT-10) and the `openNoFollow` directory open both refuse it. |
| Parent directory swapped during the run | The root is pinned to a verified directory descriptor and every create, link, rename and remove is a single-component operation relative to it. The output lands only in the pinned directory; a hard-linked lookalike passes the input binding, so the guarantee is the pin, not the binding. A detected swap is refused with `ErrChanged`. |
| Planted file at the temp name (shared directories: see the accepted risks in section 7) | `O_EXCL` fails with `EEXIST` on any existing entry, including a symlink (Verified; spike S2), so the run retries with a new random name. |
| Umask or inherited mode | `0600` at create time plus `f.Chmod(0600)` on the descriptor. |

**Correction recorded from the security review.** The by-path `rename` fails closed when a parent is swapped. That claim is false: verified on macOS, a by-path rename follows a swapped parent. That is why the root is pinned.

**Why `os.Root` here, when ADR 0002 rejected it.** ADR 0002 rejected `os.Root` for opening input paths, because it follows symlinks within the root across intermediate components. Here the root is pinned to a descriptor that has already been verified symlink-free, and only single-component names are used, so there are no intermediate components. ADR 0003 records this.

### 3.6 CLI (`internal/cli`)

Usage: `redactscan redact [-summary] [-stdout] [-force] [FILE|-]`. Flags must come before FILE.

Flow for FILE without `-stdout`:

1. Open FILE with `safefs.OpenRegular` and keep `fi := f.Stat()`.
2. Do the bounded read (already in `readInput`, extended to return `fi`).
3. Call `Redact`. On failure: exit 1, no file.
4. Compute the output name.
5. Call `safefs.WriteSibling(path, fi, cleanedName(base), out, force)`.
6. On success, print the summary line if requested, then `redactscan: wrote <quoted out>`, then the note line, and exit 0. If `tempLeft`, also print `redactscan: temporary file may remain`.

Write error messages (exit 3) take the form `redactscan: cannot write <quoted out>: <reason>`. Reasons are checked in this order:

| Condition | Reason |
| --- | --- |
| `EEXIST` (pre-check or link, only without `-force`; with `-force` a rename `EEXIST` arrives as `ErrChanged`) | `already exists (use -force to replace)` |
| `ErrSymlink` | `symlink refused` |
| `NotRegularError` | `not a regular file (<type>)` |
| `ErrChanged` | `file changed during write` |
| link step with `EPERM`, `ENOTSUP`/`EOPNOTSUPP` or `EMLINK` | `no-clobber write not supported on this filesystem` (the exact errnos are confirmed by spike S3) |
| `EACCES` or `EPERM` | `permission denied` |
| `ENOSPC` or `EDQUOT` | `no space left` |
| `ENAMETOOLONG` | `name too long` |
| `EROFS` | `read-only filesystem` |
| `ErrUnsupportedPlatform` | `unsupported platform` |
| anything else | `write failed` |

`ErrInvalidName` and `ErrTempNames` map to `write failed`.

Exit codes (unchanged numbers, wider meaning):

- 0: success, or help requested. Stdout is empty in file mode.
- 1: redaction refused. Nothing is written anywhere: no stdout bytes and no file.
- 2: usage error, including a flag after FILE.
- 3: I/O error: open, read, stdout write, or output create, write, link or rename, or a refused destination.

## 4. Data/API changes and migrations

- No data or schema changes.
- CLI contract change: the default output for FILE moves from stdout to a file. This is breaking for scripts. Mitigations: `-stdout` (documented in help and README) and the ADR. There is no compatibility flag beyond `-stdout`.
- Added API: `safefs.WriteSibling`, `ErrInvalidName`, `ErrTempNames`. `OpenRegular` is unchanged.

## 5. Engineering decisions and rationale

| Decision | Rationale | Alternatives rejected |
| --- | --- | --- |
| Default to file output for FILE (user decided, option B). | The user wants a cleaned file next to the original without extra flags. | Opt-in `-w` flag: no breaking change, but not what the user wants. Making `-o` a bool: confusing next to the usual `-o PATH`. |
| Derived name `<stem>_cleaned<ext>` in the input's directory. | User decided. Keeping the extension keeps editors and ignore patterns like `*.log` working. | A user-typed `-o PATH`: deferred. |
| No clobber by default, `-force` to replace (user decided). | Re-running never silently overwrites a file the user may have edited. `link` gives an atomic EEXIST. | Always replace: simpler, but clobbers silently. `O_EXCL` directly on the destination: not atomic with respect to content (a partial file would be visible). |
| Writer in `safefs` as `WriteSibling`. | `safefs` is already the filesystem trust boundary and holds `openNoFollow` and `normalizePath`. | A writer in `cli`: duplicates the no-follow logic and splits the boundary. |
| `os.Root` pinned to a verified directory descriptor. | Gives single-component, descriptor-relative create, link, rename and remove using only the standard library (Verified: `Root.Link`, `Rename`, `Remove`, `Lstat` and `OpenFile` exist in Go 1.27.1 and use `linkat`/`renameat` on Unix). | Raw `syscall.Renameat`: not exported on darwin. `x/sys`: a new dependency. Path-based rename: unsafe under a parent swap. |
| Bind output dir to input via `SameFile(root.Lstat(base), input)`. | Proves the output lands beside the file that was actually read. | Trust the path: open to a race. |
| File output prints `wrote` plus a fixed note on stderr. | The derived path is not obvious, and the user accepted the risk of uncovered formats only with a visible reminder. | Silent success: the user has to guess where the output went. |
| Accept that the derived name may escape ignore and sync rules (user accepted). | Documented in the threat model. Never call `git check-ignore` (it would execute a tool on untrusted repo config). | Refuse when an ignore rule would not match: needs a git parser or exec. |

**ADR 0003** (long-term impact): "Default file output beside the input, written through a pinned `os.Root` with no clobber." It records:

- the breaking change (`redact f | cmd` now gets empty stdout and exit 0)
- the user's acceptance of the ignore-rule and uncovered-formats risk
- `-stdout` and `-force` semantics: no-ops with stdin, and `redact f -stdout` stays a usage error
- why `os.Root` is acceptable here but was rejected in ADR 0002
- that `safefs` now covers output too

ADR 0002 decision 1 gets an "Amended by ADR 0003" note; the decision text itself is not edited.

## 6. Risks and failure modes

| Failure | Behavior |
| --- | --- |
| Redaction refused, open or read error | Exit 1 or 3. Nothing is created (FR7). |
| ENOSPC, EIO, short write, sync or close failure | Exit 3. Temp removed, destination absent or unchanged (FR8). |
| Temp removal fails | Fixed `temporary file may remain` line. The leftover holds redacted bytes only. |
| Destination exists | Exit 3 `already exists` unless `-force`. |
| Directory swapped mid-run | `ErrChanged` (exit 3), or the output lands in the pinned original directory. Never in an attacker's directory. |
| Fatal signal (SIGKILL, SIGINT, SIGTERM, crash) during the write | A hidden `.redactscan-*.tmp` with redacted bytes may remain. Accepted, with no signal handling. |
| Power loss after rename | The directory fsync is best effort, so the rename may be lost; the old destination or nothing remains. Accepted. |
| Hard-link-less filesystem | No-clobber mode fails closed (FR13). `-force` works. |
| Scripts that relied on `redact FILE` printing | They now get empty stdout and exit 0. Accepted breaking change; use `-stdout`. |

## 7. Security

Recommended and done: `security-reviewer` design review (all requirements folded in above). After the PRs land, `security-reviewer` checks that the path-binding and swap tests exist and pass.

- **Trust boundary.** The output directory comes from a path that may be inside untrusted content (a cloned repo or an extracted archive). Writes go only to a directory verified symlink-free and bound to the input's inode.
- **Fail closed.** Every unexpected condition removes the temp file and refuses. There is no fallback to a path-based write.
- **No disclosure.** Messages are built from fixed text and quoted typed paths, never OS text, `Readlink` results or contents. Temp names are random and contain no input name.
- **Permissions.** Mode 0600, owned by the invoking user. A replaced file loses its old mode, owner and hard links (they keep the old content).
- **Accepted and documented in the threat model:**
  - inherited ACLs on macOS or Linux can grant extra access beyond 0600
  - in sticky, world-writable or group-writable directories, other users can create the destination first, so no-clobber refuses (fail closed); pinning still prevents redirection
  - hard links to an old destination keep the old content
  - in a group- or world-writable directory without the sticky bit, another user can rename the closed temp file away and plant their own file under its name before the link or rename; this is equivalent to the accepted "others can pre-create the destination" risk
  - running as root writes a root-owned 0600 file
  - the derived name may not match `.gitignore` or sync rules (`.env` → `.env_cleaned`)
  - uncovered secret formats pass through to the file
- **CI.** No change to workflows or credentials.

## 8. Performance/scalability

There is one extra fsync, one directory open and one root open per run. Data is already in memory (at most 10 MiB plus the redactor's budget). Nothing here is measurable compared with redaction.

## 9. Implementation steps

Two stacked PRs. Estimated size: PR 1 about 400-480 lines (code about 160, tests about 250, docs and ADR about 70); PR 2 about 300-380 lines (code about 90, test churn and new tests about 200, docs about 70). If PR 1's tests push it past about 500 lines, move the spike tests (S1-S3) into a preceding PR 0.

**PR 1: `safefs.WriteSibling`** (no user-visible change)

1. **Spikes as native tests** (no dependencies). Expected result: the behavior is recorded, and the tests stay as regression tests.
   - S1 (macOS): `O_CREAT|O_EXCL|O_NOFOLLOW_ANY` with a symlink at the name gives `EEXIST` or `ELOOP`; a symlinked parent gives `ELOOP`.
   - S2 (both OSes): `Root.OpenFile(O_CREATE|O_EXCL)` on a planted symlink gives `EEXIST`, and `Root.Rename` over a symlink replaces the link.
   - S3: the errno from link on a filesystem without hard links. Run it where available; otherwise record it as Assumed, and the CLI maps the candidate errnos.

   Run on macOS and in `golang:1.27` under Docker.
2. **`newOpError` hardening and `openNoFollow` for `"."` and `"/"`** (depends on 1). Tests: `*os.LinkError` and `*os.SyscallError` unwrap to `syscall.Errno` with no path in the text; `openNoFollow(".")` and `openNoFollow("/")` open the directory.
3. **`WriteSibling` and the other-OS stub** (depends on 2). Tests: section 10, the safefs list.
4. **Docs for PR 1** (depends on 3):
   - `safefs` package doc
   - threat-model "Safe file opening" output controls and accepted risks
   - ADR 0003
   - ADR 0002 amended note

   Run `task verify` and the Linux container run.

**PR 2: CLI default change** (depends on PR 1)

5. **`cleanedName` and output-path derivation.** Tests: the FR2 table, the FR3 path splits, and a 250-byte name.
6. **Flags and flow** (`-stdout`, `-force`, default file mode, `readInput` returns `fi`, messages, error mapping) (depends on 5). Tests: FR1, FR4-FR14 at the CLI level; existing tests updated to `-stdout` or to file assertions.
7. **Help, README, threat-model CLI section, caller constraints, redact-command spec superseded note** (depends on 6). Tests: the FR15 wording test.

   Run `task verify`.

## 10. Testing strategy

All tests use real temp directories (`t.TempDir()`), runtime-built secret-shaped input, and no realistic secrets. Behavior is tested natively on macOS and in `golang:1.27` (Linux), since CI runs no Go tests.

**safefs:**

- Happy path: content, mode 0600 under umask 000 and 077 (set with `syscall.Umask` in a non-parallel test), owner uid, empty data.
- No clobber: an existing regular file, symlink, directory or FIFO gives `EEXIST`, and the destination is unchanged.
- Replace: a regular file is replaced; a symlink gives `ErrSymlink` with its target unchanged; directory, FIFO and device entries give `NotRegularError`.
- The `beforeCommit` hook:
  - (a) Swap in a symlink at the destination. With replace, the link is replaced and the target unchanged; without replace, `EEXIST`.
  - (b) Rename the directory away and put a symlink to another directory in its place: `ErrChanged`, nothing created in the other directory.
  - (c) The same with a real directory that holds a same-named temp file: nothing created or replaced there.
  - (d) Plant a file at the next temp name: retry succeeds.
- Binding: the input path is replaced after its read, so `root.Lstat(base)` is a different inode: `ErrChanged`. A directory path containing a symlink gives `ErrSymlink`.
- Injected failures (write, short write, ENOSPC via an injectable writer seam, sync, close, link, rename): the error, no temp left, `tempLeft` false. A remove failure makes `tempLeft` true.
- Error text has no path, and `errors.Unwrap` gives a `syscall.Errno`.
- Concurrency: 16 goroutines writing the same destination. With replace, the result is one whole output; without replace, exactly one succeeds.
- No descriptor leaks (the existing `/dev/fd` count helper).

**CLI:**

- FR1-FR15 as listed, including the stderr order with `-summary`, ESC, newline and U+202E filenames quoted, a directory listing unchanged after exits 1 and 3, `-stdout` with FILE, stdin, `-force` as a no-op with stdin, and a flag after FILE as a usage error.

**Regression:** the REDACT-2 and REDACT-10 behaviors (refusals, exit codes, stdin) keep passing via `-stdout` or stdin.

**Break-the-guard (manual, then revert):**

- Remove the root `SameFile` check: the swap test fails.
- Remove `f.Chmod`: the umask 000 test fails.
- Replace `Link` with `Rename`: the no-clobber race test fails.
- Remove temp cleanup: the injected-failure tests fail.

## 11. Observability, deployment, rollback

- **Observability.** CLI only: fixed stderr lines. No logging of paths beyond the quoted typed paths, and never contents.
- **Deployment.** Merge PR 1, then PR 2. Release notes call out the breaking default change and `-stdout`.
- **Rollback.** Revert PR 2 to restore stdout behavior; PR 1 is unused API on its own. There is no migration.

## 12. Definition of done

- FR1-FR15 pass. `task test` passes during development, and `task verify` (fmt, lint, test, cross, security, secrets) succeeds before each PR is marked ready.
- The Linux container run passes: `docker run --rm -v "$PWD":/src -w /src golang:1.27 go test ./...`.
- Spike results S1-S3 are recorded as Verified or Assumed in the spec or ADR 0003.
- The docs are updated:
  - `docs/threat-model.md`: caller constraints, Safe file opening, the CLI section, and replacing the "`-o` not implemented" line
  - ADR 0003, plus the ADR 0002 amended note
  - README and help
  - the `docs/features/redact-command/spec.md` FR1/FR7 superseded note
- `staff-engineering-reviewer` and `security-reviewer` pass on each PR, and `security-reviewer` confirms the path-binding tests.
- PRs use the template, link REDACT-11, this spec and ADR 0003, and call out the breaking change.

## 13. YouTrack REDACT-11 text updates

- **Title:** "Write redacted output to `<name>_cleaned<ext>` next to the input, atomically and without clobbering".
- **Story:** "As a user, I want `redactscan redact FILE` to write a cleaned copy next to FILE only after redaction succeeds, so that a failure never leaves partial or raw output."
- **Scope:**
  - default file output for FILE
  - `-stdout` for the old behavior and `-force` to replace
  - a 0600 temp file in the input's directory (pinned and bound to the input), fsync, then atomic link (no clobber) or rename (`-force`)
  - refuse a symlink or non-regular destination
  - remove the temp file on every error path
  - stdin unchanged
- **Acceptance criteria:** keep the original four, and add:
  - the naming examples (FR2)
  - an existing destination is refused without `-force`
  - `-stdout` restores stdout
  - stdin is unchanged
  - stderr gets `wrote` plus the uncovered-formats note
  - the breaking change is documented
- **Size:** about 700-850 changed lines in 2 stacked PRs (each under 500).
