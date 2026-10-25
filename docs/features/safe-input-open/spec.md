# Safe input opening: spec

Status: approved design; PR 1 and PR 2 implemented.
Story: [REDACT-10](http://localhost:8080/issue/REDACT-10) "Safe input file opening". Depends on REDACT-2 (merged: `redactscan redact`, the `openInput` seam in `internal/cli/redact.go`).
Branch: `feat/redact-10-safe-input-open`. Delivered as two stacked PRs (PR 1, PR 2; see section 9).
Packages: new `internal/safefs`; small change to `internal/cli`; `Taskfile.yml`. Go standard library only, no new dependency.
Related: `docs/threat-model.md` "Constraints for callers" and CLI "Accepted risks"; `docs/features/redact-command/spec.md` section 3.3; ADR 0001. New ADR 0002 (PR 2).
Design reviewed by `security-reviewer` (findings R1-R4 and minor items are incorporated below).

> Spec text and tests never contain realistic secret values. Tests build secret-shaped input at runtime.

## 1. Feature overview

**Purpose.** `redactscan redact FILE` must never be redirected or hung by the file it is given. Today `openInput` is a plain `os.Open`: a symlink is followed (so a file inside a cloned repo can point at `~/.aws/credentials` or `/proc/self/environ`, whose uncovered formats pass through), a FIFO with no writer blocks forever, and a device is read. This story replaces it with `safefs.OpenRegular`, which opens only a regular file reached without any symlink, and refuses everything else with a clear, fixed error.

**In scope**

- New package `internal/safefs` with `OpenRegular(path string) (*os.File, error)` and typed errors.
- PR 1: final-component protection (`Lstat`, `O_NOFOLLOW`, post-open `Fstat` identity check), file-type refusal, non-blocking open then blocking mode restored, fixed error text, unsupported-platform stub, CLI wiring, cross-OS build check in `task verify`.
- PR 2: full-path protection (no symlink in any component the user typed): `O_NOFOLLOW_ANY` on macOS, an `openat` component walk on Linux, plus a run-time-checked macOS allowlist for the root-owned system links `/tmp`, `/var`, `/etc`. Threat model update and ADR 0002.
- Supported platforms: macOS (`darwin`) and Linux. Every other GOOS gets `ErrUnsupportedPlatform`; there is no plain-open fallback.

**Non-goals**

- Stdin checks. A pipe or redirected file on stdin is the user's own choice and is read as today (bounded).
- Windows support (reparse points, file IDs). Separate story if needed.
- Confining paths to a root directory (`os.Root`), and any flag to allow symlinks.
- Detecting hard links (`nlink > 1`); a hard link to a regular file is a regular file.
- Protecting the current working directory or anything above it for relative paths (the kernel already resolved it).
- `-o` output files; directory or repository scanning; quarantine.

## 2. Functional requirements and acceptance criteria

All tests use real temp files, real symlinks and real FIFOs. Every refusal leaves stdout empty and exits 3.

| ID | Requirement | Acceptance | PR |
| --- | --- | --- | --- |
| FR1 | A regular file opens and is fully readable. | `OpenRegular` returns a file; reading a 1 MiB file (above 64 KiB, within 10 MiB) returns all bytes; `redact FILE` still works (existing tests pass). | 1 |
| FR2 | A symlink as the final component is refused, whatever it points to (file, dir, dangling). | `errors.Is(err, ErrSymlink)`; CLI: `cannot open "P": symlink refused`. | 1 |
| FR3 | A directory, FIFO, character or block device and socket are refused. | `errors.As(err, &nre)` with `nre.Type` = `directory`, `fifo`, `device`, `socket`; `errors.Is(err, ErrNotRegular)`; CLI: `cannot open "P": not a regular file (fifo)` etc. `/dev/null` is the device fixture. | 1 |
| FR4 | A FIFO never blocks, whether present at `Lstat` time or swapped in after it. | FIFO tests complete within a 2 s timeout with no writer attached. | 1 |
| FR5 | A file swapped after `Lstat` is refused. | Via the test hook: swap to a symlink gives `ErrSymlink`; swap to another regular file gives `ErrChanged`; swap to a FIFO gives `ErrChanged` and does not block. Optional: swap to a hard link of `/dev/null` gives `ErrChanged` (test skips when `os.Link` fails, e.g. `EXDEV`). | 1 |
| FR6 | The returned file is in blocking mode. | Test reads `F_GETFL` through `f.SyscallConn().Control` and asserts `O_NONBLOCK` is clear. | 1 |
| FR7 | No file descriptor leaks on any path. | Count `/dev/fd` entries before and after 20 iterations of each refusal (symlink, each file type, each swap case, missing file); counts equal. Successful opens are closed by the caller (`defer` in CLI, unchanged). | 1 |
| FR8 | Error text never includes file contents, the path, or OS error text. | For every refusal and for missing / permission-denied: `err.Error()` does not contain the temp path, a marker string written into the file, or the `syscall.Errno` text (`"no such file"`, `"permission denied"`, `"too many levels"`). | 1 |
| FR9 | OS errors stay inspectable. | `errors.Is(err, fs.ErrNotExist)` and `errors.Is(err, fs.ErrPermission)` hold for missing and unreadable files; CLI messages `not found` / `permission denied` unchanged. | 1 |
| FR10 | Non-macOS, non-Linux builds compile and refuse. | `GOOS=windows go build ./...` succeeds in `task verify`; the stub returns `ErrUnsupportedPlatform`; CLI: `cannot open "P": unsupported platform`. | 1 |
| FR11 | A symlink in any directory component the user typed is refused. | `dir/link-to-dir/file` where `link-to-dir` is a symlink gives `ErrSymlink`, for absolute and relative paths; `link-to-dir/../file` also refused. | 2 |
| FR12 | Relative paths are checked from the current directory only. | With cwd set (in-test `t.Chdir`) to a directory reached through a symlink, `OpenRegular("file")` succeeds; `OpenRegular("sub/file")` where `sub` is a symlink is refused. | 2 |
| FR13 | macOS: absolute paths through `/tmp`, `/var`, `/etc` work. | On darwin, `OpenRegular` on a file under raw `t.TempDir()` (`/var/folders/...`) and under `/tmp/...` succeeds; a user-made symlink beneath them is still refused. | 2 |
| FR14 | The macOS allowlist is exact and checked at run time. | Unit test of the prefix rule with an injected check: rewrites only `/tmp/`, `/var/`, `/etc/` prefixes to `/private/...`, and only when the check passes; `/tmpx/a`, `//tmp/a`, `/./tmp/a`, `/private/tmp/a` are left unchanged. | 2 |

## 3. Technical design

### 3.1 Layout

```
internal/safefs/
  safefs.go           all platforms: package doc, errors, FileType, NotRegularError, opError, test hook
  open_unix.go        //go:build darwin || linux   OpenRegular
  open_other.go       //go:build !darwin && !linux  OpenRegular -> ErrUnsupportedPlatform
  nofollow_darwin.go  PR 2: O_NOFOLLOW_ANY open + system-prefix rule
  nofollow_linux.go   PR 2: openat component walk
  safefs_test.go      //go:build darwin || linux
  nofollow_darwin_test.go, fullpath_test.go   PR 2
internal/cli/redact.go   openInput -> safefs.OpenRegular; openReason extended
```

Build tags are exact complements (`darwin || linux` and `!darwin && !linux`) so every GOOS compiles exactly one `OpenRegular`. In PR 1 the unix-only open helper `openNoFollow(path, flags)` lives in `open_unix.go` and is `os.OpenFile(path, flags, 0)`; PR 2 moves it into per-OS files with full-path behavior, leaving `OpenRegular` unchanged.

### 3.2 Public API (`internal/safefs`)

```go
var (
    ErrSymlink             = errors.New("safefs: symlink refused")
    ErrNotRegular          = errors.New("safefs: not a regular file")
    ErrChanged             = errors.New("safefs: file changed during open")
    ErrUnsupportedPlatform = errors.New("safefs: unsupported platform")
)

type FileType string // closed set
const (
    TypeDirectory FileType = "directory"
    TypeFIFO      FileType = "fifo"
    TypeDevice    FileType = "device"    // character and block
    TypeSocket    FileType = "socket"
    TypeIrregular FileType = "irregular" // any other non-regular mode
)

// NotRegularError matches ErrNotRegular with errors.Is.
type NotRegularError struct{ Type FileType }
func (e *NotRegularError) Error() string        // "safefs: not a regular file (" + Type + ")"
func (e *NotRegularError) Is(target error) bool // target == ErrNotRegular

// OpenRegular opens path read-only. It returns a blocking *os.File only when
// path names a regular file reached without following a symlink. The caller
// closes the file.
func OpenRegular(path string) (*os.File, error)
```

Unexported:

```go
// opError has fixed text per step and unwraps to the bare syscall.Errno
// (never the *fs.PathError, which carries the path).
type opError struct {
    op  string // "lstat", "open", "fstat", "set blocking"
    err error  // syscall.Errno, or the original error if it is not a PathError
}
func (e *opError) Error() string { return "safefs: " + e.op + " failed" }
func (e *opError) Unwrap() error { return e.err }

// afterLstat runs between Lstat and open. Tests in this package replace it to
// swap the file on disk; production never changes it.
var afterLstat = func() {}
```

`syscall.Errno` implements `Is(fs.ErrNotExist)` and `Is(fs.ErrPermission)`, so FR9 holds (Verified: Go stdlib `syscall.Errno.Is`, Go 1.27.1 source).

### 3.3 `OpenRegular` (darwin, linux)

```text
1. fi, err := os.Lstat(path)               err -> opError{"lstat"}
2. fi is symlink                            -> ErrSymlink
   fi not regular                           -> NotRegularError{fileType(fi.Mode())}
3. afterLstat()
4. f, err := openNoFollow(path, O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY)
       errors.Is(err, syscall.ELOOP)        -> ErrSymlink
       other err                            -> opError{"open"}
5. st, err := f.Stat()                      err -> close; opError{"fstat"}
6. !os.SameFile(fi, st)                     -> close; ErrChanged
   !st.Mode().IsRegular()                   -> close; NotRegularError{fileType(st.Mode())}
7. f.SyscallConn().Control(fd -> syscall.SetNonblock(fd, false))
       any error                            -> close; opError{"set blocking"}
8. return f
```

- Type checks happen before any read. Nothing is read inside `safefs`.
- `O_NONBLOCK` makes opening a FIFO (swapped in after step 1) return immediately instead of waiting for a writer; for regular files it does not affect `open`. `O_NOCTTY` stops a terminal device from becoming the controlling terminal. `os.OpenFile` adds `O_CLOEXEC` itself.
- Identity check comes before the type check so every swap reports `ErrChanged`.
- Step 7 is required: **Verified** (Go 1.27.1 `src/os/file_unix.go`, `newFile`): when `O_NONBLOCK` is in the open flags Go records `nonBlocking=true`, does not set non-blocking mode itself, and therefore never clears it; on Linux epoll registration of a regular file fails and on darwin regular files are not registered with kqueue, so the descriptor stays `O_NONBLOCK` with no poller. Clearing it makes reads plain blocking reads. Use `SyscallConn().Control`, never `f.Fd()` (which changes the file's mode handling).
- `fileType`: `ModeDir` -> directory, `ModeNamedPipe` -> fifo, `ModeDevice` or `ModeCharDevice` -> device, `ModeSocket` -> socket, anything else non-regular -> irregular.
- The path passed to `os.OpenFile` carries `// #nosec G304 -- path is validated by Lstat, O_NOFOLLOW and the Fstat identity check`.

### 3.4 Full-path protection (PR 2)

`openNoFollow` refuses a symlink in any component of the path as typed. For a relative path the components are those after the current directory; the cwd itself is not re-checked.

**macOS (`nofollow_darwin.go`).**

```go
// O_NOFOLLOW_ANY: no symlinks allowed in path (macOS 11+). Not exported by syscall.
const oNofollowAny = 0x20000000

func openNoFollow(path string, flags int) (*os.File, error) {
    return os.OpenFile(path, flags&^syscall.O_NOFOLLOW|oNofollowAny, 0)
}
// OpenRegular calls normalizePath(path) = systemPath(path, trustedSystemLink) first.
```

- **Verified**: `O_NOFOLLOW_ANY` is `0x20000000` in the macOS SDK `sys/fcntl.h` (line 158, "no symlinks allowed in path") and in `golang.org/x/sys/unix` v0.47.0 `zerrors_darwin_arm64.go`. Go's `syscall` does not export it, so `safefs` defines it (no `x/sys` dependency).
- **Assumed** (asserted by FR11/FR12 tests): the refusal errno is `ELOOP`; a relative path is resolved from the cwd without re-checking the cwd; Go's minimum supported macOS includes `O_NOFOLLOW_ANY` (macOS 11+; older kernels not verified). **Verified**: passing `O_NOFOLLOW` together with `O_NOFOLLOW_ANY` fails with `EINVAL`, so the open clears `O_NOFOLLOW`.
- `os.Lstat` in step 1 is also given `systemPath(path)`, so `Lstat` and `open` see the same path.

**macOS system-link rule.** `/tmp`, `/var` and `/etc` are symlinks to `private/tmp`, `private/var`, `private/etc`, and `$TMPDIR` / `t.TempDir()` live under `/var/folders`. `systemPath(path, check)`:

- Matches only the literal prefixes `/tmp/`, `/var/`, `/etc/` (no `Clean`, no other spellings).
- Calls `check(name)`, which requires, at run time: `os.Lstat("/"+name)` is a symlink, its `Stat_t.Uid == 0`, and `os.Readlink("/"+name) == "private/"+name`.
- If both hold, returns `"/private/" + name + rest`; otherwise returns `path` unchanged, and the open then refuses it with `ErrSymlink`.
- `rest` is still checked by `O_NOFOLLOW_ANY`. Entries in `/` are writable only by root, and links made by a user or a cloned repo are owned by that user, so the rule cannot be used to smuggle a link.
- `check` is a parameter only so the matching logic is unit-testable (FR14); production always passes `trustedSystemLink`.

**Linux (`nofollow_linux.go`).**

```text
start := "/" if path is absolute else "."
dirfd := syscall.Open(start, O_RDONLY|O_DIRECTORY|O_CLOEXEC, 0)
parts := split path on "/", drop "" and "."      (".." is kept)
for each part except the last:
    next := syscall.Openat(dirfd, part, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC, 0)
    close(dirfd); dirfd = next            ELOOP, or ENOTDIR + Lstat symlink -> ErrSymlink; other -> opError{"open"}
fd := syscall.Openat(dirfd, last, flags|O_CLOEXEC, 0); close(dirfd)
return os.NewFile(uintptr(fd), path)
```

- **Verified** (Go 1.27.1 source): `syscall.Openat` is exported on Linux; `AT_FDCWD` is not, hence opening `"."`. On darwin `openat` is unexported, which is why macOS uses the flag instead.
- `openat2(RESOLVE_NO_SYMLINKS)` is not used: it needs `golang.org/x/sys` or hand-written per-arch syscall numbers.
- `".."` is opened like any component; `..` is never a symlink, and the component before it was already checked, so `link/../x` is refused at `link`.
- Directories need read permission to be opened `O_RDONLY`; a search-only (`--x`) directory fails with permission denied. Accepted (fail closed).
- **Verified** (golang:1.27 container): a symlinked directory opened with `O_DIRECTORY|O_NOFOLLOW` fails with `ENOTDIR`, not `ELOOP`. The walk classifies it with `syscall.Lstat` of the typed prefix (`Fstatat` is not exported on every Linux architecture) so FR11 reports `ErrSymlink`; a race can only change which refusal is reported. The raw `Open`/`Openat` calls retry on `EINTR`.
- **Accepted**: the pre-open `os.Lstat` resolves symlinked parents, so metadata traversal (autofs, NFS, FUSE) can occur before the refusal, and a dangling symlinked parent may report `cannot open`.
- Every intermediate descriptor is closed on every path (FR7 covers the walk).
- `os.NewFile` with an `O_NONBLOCK` descriptor follows the same `newFile` logic as 3.3, so step 7 still clears it.
- No Linux special case for `/proc`: `/proc/self` is a symlink, so `/proc/self/...` is refused.

### 3.5 CLI wiring (`internal/cli/redact.go`)

- `openInput(path)` returns `safefs.OpenRegular(path)`; the `#nosec` comment and the "REDACT-10" doc comment are removed.
- `openReason` order (R2): `ErrSymlink` -> `symlink refused`; `errors.As(&NotRegularError)` -> `not a regular file (TYPE)` (plain `ErrNotRegular` -> `not a regular file`); `ErrChanged` -> `file changed during open`; `ErrUnsupportedPlatform` -> `unsupported platform`; `fs.ErrNotExist` -> `not found`; `fs.ErrPermission` -> `permission denied`; default -> `cannot open`.
- Message format unchanged: `redactscan: cannot open "PATH": REASON`, exit 3, path via `strconv.Quote`. `err.Error()` is still never printed.
- A directory now fails at open (`not a regular file (directory)`) instead of at read; the existing directory case in `TestRedactIOErrors` is updated.
- Help text: PR 1 adds "FILE must be a regular file; a symlink is refused." PR 2 changes it to "FILE must be a regular file reached without symlinks (on macOS the system links /tmp, /var and /etc are allowed)."

### 3.6 Behavior summary for users

| Input | Result |
| --- | --- |
| `redact app.log`, regular file | Redacted output, exit 0. |
| `redact link.log` (symlink) | `cannot open "link.log": symlink refused`, exit 3. |
| `redact logs/app.log`, `logs` is a symlink | PR 1: opened. PR 2: `symlink refused`. |
| `redact /tmp/app.log` on macOS | Works (system-link rule). |
| `redact some/dir`, FIFO, `/dev/zero`, socket | `not a regular file (directory / fifo / device / socket)`. |
| `redact - < anything` or a pipe | Stdin read as today. |

## 4. Data/API changes and migrations

- New internal package API (3.2). No persisted data, no migrations, no config.
- CLI contract: exit codes unchanged; new stderr reasons; inputs that previously worked through a symlink are refused (intended). Directory errors move from "cannot read" to "cannot open".
- `Taskfile.yml`: new `cross` task, run by `verify`: `GOOS=windows go vet ./...`, `GOOS=linux go vet ./...` (also `GOARCH=amd64`, `arm64` and `386`), `GOOS=freebsd go vet ./...` (catches build errors in files that never compile on the developer's macOS).

## 5. Engineering decisions and rationale

| Decision | Rationale | Alternatives rejected |
| --- | --- | --- |
| Full-path protection, delivered as PR 2 on top of final-component protection in PR 1 | A symlinked parent in a cloned repo reopens the disclosure the threat model names (R4). Splitting keeps each PR under ~500 lines and lands the FIFO/device/race fixes first. | Final component only (leaves R4 open); one large PR (~600 lines). |
| macOS: `O_NOFOLLOW_ANY`; Linux: `openat` walk | One kernel-enforced call on macOS; stdlib-only on Linux. No new dependency. | `golang.org/x/sys` for `openat2` / darwin `openat` (new dependency); `os.Root` (confines but follows in-root symlinks, changes path contract). |
| macOS allowlist of exactly `/tmp`, `/var`, `/etc`, verified root-owned with exact targets at run time | Keeps everyday macOS paths and `$TMPDIR` working; links in `/` are root-only. | Refuse them (surprising, breaks pasted `$TMPDIR` paths); trust any root-owned link (needs a user-space resolver, much more code). |
| macOS and Linux only; other OSes refuse | Smallest fail-closed option; testable locally. | Windows implementation (doubles code, no Windows CI); no stub (breaks other builds). |
| Specific fixed errors, exit 3 | Clear messages, tests can assert the branch, REDACT-2 exit contract unchanged. | New exit code; one generic error. |
| Errors carry no path or OS text; unwrap to bare `Errno` | Error text is safe even if a future caller prints it (R2). | Returning `*fs.PathError` (contains the path and OS text). |
| Unexported `afterLstat` hook | Only deterministic way to test the swap on the production code path. | Split entry point; race loop. |
| Clear `O_NONBLOCK` before returning | Go never clears it (Verified); callers expect blocking reads (R1). | Leave it (risk of `EAGAIN` on unusual filesystems and surprising semantics). |

**ADR 0002** (PR 2): "`safefs` is the filesystem trust boundary for input files: regular files only, no symlink in any typed component, macOS system-link allowlist, macOS/Linux only." Long-term impact: the future scanner and quarantine work reuse it.

## 6. Risks and failure modes

| Risk / failure | Handling |
| --- | --- |
| Symlinked parent directory (PR 1 only) | Closed by PR 2; stated as a temporary accepted risk in the threat model between the PRs. |
| A different file swapped in during the open | `O_NOFOLLOW` (plus `O_NOFOLLOW_ANY` / walk in PR 2) and the `os.SameFile` check; `ErrChanged`. |
| FIFO hang | `O_NONBLOCK` open; FIFO refused before any read. |
| Hard link to a sensitive file | Accepted: it is a regular file and is not detected. Creating one needs only search permission on the target's directories, write permission on the destination directory and the same filesystem (macOS has no `protected_hardlinks`); the file is still read only with the invoking user's permissions. |
| File contents change after open (append, truncate) | Accepted; the 10 MiB bounded read still applies. |
| Regular file on a network/FUSE filesystem blocks on read | Accepted; out of scope. |
| Linux errno behavior differs from assumptions (`ELOOP` vs `ENOTDIR`) | Fails closed regardless; Linux container test run catches it (section 10). |
| macOS allowlist check fails (unusual system layout) | No rewrite; path refused with `symlink refused`; user can pass `/private/...` or a relative path. |
| Search-only directories in the path (Linux walk) | Refused with permission denied (fail closed). |
| fd leak on an error path | FR7 tests on every refusal path, including the walk. |
| Test hook misused | Unexported; no-op by default; hook tests do not use `t.Parallel` and restore it with `t.Cleanup`. |

## 7. Security

- Trust boundary: the path is user-supplied; the file it names and every directory on the way may be attacker-controlled (cloned repos, extracted archives).
- Fail closed: any unexpected condition (stat failure, identity mismatch, mode change, `SetNonblock` failure, unsupported OS) refuses the open and closes any descriptor.
- No contents are read before all checks pass; `safefs` reads nothing.
- Error text is fixed; no path, contents or OS text in `Error()`; the CLI still prints only its own messages.
- No new dependency. `gosec` G304 is annotated with the validation that justifies it.
- `security-reviewer` re-reviews the diff of each PR (file/path handling, symlinks).

## 8. Performance/scalability

Negligible: one `lstat`, one `open`, one `fstat`, one `fcntl`; PR 2 on Linux adds one `openat` and `close` per path component. Single input file per run.

## 9. Implementation steps

Two stacked PRs. PR 2 branches from PR 1. Estimated size: PR 1 about 450 changed lines including tests, PR 2 about 250 plus docs.

**PR 1: final-component safe open**

1. **`safefs` errors and types (all platforms).** `safefs.go`, `open_other.go`. Depends on nothing. Expected: package compiles on every GOOS. Tests: `NotRegularError` matches `ErrNotRegular`; `opError` text is fixed and `errors.Is(fs.ErrNotExist)` works through it; `fileType` mapping table.
2. **`OpenRegular` for darwin/linux.** `open_unix.go` per 3.3. Depends on 1. Tests (`safefs_test.go`, real temp files): FR1-FR9, including FIFO timeouts, `/dev/null`, a Unix socket made with `net.Listen("unix", ...)` in a short temp path, the hook-driven swaps, `F_GETFL`, 1 MiB read, `/dev/fd` leak counts, and error-text checks. **Assumed**: reading `F_GETFL` in tests via `syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)` works on both OSes; if not, use a per-OS test helper.
3. **CLI wiring.** `internal/cli/redact.go` per 3.5 and the PR 1 help sentence. Depends on 2. Tests (`cli_test.go`): one case per refusal (symlink, directory, FIFO, `/dev/null`, swap not needed here) asserting exit 3, exact stderr and empty stdout; updated directory case; mapping-order test for `openReason` with wrapped errors.
4. **Cross-OS build check.** `Taskfile.yml` `cross` task, added to `verify`. Depends on 1. Expected: `task verify` runs it and passes.
5. **Docs for PR 1.** `docs/threat-model.md`: new `## Safe file opening (internal/safefs)` section (controls, typed errors, platforms); CLI "Accepted risks" replaces "Unsafe file opening until REDACT-10" with "Symlinked parent directories are followed until REDACT-10 PR 2"; mark the "Open only regular files" constraint as met for the final component. Depends on 2-3.

**PR 2: full-path protection**

6. **Linux walk.** `nofollow_linux.go` per 3.4; move PR 1's `openNoFollow` out of `open_unix.go`. Depends on PR 1. Tests (`fullpath_test.go`): FR11, FR12, `..` handling, fd leak on walk failures.
7. **macOS `O_NOFOLLOW_ANY` and system-link rule.** `nofollow_darwin.go`. Depends on PR 1. Tests (`nofollow_darwin_test.go`): FR11-FR14, including raw `t.TempDir()` and `/tmp` success and the injected-check unit table.
8. **CLI help and tests.** PR 2 help sentence; CLI test for a symlinked parent directory (exit 3, `symlink refused`). Depends on 6-7.
9. **Docs and ADR.** `docs/threat-model.md`: remove the temporary parent-directory risk; record the macOS allowlist, the relative-path/cwd rule, Unix-only support, and the accepted risks in section 6. `docs/adr/0002-safe-input-open.md`. `docs/features/redact-command/spec.md` is left as historical. Depends on 6-8.

## 10. Testing strategy

- Unit and integration tests in `internal/safefs` with real files, symlinks, FIFOs (`syscall.Mkfifo`), a Unix socket, `/dev/null`, and `t.TempDir()`. Tests that need a symlink-free base use `filepath.EvalSymlinks(t.TempDir())`; FR13 deliberately uses the raw path.
- Hook tests: no `t.Parallel`; set `afterLstat` and restore it in `t.Cleanup`.
- Blocking-risk tests (FIFO) run the call in a goroutine and fail after 2 s.
- CLI tests through `cli.Run` with buffers: exit code, exact stderr, empty stdout.
- Error-text regression: marker content, temp path and Errno text never appear in `err.Error()` or in CLI stderr.
- Linux coverage: CI runs no Go tests today and development is on macOS, so before each PR is marked ready run `go test ./...` in a Linux container, for example `docker run --rm -v "$PWD":/src -w /src golang:1.27 go test ./...`, and record the result in the PR. `task cross` only proves Linux compiles.
- Skip conditions: permission tests skip as root; the hard-link-to-`/dev/null` test skips when `os.Link` fails.
- Break-the-guard check (manual, then revert): remove the `SameFile` check, the `ELOOP` mapping, the `SetNonblock` step and (PR 2) `oNofollowAny`; confirm the corresponding tests fail.

## 11. Observability, deployment, rollback

- No logging (consistent with the CLI). The stderr reason is the only signal.
- No flags or migrations. Rollback is reverting the PR; PR 2 can be reverted alone, returning to final-component protection.

## 12. Definition of done

- FR1-FR10 (PR 1) and FR11-FR14 (PR 2) covered by passing tests.
- `task test` during development; `task verify` (fmt, lint, test, cross, gosec, govulncheck, gitleaks) passes before each PR is marked ready.
- Linux container test run passes and is noted in the PR.
- `docs/threat-model.md` updated in both PRs; ADR 0002 added in PR 2.
- Each PR uses `.github/pull_request_template.md`, links REDACT-10, this spec and (PR 2) ADR 0002, and lists manual steps: `redact` on a symlink, a FIFO (`mkfifo`, must not hang), `/dev/null`, a directory, a symlinked parent (PR 2), and `/tmp/...` on macOS (PR 2), with expected stderr and `echo $?` = 3 (0 for `/tmp/...`).
- `staff-engineering-reviewer` and `security-reviewer` pass on each PR.
