# Live log source: `LogSource` interface and `FileSource`: spec

Status: approved design. The user approved it after the `security-reviewer` design review. Requirements R1 to R11 are incorporated, with the user's decisions on F5/R7 (owner and link-count checks on reopen) and F7/R8 (a single marker per over-cap line).
Story: [REDACT-65](http://localhost:8080/issue/REDACT-65) "LogSource interface and FileSource with rotation handling". Depends on REDACT-10 (merged: `internal/safefs`, ADR 0002).
Branch: `feat/redact-65-file-log-source`. Delivered as three stacked PRs (section 9). The estimate is well over the story's 500-line split point.
Packages: new `internal/logs`, plus one small exported helper in `internal/safefs`. Go standard library only, no new dependency.
Related: `docs/architecture.md` section 15; `docs/threat-model.md`; ADR 0002. New ADR 0005 (PR 1).
Visual plan: `plans/file-log-source/plan.mdx`.

> Spec text and tests never contain realistic secret values. Tests build any secret-shaped input at runtime.

## 1. Feature overview

**Purpose.** This story adds the first live log adapter from architecture section 15. `FileSource` follows a log file, like `tail -F`, and delivers it as a stream of complete lines. The stream is the input for a later redaction pipeline and, after that, for an MCP buffer. Everything about the file is untrusted: its content, its line lengths, and whatever appears at its path after rotation (a symlink to `~/.ssh/id_ed25519`, a FIFO, someone else's file, a hard link). The adapter must keep memory bounded and never hang. It must never emit a fragment of a line, so a secret cannot be split across what the redactor later sees. It must also never reopen anything except a safe regular file with the same owner.

**Concrete example.** A caller runs `src, _ := logs.NewFileSource("app", "/var/log/app/app.log", logs.FileOptions{})` and then `ch, err := src.Read(ctx, logs.Query{})`. The stream starts at the current end of the file:

- Each newly appended complete line arrives as `LogEntry{Source: "app", Line: <bytes without "\n">}`.
- For a 3 MiB JSON line, the entry is `LogEntry{Source: "app", Truncated: true, Dropped: 65537}`, sent as soon as the cap is crossed. The rest of the line is discarded silently, and no byte of it is ever emitted.
- logrotate renames `app.log` and creates a new one. The source finishes the old file (up to its size when the rotation was detected), reopens the path with `safefs.OpenRegular`, checks that the new file has the same owner and exactly one link, and carries on from offset 0.
- If an attacker plants `app.log -> ~/.ssh/id_ed25519` at rotation, the reopen fails with `safefs.ErrSymlink`. The source sends one final `LogEntry{Err: safefs.ErrSymlink}` and closes the channel.
- When the caller cancels `ctx`, the channel closes and the goroutine exits.

**In scope**

- `internal/logs`: the `LogSource` interface, `Query`, `LogEntry`, and the stream contract.
- `FileSource`, `FileOptions`, `NewFileSource` with validation.
- Line assembly with a cap and drop markers.
- Start position (end of file or `FromStart`).
- Polling for growth, truncation and rotation; bounded drain; fail-closed reopen with owner and link-count checks.
- Fixed-text errors.
- `internal/safefs`: export the existing path-stripping step as `StripPath`, so `logs` can build its own error type without copying it.
- ADR 0005, the `docs/threat-model.md` section "Live log sources (`internal/logs`)", and a note in `docs/architecture.md` section 15.

**Non-goals**

- A CLI command, and any call to the redactor inside the adapter. The adapter emits raw lines; the redaction pipeline is a later story.
- MCP, a ring buffer or index, search, last-N lines, a no-follow (read-to-EOF) mode.
- fsnotify, inotify, kqueue, or polling backoff.
- Other adapters (stdout, Docker, Kubernetes, journald).
- Glob or directory sources, and following several files.
- Character-set handling. Bytes are passed through apart from removing the trailing `\n`.
- Windows and other non-Unix platforms: `safefs.OpenRegular` returns `ErrUnsupportedPlatform`, so `Read` does too.

## 2. Functional requirements and acceptance criteria

| ID | Requirement | Acceptance criteria |
| --- | --- | --- |
| FR1 | Interface per architecture section 15. | `type LogSource interface { Name() string; Read(ctx context.Context, q Query) (<-chan LogEntry, error) }`. `*FileSource` satisfies it (compile-time assertion). |
| FR2 | Stream contract. | The channel is unbuffered. It is always closed eventually, after cancellation or after a fatal error. Only the last entry may have a non-nil `Err`; such an entry has nil `Line`, `Truncated` false and `Dropped` 0. The channel closes without an `Err` entry only when `ctx` is done. Every send selects on `ctx.Done()`. |
| FR3 | Construction validation (R3, R9). | `NewFileSource(name, path, opts)` returns `ErrInvalidOptions` before any I/O when: `name` is empty, longer than 128 bytes, not valid UTF-8, or contains a control (`unicode.IsControl`) or format (`unicode.Cf`, which includes the bidi controls) character; `path` is empty or contains NUL; `PollInterval` is negative, between 0 and 10 ms exclusive, or over 1 minute; `MaxLineBytes` is negative or over 1 MiB. Zero values mean the defaults: 250 ms and 64 KiB. |
| FR4 | `Name()` is the label (R9). | `Name()` returns `name` and never the path. `LogEntry.Source` is the same label. |
| FR5 | `FileSource` is immutable. | It has unexported fields only and is safe for concurrent `Read` calls. Each `Read` has its own descriptor, goroutine and state. |
| FR6 | Context done before `Read` (R9). | If `ctx.Err() != nil`, `Read` returns `nil, ctx.Err()` without opening anything (the fd count does not change). |
| FR7 | Safe first open (acceptance: only regular files). | `Read` calls `safefs.OpenRegular(path)` synchronously. A refusal (symlink in any component, FIFO, device, socket, directory, `ErrChanged`), a missing file or denied permission is returned as `nil, err` with no channel and no leaked descriptor. A FIFO path returns within 2 s. |
| FR8 | Start position. | `Query{FromStart: true}` reads from offset 0. `Query{}` starts at the size reported by `Fstat` at open. |
| FR9 | Start mid-line (R1). | With `Query{}` and size > 0, the source preads the last byte (`ReadAt(b, size-1)`). If it is not `\n`, the source is in fragment-skip mode: the bytes appended up to and including the next `\n` are discarded, and one marker is emitted (FR12). If it is `\n`, nothing is skipped. |
| FR10 | Complete lines only. | A line is emitted only when its terminating `\n` has been read and its length (excluding `\n`) is at most `MaxLineBytes`. `Line` is a fresh copy (it never aliases an internal buffer) with only the trailing `\n` removed; `\r` and every other byte are kept. An empty line is emitted as an entry with an empty, non-nil `Line`. |
| FR11 | Over-cap lines (acceptance: long lines capped; R8). | When a line's byte count passes `MaxLineBytes` before its `\n`, exactly one marker is emitted at that moment: `Truncated: true`, `Line` nil, `Dropped` as defined in 3.4. The rest of the line up to and including its `\n` is discarded with no further entry. No byte of the line is ever emitted. |
| FR12 | Markers for cut partial lines. | Bytes of an unfinished line (no `\n` yet) that are cut off by truncation (FR15) or rotation (FR16) give one marker with `Dropped` = the number of pending bytes, unless a marker for that line was already sent. Fragment-skip (FR9) gives one marker when its `\n` arrives or its count passes the cap, whichever comes first. On cancellation, pending bytes are discarded without a marker. |
| FR13 | Bounded memory (acceptance). | Per `Read`, heap held is at most `MaxLineBytes` (pending line) plus a fixed 32 KiB read buffer, plus entries the consumer still holds. Newlines are found by scanning the fixed buffer by hand (`bytes.IndexByte`). `bufio.Scanner`, `ReadBytes`, `ReadString` and `io.ReadAll` are not used. Test: a 10 MiB line written in chunks raises sampled peak heap by less than `MaxLineBytes` + 1 MiB, and gives exactly one marker. |
| FR14 | Follow. | At EOF the loop waits for the poll tick or `ctx.Done()`. Bytes appended to the file are emitted within about one poll interval. |
| FR15 | Truncation (acceptance). | On a tick, if `Fstat` of the held descriptor reports a size below the read offset, the offset becomes 0, pending bytes give a marker (FR12), and reading continues from the start. |
| FR16 | Rotation (acceptance; R4, R6). | On a tick, `Lstat(path)` is compared with `Fstat` of the held descriptor (the reference identity is always the held descriptor's `Fstat`, never an earlier `Lstat`) using `os.SameFile`. If they differ, the size `S` of the held descriptor is recorded and the old file is read up to `S` and no further. Pending bytes at `S` give a marker. The old descriptor is closed, then the path is reopened (FR18). |
| FR17 | Missing path. | `Lstat` reporting `fs.ErrNotExist` is not a rotation: keep reading the held descriptor and check again next tick. |
| FR18 | Reopen (R5, R7). | The reopen uses `safefs.OpenRegular(path)`. A `fs.ErrNotExist` result (a removal racing the reopen) puts the source in a no-descriptor state that retries the open every tick until it succeeds or `ctx` is done; this is not fatal. On success, the new descriptor's `Fstat` must report the same owner uid as the first descriptor's `Fstat` and a link count of exactly 1; otherwise the descriptor is closed and the error is `ErrReopenRefused`. Reading the new file starts at offset 0 with no fragment-skip. |
| FR19 | Fail closed during the stream. | Every other error ends the stream with one final `Err` entry and then closes the channel: a reopen refusal (`safefs.ErrSymlink`, `*safefs.NotRegularError`, `safefs.ErrChanged`), permission errors, `ErrReopenRefused`, an `Lstat` error other than not-found, and a `Fstat` or read error on the held descriptor. The descriptor is closed first. |
| FR20 | Fixed error text (R2). | No error from `NewFileSource`, `Read` or an `Err` entry contains the path, the label, line content or OS error text. OS errors unwrap to a bare `syscall.Errno`, so `errors.Is(err, fs.ErrNotExist)` and `fs.ErrPermission` still match. A marker-name test covers every error path that tests can trigger (section 10). |
| FR21 | Resources. | At most one log descriptor is held per `Read` (the old one is closed before the reopen). After the channel closes, for any reason, the process fd count equals the count before `Read`, and the goroutine has exited (tested with `runtime.NumGoroutine` stabilising after close). |

## 3. Technical design

### 3.1 Package layout

```text
internal/safefs/safefs.go       StripPath (exported; newOpError uses it)
internal/logs/logs.go           package doc (contract, caller constraints), LogSource, Query, LogEntry, errors, opError
internal/logs/options.go        FileOptions, defaults and bounds, label validation
internal/logs/lines.go          lineAssembler: fixed-buffer splitting, cap, markers (pure, no I/O)
internal/logs/file.go           FileSource, NewFileSource, Read, follow loop, truncation, rotation, reopen
internal/logs/owner_unix.go     //go:build darwin || linux: ownerAndLinks(fs.FileInfo) (uid uint32, nlink uint64, ok bool)
internal/logs/owner_other.go    //go:build !darwin && !linux: returns ok=false (never reached: OpenRegular refuses first)
```

Keep business logic out of `cmd/`; this package is not wired to the CLI.

### 3.2 API

```go
package logs

type LogSource interface {
    Name() string
    Read(ctx context.Context, q Query) (<-chan LogEntry, error)
}

type Query struct {
    FromStart bool // false: start at the current end of the file (tail -f)
}

// LogEntry is one complete line, one drop marker, or (last entry only) a fatal error.
type LogEntry struct {
    Source    string // the source label, never a path
    Line      []byte // raw, UNREDACTED line without the trailing "\n"; nil for markers and errors
    Truncated bool   // a line, or part of one, was dropped; Line is nil
    Dropped   int64  // bytes discarded when the marker was sent (see 3.4)
    Err       error  // non-nil only on the final entry before close
}

const (
    DefaultPollInterval = 250 * time.Millisecond
    MinPollInterval     = 10 * time.Millisecond
    MaxPollInterval     = time.Minute
    DefaultMaxLineBytes = 64 << 10
    MaxMaxLineBytes     = 1 << 20
    MaxNameBytes        = 128
)

type FileOptions struct {
    PollInterval time.Duration // 0 = DefaultPollInterval
    MaxLineBytes int           // 0 = DefaultMaxLineBytes
}

var (
    ErrInvalidOptions = errors.New("logs: invalid options")
    ErrReopenRefused  = errors.New("logs: rotated file refused") // owner or link count differs
)

func NewFileSource(name, path string, opts FileOptions) (*FileSource, error)
func (s *FileSource) Name() string
func (s *FileSource) Read(ctx context.Context, q Query) (<-chan LogEntry, error)
```

The package doc states the contract from FR2 and the caller constraints from section 7.

### 3.3 Read and the follow loop

```text
Read(ctx, q):
  ctx done?                  -> return nil, ctx.Err()                         (FR6)
  f := safefs.OpenRegular()  -> refusal: return nil, err                      (FR7)
  ref := Fstat(f); owner := uid(ref)                                          (reference identity, R4)
  off := 0 or ref.Size(); if !FromStart && size>0 && lastByte != '\n' { skip fragment }  (FR8, FR9)
  go loop(); return ch, nil

loop (one goroutine, defer close(ch) and close(f)):
  read: ReadAt(buf, off) until io.EOF, feeding lineAssembler; each entry sent with select{ch<-e; <-ctx.Done()}
  wait: select{ <-ticker.C; <-ctx.Done() -> return }
  tick:
    st := Fstat(f)                    error -> fail(opError "stat")
    st.Size() < off                   -> truncation: assembler.cut(); off = 0          (FR15)
    li, err := Lstat(path)
      not found                       -> continue reading f                            (FR17)
      other error                     -> fail(opError "lstat")
      !SameFile(li, st)               -> rotation:                                     (FR16)
          S := st.Size(); read f up to S only; assembler.cut()
          close(f); afterRotationDetected()                                            (R11 seam)
          reopen()                                                                     (FR18)
  reopen (also on every tick while there is no descriptor):
    f2, err := safefs.OpenRegular(path)
      not found -> f = nil, retry next tick
      error     -> fail(err)
    st2 := fstat(f2) (seam); uid(st2) != owner || nlink(st2) != 1 -> close f2; fail(ErrReopenRefused)
    f = f2; off = 0
```

With `ReadAt` and the offset kept by the loop there are no seek calls. `ReadAt` returns `io.EOF` on a short read at end of file (Verified: `go doc os.File.ReadAt`, go1.27.2). Truncation is checked before rotation on each tick. If both apply, the rotation drain reads nothing past the old size, and the cut produces at most one marker.

The ticker is created once per `Read` and stopped on exit. While catching up on a large backlog, the loop reads to EOF before it waits. Backpressure comes from the unbuffered channel: a slow consumer slows reading, and memory does not grow.

### 3.4 Line assembly (`lineAssembler`)

This is a pure state machine over byte chunks, with no I/O, so it can be unit tested on its own. State: `pending []byte` (capacity grows up to `MaxLineBytes`, never beyond), `skipping bool` (discard until `\n`), `markerSent bool`, `dropped int64`.

- **Normal.** Append bytes to `pending` until `\n`. On `\n`, emit a copy of `pending` and reset. If appending would make `len(pending)` exceed `MaxLineBytes`, emit the marker now with `Dropped = len(pending) + bytes of this line in the current chunk up to the chunk end or \n` (so it is at least `MaxLineBytes + 1`), clear `pending`, and switch to `skipping` with `markerSent = true`.
- **Skipping.** Discard bytes until `\n`, then return to normal. No further entry is sent if `markerSent` is set.
- **Fragment-skip (FR9).** This is `skipping` with `markerSent = false`, and `dropped` counts the discarded bytes. The marker is emitted when the `\n` arrives (`Dropped` = bytes discarded including the `\n`) or when `dropped` passes `MaxLineBytes` (`Dropped` = the count at that moment), whichever comes first.
- **`cut()`** (truncation or rotation). If `pending` is non-empty and no marker has been sent for this line, emit a marker with `Dropped = len(pending)`. If in fragment-skip with no marker sent and `dropped > 0`, emit a marker with `Dropped = dropped`. Then reset to normal.

**`Dropped` is defined** as the number of bytes of the affected line that had been discarded when its marker was sent. It is a lower bound on the line's length, not its total length. Counting uses a saturating add capped at `math.MaxInt64` (user decision). Because the marker is sent once, when the cap is crossed, the value is in practice bounded by `MaxLineBytes` plus one read buffer, so the saturation is defense in depth.

### 3.5 Reopen checks (R7)

`ownerAndLinks` reads `Uid` and `Nlink` from `fs.FileInfo.Sys().(*syscall.Stat_t)` and converts `Nlink` to `uint64`. The field type differs by platform (Verified with `go doc syscall.Stat_t` under go1.27.2: darwin `Nlink uint16`; linux/amd64 `uint64`; linux/arm64 and linux/386 `uint32`; `Uid uint32` everywhere). If `Sys()` is not a `*syscall.Stat_t`, `ok=false` and the reopen is refused (fail closed).

- **Owner.** The new file's uid must equal the uid of the first descriptor's `Fstat` in this `Read`. This catches a file pre-created by another user in a shared log directory. It is an operational trade-off: rotation that changes ownership ends the stream.
- **Link count.** It must be exactly 1. This catches a hard link to another file of the same user (for example `~/.aws/credentials`) planted at the path, which `safefs` does not detect. A log file that legitimately has a second hard link is refused at rotation. The first open does not apply this check (user decision); see accepted risks.
- **`fstat` seam.** `var fstat = func(f *os.File) (fs.FileInfo, error) { return f.Stat() }`, which tests in the package replace to report a different uid. A different owner cannot be created without root. A link count of 2 is tested with a real hard link.

### 3.6 Errors (R2)

- `safefs` gains `func StripPath(err error) error`. It returns the inner error of a `*fs.PathError`, `*os.LinkError` or `*os.SyscallError`, otherwise `err`. `newOpError` uses it, so the path-stripping rule lives in one place. This is about 10 lines of refactor with no behavior change. It is preferred over copying the logic (duplicated security-relevant knowledge drifts) and over exporting `safefs`'s `opError` (its text says "safefs:", which would be wrong for a read error inside `logs`).
- `logs.opError{op, err}` has `Error() = "logs: " + op + " failed"` and unwraps to `safefs.StripPath(err)`. The ops are `stat`, `lstat` and `read`.
- Errors from `safefs` (`ErrSymlink`, `*NotRegularError`, `ErrChanged`, `ErrUnsupportedPlatform`, its `opError`) are passed through unchanged; they already have fixed text.
- `ctx.Err()` is returned as is from `Read` (FR6) and is never sent as an `Err` entry.

### 3.7 Test seams

These are package-level variables that production never changes, following the pattern of `safefs.afterLstat`:

- `afterRotationDetected func()` runs after the old descriptor is closed and before the reopen (R11). Tests use it to swap the path for a symlink, a FIFO, a directory, a hard link, or nothing.
- `fstat` (see 3.5).

## 4. Data/API changes and migrations

- New package `internal/logs` (section 3.2).
- `internal/safefs`: new exported `StripPath`. `newOpError` is refactored to use it, and existing safefs tests keep its behavior pinned.
- No persisted data, no wire format, no CLI flags, no migrations.

## 5. Engineering decisions and rationale

| Decision | Rationale | Alternatives rejected |
| --- | --- | --- |
| Architecture signature with a terminal `Err` entry (user) | Matches section 15; fits the context-aware unbuffered send; an error is explicit and hard to miss. | `Err()` method (stateful), `iter.Seq2` and `Next(ctx)` (both depart from the architecture and need an ADR). |
| `Query{FromStart bool}`, always follow (user) | Smallest useful query; makes tests deterministic. | Follow switch, last-N, empty `Query`: speculative or less useful. |
| Polling with the standard library at 250 ms (user) | No dependency; same behavior on macOS and Linux; about 60 lines. | fsnotify plus fallback (dependency, two code paths, lost events on NFS and FUSE), backoff (unpredictable latency). |
| Drop over-cap and cut lines as markers, never emit fragments (user) | The adapter guarantees no part of a split secret leaves it; the threat model forbids splitting input across `Redact` calls. | Prefix with a flag, chunking, ending the stream (denial of service). |
| One marker, sent when the cap is crossed (user, R8) | The consumer learns at once; no unbounded counter; one rule. | A marker at the newline with the total size (holds state for an unbounded time). |
| Fail closed on any reopen failure except not-found (user) | Every refusal is visible to the consumer; no silent stall on a planted symlink. | Retry forever, or split errors by type. |
| Owner uid and `Nlink == 1` on reopen (user, R7) | Closes the hard-link and foreign-file gaps at the one point an attacker controls. | No checks (rely on safefs only). |
| Label for `Name()`, not the path (user) | The path can hold user names or internal layout; section 15 plans to expose source names through MCP. | `Name()` returns the path or its base name. |
| Export `safefs.StripPath` | One home for the path-stripping rule. | Copy it into `logs`; reuse safefs's `opError` (wrong prefix). |
| `ReadAt` with an explicit offset | No seek state; the bounded drain (R6) is a simple comparison. | `Read` plus `Seek`. |

**ADR 0005 "Live log source stream contract" (PR 1)** is warranted because every future adapter (stdout, Docker, journald) inherits it. It records: the terminal `Err` entry; complete lines only, with over-cap and cut lines dropped as single markers; the label as `Name()`; fail-closed reopen with owner and link checks; and polling over fsnotify. The `docs/adr/` directory already has three files numbered 0004, so this one is 0005.

## 6. Risks and failure modes

| Scenario | Behavior |
| --- | --- |
| Consumer stops reading and never cancels | The goroutine blocks on send forever, holding one descriptor. The package doc requires callers to always cancel. Not detectable inside the adapter. |
| Two rotations within one interval | The intermediate file is skipped (accepted). |
| Writer keeps appending to the old file after rotation | Bytes past the size `S` at detection are lost (bounded drain, R6; accepted). |
| `copytruncate`, then regrowth past the offset within one interval | The truncation is missed and reading resumes mid-line in the new content. Unlike the start position (FR9) there is no fragment-skip, so a mid-line fragment can be emitted as a line (accepted; see threat model). |
| `/proc` and `/sys` files (size 0) | Every tick sees size < offset, so the content is re-emitted every tick (accepted; documented as unsupported input). |
| Inode identity on NFS, FUSE or overlayfs | `SameFile` may report a rotation falsely or miss one (accepted). |
| `Lstat` blocks on a hung network filesystem | The loop blocks until the call returns; cancellation takes effect afterwards (accepted). |
| Read blocks on a network or FUSE filesystem | Same as above; this matches the existing safefs accepted risk. |
| Rotation changes the owner, or the log has two hard links | Stream ends with `ErrReopenRefused` (intended; operational cost). |
| Path deleted and never recreated | The held descriptor keeps being read; there is no error. After a rotation drain with no new file, the source waits with no descriptor until the file appears. |
| Removal races the reopen | Treated as not-found: no-descriptor state, retried each tick (R5). |

## 7. Security

**Trust boundary.** The adapter is the point where untrusted file state (path, content, rotation) enters. `LogEntry.Line` holds raw, unredacted data.

Controls:
- **Opens.** Every open, first or reopen, goes through `safefs.OpenRegular`: no symlink in any typed component, regular files only, no blocking on a FIFO, identity checked with `Fstat`.
- **Reopen identity.** Same owner uid as the first open and a link count of exactly 1.
- **Lines.** Only complete lines within the cap leave the adapter; over-cap lines, cut partial lines and the start-mid-line fragment become markers with no content.
- **Errors.** Error text is fixed (no path, label, content or OS text); the label is validated.
- **Fail closed.** Every unexpected condition ends the stream with an `Err` entry.
- **Resources.** Memory per `Read` is bounded; each `Read` holds one descriptor and one goroutine.
- **Never executed.** Scanned content is never executed. The package does not import `os/exec`, and nothing is logged.

Accepted risks (threat model, R10):
- The first open does not check the link count, and a hard link created before `Read` is not detected. This matches the safefs accepted risk; the file is still read only with the invoking user's permissions.
- Fragments after a `copytruncate` regrowth.
- Inode identity on NFS, FUSE and overlayfs.
- A blocking `Lstat` during the rotation check.
- Re-emitting `/proc` and `/sys` files.
- Lost lines after rotation (two rotations per interval, writes past `S`).
- **Cross-line secret splitting.** The adapter guarantees no partial line, not that a secret stays on one line. A PEM block or a wrapped token spans several entries.
- A consumer that never cancels pins a goroutine and a descriptor.

Caller constraints (threat model, package doc):
- Redact with context across lines (multi-line blocks such as PEM), because the guarantee is only "no partial line".
- Never expose `Line` outside the process, to MCP or logs, before redaction.
- Escape CR, NUL, ANSI and bidi characters before display.
- Cap concurrent `Read` calls in any MCP layer: each costs one descriptor, one goroutine and up to `MaxLineBytes + 32 KiB`.
- Always cancel `ctx` when done.
- Never use `Dropped` as a size for allocation.

`security-reviewer` must review every PR, because the change touches file and path handling, symlinks and untrusted content parsing.

## 8. Performance/scalability

- Idle cost per `Read`: one `Fstat` and one `Lstat` per 250 ms.
- Latency: at most one poll interval plus the consumer's speed.
- Memory per `Read`: at most `MaxLineBytes` (64 KiB by default, 1 MiB maximum) plus a 32 KiB buffer plus entries the consumer holds. Throughput is bounded by the consumer through the unbuffered channel.
- Concurrency: no shared state between `Read` calls. The number of concurrent `Read` calls is the caller's job to bound (section 7).

## 9. Implementation steps

The estimate is about 380 production lines and about 550 test lines, plus about 130 lines of docs: roughly 1,060 changed lines. That is well over the 500-line split point, so the work is delivered as **three stacked PRs**, each a usable increment under 500 lines:

| PR | Contents | Estimate |
| --- | --- | --- |
| PR 1 | `safefs.StripPath`; `logs` types, interface, errors, `opError`; options and label validation; `lineAssembler`; ADR 0005 | about 130 production, 230 tests, 60 docs = about 420 |
| PR 2 | `FileSource.Read`: context checks, first open, start position and fragment-skip, follow loop, truncation, fail closed on stat and read errors; threat-model section (controls, contract, caller constraints) | about 140 production, 200 tests, 40 docs = about 380 |
| PR 3 | Rotation: `Lstat`/`SameFile` detection, bounded drain, reopen with owner and link-count checks, not-found retry, seams; rotation accepted risks; architecture section 15 note | about 110 production, 200 tests, 30 docs = about 340 |

Steps (each can be done and verified on its own; `task test` must pass after each):

1. **`safefs.StripPath`** (PR 1). Export it and make `newOpError` use it. Result: existing safefs tests pass. Tests: a table for `PathError`, `LinkError`, `SyscallError`, a bare `Errno`, and nil.
2. **`logs` contract types** (PR 1, depends on 1). `logs.go`: package doc with the FR2 contract and the section 7 caller constraints, `LogSource`, `Query`, `LogEntry`, sentinels, `opError`. Tests: `opError` text is fixed and unwraps to `Errno`, `errors.Is(fs.ErrNotExist)` works.
3. **Options and label validation** (PR 1, depends on 2). `options.go` and `NewFileSource` (constructor only, no I/O). Tests: table over every FR3 boundary (9 ms, 10 ms, 1 min, 1 min + 1 ns, -1, `MaxLineBytes` 1 MiB and 1 MiB + 1, 128 and 129 byte labels, invalid UTF-8, `\x1b`, U+202E, an empty path, NUL in the path); the error text never contains the label or path.
4. **`lineAssembler`** (PR 1, depends on 2). Tests: lines split across chunk boundaries; exactly `MaxLineBytes` (emitted) and `MaxLineBytes + 1` (one marker, `Dropped` ≥ cap + 1); a marker sent once even when the line spans many chunks; an empty line; `\r\n` keeps `\r`; `cut()` with pending bytes, without, and after a marker; fragment-skip ending at `\n` and at the cap; returned `Line` slices do not alias (a later chunk does not change an earlier line); the saturating add at `MaxInt64`.
5. **ADR 0005** (PR 1, depends on 2 to 4).
6. **`Read`: open, start position, follow** (PR 2, depends on PR 1). FR6 to FR10, FR13, FR14, FR21, using a short `PollInterval` (10 ms). Tests use real files in `t.TempDir()`: `FromStart` versus end of file; fragment-skip when the file does not end in `\n`; append then receive; a 10 MiB line written in 64 KiB chunks with the heap bound and one marker; a context already done (no fd change); cancellation closes the channel and the goroutine count returns to the baseline; refusals on first open (symlink as the final component, symlinked parent, FIFO within 2 s, directory, missing, mode 000) are returned synchronously with no fd leak.
7. **Truncation and stream errors** (PR 2, depends on 6). FR15, FR19 for stat errors. Tests: truncate to 0 then write again (lines from the start, one marker if a partial line was pending); fail closed on a stat error through the `fstat` seam, with one `Err` entry, the channel closed, and the fd count back to baseline.
8. **Threat-model section** (PR 2, depends on 6 and 7). "Live log sources (`internal/logs`)": controls, stream contract, caller constraints.
9. **Rotation** (PR 3, depends on PR 2). FR16 to FR18, the seams, `owner_unix.go` and `owner_other.go`. Tests:
   - rename and create (lines from both files, in order, nothing duplicated);
   - a pending partial line at rotation gives a marker;
   - the drain is bounded (data written to the old file after detection, through the seam, is not emitted);
   - path removed with no new file: the old descriptor is still read;
   - not-found at reopen: the source waits, then picks up the new file;
   - through `afterRotationDetected`, the new path is a symlink (`ErrSymlink` entry), a FIFO (`NotRegularError` within 2 s), a directory, or a hard link to another file (`ErrReopenRefused`);
   - a different owner through the `fstat` seam (`ErrReopenRefused`);
   - every final `Err` entry is followed by close, and no fd leaks.
10. **Docs** (PR 3, depends on 9). Add the rotation accepted risks to the threat model and a note in `docs/architecture.md` section 15 (the `Query` and `LogEntry` contract, the label as `Name`, ADR 0005).

## 10. Testing strategy

- Real filesystem only (`t.TempDir()`, real rename, truncate, hard links, FIFOs via `syscall.Mkfifo`, symlinks). There are two seams, `afterRotationDetected` (timing) and `fstat` (owner and stat errors), and each is noted where used. Per the test-writing skill, the uid case uses the seam because a different owner cannot be created without root.
- **Timing.** Tests wait on the channel with deadlines (2 s) and never sleep for a fixed time to infer that something did not happen. "Not emitted" assertions use a sentinel line written afterwards: when the sentinel arrives, nothing else may have arrived before it.
- **Error-text test.** Every error path that tests can trigger (FR3 validation, FR6, FR7 refusals, stat failure through the seam, `ErrReopenRefused`, each reopen refusal) is checked to contain neither the path, the label, nor a marker string written into the file. The read-error path cannot be triggered on a local filesystem without fault injection. It is verified by inspection, as safefs did for fstat and set-blocking, and the reason is noted in the PR.
- **Leaks.** Every test that ends a stream checks that the fd count and the goroutine count are back to their baselines.
- **Break-the-guard checks** (revert after each). Each change must make a test fail:
  - emit `pending` on `cut()`;
  - remove the cap check;
  - compare against the first `Lstat` instead of `Fstat`;
  - drop the `Nlink` check;
  - drop the owner check;
  - make the drain unbounded;
  - treat not-found at reopen as fatal;
  - remove `ctx.Done()` from the send select.
- **Linux.** CI runs no Go tests, so each PR runs `docker run --rm -v "$PWD":/src -w /src golang:1.27 go test ./...` and records the result in the PR.
- **Race detector.** `go test -race ./internal/logs/...` on each PR. Concurrent `Read` calls on one `FileSource` are tested.

## 11. Observability, deployment, rollback

- The package logs nothing (no risk of leaking content). Markers and the terminal `Err` entry are the signals; a future consumer decides what to report.
- No deployment: the package has no CLI or runtime callers yet. Rollback is reverting the PRs, which is safe because nothing depends on them yet.
- `.plan-url` is never committed (it is already in `.gitignore`).

## 12. Definition of done

- All FR1 to FR21 acceptance criteria are covered by tests. `task test` passes after each step; `task verify` (fmt, lint, test, cross, security, secrets) passes before each PR is marked ready.
- `task cross` passes, so `owner_other.go` compiles on windows and freebsd.
- Linux container run and `-race` run are recorded in each PR.
- ADR 0005, the threat-model section "Live log sources (`internal/logs`)" with controls, accepted risks and caller constraints, and the architecture section 15 note are merged in the PRs listed above.
- `staff-engineering-reviewer` and `security-reviewer` both pass on each PR.
- No new dependency in `go.mod`.
