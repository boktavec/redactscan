# ADR 0005: Live log source stream contract

Status: Accepted
Date: 2026-10-27
Spec: `docs/features/file-log-source/spec.md` (REDACT-65)

## Context

`docs/architecture.md` section 15 plans a `LogSource` interface for live logs (file, stdout, Docker, Kubernetes, journald) that feeds redaction and, later, an MCP buffer. Every adapter reads untrusted data: the content, the line lengths, and whatever appears at a file path after rotation. The redactor must never see a secret split across calls, and the process must never hang or grow without bound. The first adapter is `FileSource` (`internal/logs`); later adapters inherit this contract, so it is recorded once here.

## Decisions

1. **The architecture signature, with a terminal `Err` entry.** `Read(ctx, Query) (<-chan LogEntry, error)`. Setup failures return `(nil, err)`. A failure during the stream is the last entry (`Err` set, nothing else) and then the channel closes. The channel is unbuffered, every send also selects on `ctx.Done()`, and a channel that closes without an `Err` entry closes only because `ctx` is done.
2. **Complete lines only.** An entry carries a whole line within `MaxLineBytes`, copied, with only the trailing `\n` removed. A line over the cap, a partial line cut off by truncation or rotation, and the fragment of a line already in progress when reading starts are never emitted. Each becomes one marker (`Truncated`, nil `Line`, `Dropped` a lower bound on the discarded bytes) sent as soon as the condition is known. The adapter guarantees "no partial line"; it does not guarantee that a secret stays on one line, so consumers redact with context across lines.
3. **A label, not the path.** `Name()` and `LogEntry.Source` are a validated label (non-empty, at most 128 bytes, valid UTF-8, no control, format or line and paragraph separator characters). Paths can hold user names and internal layout, and section 15 plans to expose source names through MCP.
4. **Fail closed.** Every error except "path not found yet" ends the stream with a fixed-text `Err` entry. Error text never contains the path, the label, line content or OS error text; OS errors unwrap to a bare `syscall.Errno`.
5. **Files are reopened only through `safefs.OpenRegular`,** and a rotated file must have the same owner as the first one and exactly one hard link.
6. **Polling, standard library only.** The file adapter polls (default 250 ms) rather than using fsnotify, inotify or kqueue.
7. **`safefs.StripPath` is exported** so `logs` builds its own fixed-text errors without copying the path-stripping rule.

## Alternatives considered

- **`Err()` method, `iter.Seq2`, `Next(ctx)`.** Stateful or a departure from section 15; would need their own ADR. Rejected.
- **Emit over-cap lines with a flag, or in chunks.** Puts part of a line, and so part of a secret, in front of the redactor. Rejected.
- **End the stream on an over-cap line.** One long line would stop log delivery (denial of service). Rejected.
- **One marker at the newline with the total size.** Holds counter state for an unbounded time. Rejected.
- **Retry forever on any reopen failure.** A planted symlink would stall silently. Rejected.
- **fsnotify plus a polling fallback.** A dependency, two code paths, and lost events on NFS and FUSE. Rejected.
- **Return the path from `Name()`.** Leaks layout through later MCP output. Rejected.

## Consequences

- Consumers must always cancel `ctx`; a consumer that stops reading pins one goroutine and one descriptor.
- Lines over the cap are lost (visible only as a marker), and so are lines lost to a missed rotation window. Accepted.
- Rotation that changes the file owner, or a log with a second hard link, ends the stream with `ErrReopenRefused`. This is an operational cost of the checks.
- Windows and other platforms are unsupported: `safefs.OpenRegular` returns `ErrUnsupportedPlatform`.
- Residual risks and caller constraints are in `docs/threat-model.md`, section "Live log sources (`internal/logs`)".
