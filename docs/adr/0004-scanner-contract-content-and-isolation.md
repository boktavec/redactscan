# ADR 0004: Scanner contract, with content passed in and per-scanner isolation

Status: Proposed (accepted when REDACT-36 PR 2 merges)
Date: 2026-10-26
Spec: `docs/features/scanner-scan-file/spec.md`

## Context

`redactscan scan FILE` (REDACT-36) introduces `internal/scanner`, the interface every future detector implements: hash and filetype (REDACT-37), script, manifest, archive and others (architecture section 7). The section 7 sketch is `Scan(ctx, a Artifact) ([]Finding, error)`, which leaves each scanner to open `a.Path` itself. Scanned content is untrusted, and scanner output is derived from it. One scanner bug or one file that triggers a crash must not hide the other scanners' findings, or make an incomplete scan look clean. REDACT-39 will run the same registry over whole directories.

## Decisions

1. **Content is passed in, read once by the caller.** The signature is `Scan(ctx context.Context, a artifact.Artifact, content []byte) ([]finding.Finding, error)`. The caller opens the file once through `safefs.OpenRegular` and reads at most `MaxContentSize+1` bytes. `content` is shared and read-only by contract. Scanners never open files.
2. **Planned migration to a bounded `io.ReaderAt`.** When a story needs content larger than a memory-friendly cap, the parameter becomes an `io.ReaderAt` plus a size: an `*io.SectionReader` over the file the caller opened once, limited to the cap. The one-open rule is kept.
3. **An over-cap file is an incomplete scan.** `len(content) > MaxContentSize` (10 MiB, Assumed default) runs no scanner and records `{registry, too large}`. Scanners never see truncated content.
4. **Explicit, immutable, ordered registry.** `NewRegistry(scanners...)` validates names (`^[a-z0-9][a-z0-9-]{0,31}$`, unique, `registry` reserved) and captures each `Name()` once. There is no global `Register` and no `init` registration.
5. **Per-scanner isolation, fail closed.** A returned error (findings discarded), a panic (including `panic(nil)`), `runtime.Goexit`, an invalid finding (dropped individually), context cancellation, the 1000-findings cap, an invalid artifact, and zero scanners having run each record a `Failure{Scanner, Reason}` with a fixed reason and make `Result.Incomplete()` true. Each `Supports` and `Scan` call runs on its own goroutine, waited for sequentially, with a `completed` flag and `recover()`. Error and panic values are never stored or printed.
6. **`internal/scanner` checks printed fields with `internal/redactor`.** A finding is dropped as invalid when `redactor.Redact` returns an error, or detects any kind other than label-like, in its `ID`, `Title`, `File` or `Evidence`. ID and Title are also bounded to 128 bytes of UTF-8, and File to 4096 bytes.
7. **No I/O in the package.** An import-allowlist test keeps `os`, `os/exec`, `syscall`, `net`, `plugin`, `unsafe`, `log` and `internal/safefs` out of `internal/scanner`.

## Alternatives considered

- **Section 7 as written, with each scanner opening `a.Path`.** No signature change, but N opens per file, a cap enforced in N places, a TOCTOU window between scanners, and the safefs rule repeated in every scanner. Rejected.
- **`io.ReaderAt` now.** No full read, but the file stays open for the whole scan, every scanner must handle read errors, and nothing needs it yet. Deferred (decision 2).
- **Scan a truncated prefix of over-cap files.** More evidence, but partial-content results such as hashes would be wrong. Rejected.
- **Global `init` registration.** Convenient, but adds hidden order and state and makes test registries harder. Rejected.
- **No panic recovery.** Simpler, and a crash is fail-closed, but one bug would end a whole directory scan with no report. Rejected. **`recover() != nil` only** misses `panic(nil)` when `GODEBUG=panicnil=1` is set, and misses `Goexit`. Rejected.
- **Contract-only redaction of scanner output.** That leaves the terminal unprotected against a scanner that forgets to redact. Rejected in favor of decision 6. A separate verifier in `scanner` would duplicate the redactor's knowledge.

## Consequences

- `docs/architecture.md` section 7 is updated to the new signature.
- Every scanner's tests call `scannertest.AssertNoMutation`. Mutation is not prevented at runtime.
- `internal/scanner` depends on `internal/redactor`. Kinds the redactor adds later are covered automatically. A legitimate title that resembles a covered secret format is dropped (fail closed); detectors use constant text or labels.
- Isolation does not cover goroutines a scanner starts itself. An unrecovered panic there crashes the process with exit status 2 (Assumed Go runtime behavior), the same code as a usage error. The contract forbids such goroutines.
- There is no per-scanner timeout, so a hung scanner blocks the scan. REDACT-39 may add deadlines with its worker pool.
- Until REDACT-37 registers scanners, every `scan` is incomplete (`no scanner ran`, exit 1).
- The `panic(nil)` and `Goexit` semantics are Assumed from the Go 1.21 release notes and the `runtime` docs, and are verified by tests on the repo toolchain.
