# ADR 0007: Scanner reads through a bounded ReaderAt; 1 GiB cap

Status: Accepted (REDACT-37)
Date: 2026-11-13
Spec: `docs/features/hash-filetype-scanners/spec.md`
Supersedes: decisions 1-3 of [ADR 0004](0004-scanner-contract-content-and-isolation.md). Decisions 4-7 of ADR 0004 stand.

## Context

REDACT-37 adds the first production scanners: a SHA-256 hash and a file-type check. Hashing a file must not need the whole file in memory, and ADR 0004 decision 2 already planned a move from `content []byte` to a bounded `io.ReaderAt`. The old 10 MiB cap was sized for holding content in memory. A `security-reviewer` design review (R1, R2, R5, R9) set the rules below.

## Decisions

1. **`Scan(ctx, a, r io.ReaderAt, size int64)`.** The caller opens the file once through `safefs.OpenRegular` and passes the file and its size to `Registry.Run`. Nothing is read into memory by the caller. Offsets and sizes are `int64`.
2. **`Run` wraps the reader in an opaque bounded type.** Scanners receive an unexported `boundedReader` whose only method is `ReadAt`. A scanner therefore cannot reach the `*os.File` (`Chmod`, `Fd`, `Name`) or an `*io.SectionReader` (`Outer()`). The wrapper rejects negative offsets, never reads at or past `size`, treats an inner reader that over-reports its count or breaks the `io.ReaderAt` contract as a failure, and replaces every inner error other than `io.EOF` with fixed text, because OS errors carry file paths.
3. **`Run` validates before any read**, in this order: `a.Validate()`, `size < 0`, `r == nil`, `a.Size != size` (all `invalid artifact`), then `size > MaxContentSize` (`too large`). A typed-nil `*os.File` passes these checks and fails on its first read, which makes the result incomplete without a panic.
4. **`MaxContentSize` is 1 GiB (Assumed).** Memory use no longer depends on file size, so the cap bounds only time (about 1 s of SHA-256, Assumed; the `BenchmarkHash` figure on the CI runner is recorded here when the benchmark lands in a later PR of this story). An over-cap file is still an incomplete scan, never truncated.
5. **`Artifact.Mode fs.FileMode` holds permission bits only**, filled from `f.Stat()` on the descriptor that is scanned, never from `Lstat` on a path. Size and mode come from one fstat of the same descriptor as the bytes.
6. **The file is read live, so the caller must detect change.** The old design read the file once into a private snapshot. With a `ReaderAt` each scanner reads the file itself, so a file rewritten during the scan can give scanners different bytes. The CLI re-checks the descriptor after `Run` (size, mtime and ctime, plus a 1-byte probe past `size`) and records `{registry, changed}`. The check lives in `internal/cli` (`checkUnchanged`). The check is best effort: a same-size rewrite that leaves size, mtime and ctime alone is not detected, and an unprivileged writer can do that within the filesystem's timestamp granularity (coarse clocks, HFS+ 1 s, FAT and exFAT, some NFS and FUSE) or through a shared writable mmap. Only a private snapshot closes it. This stays an accepted residual risk. The hash describes the bytes read during this scan, not the file's identity; quarantine and policy must re-hash their own copy.

## Alternatives considered

- **Caller hashes while reading.** Needs a special case for files over the cap and a second path beside `Scan`. Rejected.
- **Keep `[]byte` and the 10 MiB cap.** Fails the story's "hash large files without reading them into memory". Rejected.
- **Pass an `*io.SectionReader` or the `*os.File`.** Simple, but a scanner could reach the descriptor (`Outer()`, `Fd`, `Chmod`). Rejected in favor of the opaque wrapper.
- **`Mode` as a Metadata key or an extra `Scan` argument.** Untyped, or it widens the interface for one fact. Rejected.
- **Hash while copying to a private snapshot.** Restores the single-snapshot property but doubles I/O and needs temp storage. Rejected.
- **No change detection.** A silent wrong hash. Rejected.

## Consequences

- `scanner.Scanner.Scan` and `Registry.Run` change signature; every fake and test is migrated. `scannertest.AssertNoMutation` keeps its signature and now also fails on reads outside the content, through the new `scannertest.Reader`.
- The scanner import allowlist adds `io`.
- A buffering scanner must keep its own small cap and never allocate `size` bytes; an aggregate byte budget and a per-scan deadline belong to REDACT-39.
- A network or FUSE file can block in `ReadAt`; there is no per-scanner timeout (accepted, as in ADR 0004).
- `docs/architecture.md` sections 5 and 7 and the artifact-finding-models spec (FR1) are updated. The `scan` report text for an over-cap file now says `1 GiB`.
