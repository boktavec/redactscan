# ADR 0004: Directory ingestion traverses through a pinned `os.Root`

Status: Accepted
Date: 2026-10-26
Spec: `docs/features/recursive-ingest/spec.md`
Builds on: ADR 0002 (typed-path open), ADR 0003 (pinned root through a verified descriptor)

## Context

REDACT-39 turns a directory tree (a cloned repo, an extracted archive) into artifacts for later scanning. Everything below the root is attacker-controlled: symlinks pointing outside, loops, FIFOs, devices, huge trees, and entries swapped while the walk runs. The walk must never follow a symlink, leave the root, block, or let a partial walk look complete.

ADR 0002 rejected `os.Root` for opening one typed path, because that case needs "no symlink at all" and `os.Root` follows in-root symlinks across intermediate components. Traversal is a different problem: it needs confinement to the tree for every descent, and symlinks are never followed anyway because each entry is `Lstat`ed before it is opened.

## Decisions

1. **Pin the walk root with `safefs.OpenDirRoot`.** It opens the typed path with `openNoFollow` (no symlink in any typed component, macOS system-link rule as in ADR 0002) plus `O_DIRECTORY|O_NONBLOCK`, then builds an `os.Root` through the verified descriptor (`rootFromDir`, shared with `WriteSibling`). A non-directory root is `ErrNotDir`; a symlink is `ErrSymlink`.
2. **Descend with `safefs.OpenChildDir(parent, name, want)`.** One component is opened through the parent root with `O_RDONLY|O_DIRECTORY|O_NONBLOCK`, then `os.SameFile` against the caller's `Lstat` result, then a child root is built from that same descriptor. Any swap to a different object (FIFO, symlink to a FIFO, symlink to a different directory, a different directory, removal, an escaping link) gives `ErrChanged`. A swap to a symlink that resolves to the same directory is indistinguishable from the original and is listed (accepted, harmless). The `SameFile` check inside `rootFromDir` is defense in depth that tests cannot reach.
3. **Never use `Root.OpenRoot(name)` for traversal.** It opens without `O_DIRECTORY` and `O_NONBLOCK`, so it blocks forever on a directory swapped for a FIFO (Verified on macOS go1.27.2: hangs for more than 2 s), and it follows a final in-root symlink. `O_DIRECTORY` turns a FIFO or a symlink to one into `ENOTDIR` instead of blocking; the `SameFile` check catches an in-root symlink to a directory, which `Root.OpenFile` follows.
4. **Fail closed on incomplete walks (PR 2).** A walk cut short by a limit, a read error or a change returns its partial result plus `ErrIncomplete` and exactly one `ingest-incomplete` Finding.
5. **Error text stays fixed.** `os.Root` errors contain the entry name, so they are mapped to a sentinel or wrapped with `newOpError`.
6. **The os.Root escape error is recognized structurally.** The `os` package does not export "path escapes from parent". `isRootEscape` treats a `*fs.PathError` whose inner error is not a `syscall.Errno` as an escape, except `fs.ErrClosed` and `fs.ErrInvalid` (a closed parent root is a plain failure, not `ErrChanged`). The predicate therefore matches any other non-`Errno` `PathError`, such as "empty path". `root_semantics_test.go` pins this on macOS and Linux.
7. **`OpenDirRoot` rejects `""` and NUL before any I/O.** `openNoFollow` drops empty components, so `""` would open the current directory on Linux.

## Verified behavior (go1.27, macOS and `golang:1.27` Linux container)

`internal/safefs/root_semantics_test.go` asserts, on both OSes: `Root.Stat` on an in-root link returns nil; dangling matches `fs.ErrNotExist`; a self-loop and a two-link loop match `ELOOP`; relative, absolute and missing-target escapes return a non-`Errno` `*fs.PathError`; `Root.OpenFile` with `O_DIRECTORY|O_NONBLOCK` returns `ENOTDIR` for a FIFO and a symlink to a FIFO without blocking; `Readdirnames` batches work on a Root-opened directory; `os.OpenRoot("/proc/self/fd/N")` (`/dev/fd/N` on macOS) works.

`Root.OpenFile` ignores `O_NOFOLLOW` on the final component and follows an in-root symlink (probe on macOS and Linux: opening an in-root link with `O_NOFOLLOW|O_DIRECTORY` succeeds). `SameFile` against the caller's `Lstat` is the only guard against that swap; do not "harden" `OpenChildDir` by adding the flag.

`O_DIRECTORY` has a unique job: it refuses to open a FIFO or device at all (`TestOpenChildDirDoesNotOpenFIFO` keeps a writer blocked in `open(2)` and fails if a read-only open happens). `O_NONBLOCK` and `SameFile` would also reject the FIFO, but only after an open that could release a blocked writer. `O_NONBLOCK` matters only at open time.

One difference: Linux refuses to create a symlink with an empty target (`ENOENT`), macOS allows it. The empty-target case in spec 3.6 can therefore only occur on macOS.

## Alternatives considered

- **`filepath.WalkDir`.** A symlink swapped in mid-walk redirects outside the root. Rejected.
- **`Root.OpenRoot(name)` per directory.** Blocks on a FIFO, follows a final in-root symlink. Rejected (decision 3).
- **Per-OS raw `openat` walker.** Strongest, but much more code than the standard library pattern ADR 0003 already uses. Rejected for now.

## Consequences

- Accepted risks (spec section 6): a directory moved out of the root while its descriptor is held is still listed once under its old relative path; hard links to files outside the tree are listed as regular files; the walk crosses mount points; a hung network filesystem can block a syscall (no `context`).
- Descriptor use is bounded by depth plus a small constant (PR 2 enforces `MaxDepth <= 256`).
