# ADR 0003: Default file output beside the input, written through a pinned `os.Root` with no clobber

Status: Accepted
Date: 2026-10-25
Spec: `docs/features/cleaned-file-output/spec.md`
Amends: ADR 0002 (decision 1: `safefs` is the trust boundary for output files too; the `os.Root` rejection applies to opening input paths only)

## Context

`redactscan redact FILE` should write `<name>_cleaned<ext>` next to FILE, only after redaction succeeds, without partial or mixed output and without clobbering. The output directory comes from a path that may sit inside untrusted content (a cloned repo or an extracted archive), so a symlinked or swapped parent must not redirect the write. A by-path `rename` follows a parent swapped mid-run (verified on macOS), so path-based writes are not enough.

## Decisions

1. **`safefs.WriteSibling` is the way to create an output file.** The CLI default change lands in a second PR; this PR adds only the function.
2. **Pinned directory.** The directory is opened with `openNoFollow` (no symlink in any typed component), then the root is opened through that descriptor (`/proc/self/fd/<n>` on Linux, `/dev/fd/<n>` on macOS), because `os.OpenRoot(path)` resolves the path again and blocks forever on a directory swapped for a FIFO. `os.SameFile(dirFile, root)` stays as defense in depth. The root is bound to the input with `SameFile(root.Lstat(base), input)`. Every later create, link, rename and remove is a single-component call relative to the root. The typed directory is re-verified before commit and a mismatch is `ErrChanged`.
3. **Why `os.Root` is acceptable here but not in ADR 0002.** ADR 0002 rejected it for opening input paths because it follows in-root symlinks across intermediate components. Here the root is a verified descriptor and only single-component names are used, so there are no intermediate components.
4. **Temp file then atomic commit.** A 0600 `O_EXCL` temp file (`.redactscan-<16 hex>.tmp`, bounded retries) is written, fsynced and closed. Without replace, `Root.Link` then `Root.Remove(temp)` gives an atomic no-clobber; with replace, `Root.Rename` gives an atomic replace. Mode is forced with `f.Chmod(0600)` on the descriptor. The temp is removed on every error path; `tempLeft` reports a failed removal. The destination is never touched after a successful commit.
5. **Error text.** `newOpError` also strips `*os.LinkError` and `*os.SyscallError`, so no path reaches an error.
6. **Breaking change (PR 2).** `redact FILE` will write a file and leave stdout empty with exit 0; `-stdout` restores the old behavior and `-force` replaces. Accepted by the user. The derived name may escape ignore and sync rules (`.env` becomes `.env_cleaned`), and uncovered secret formats pass through; both are accepted and documented in the threat model. `-stdout` and `-force` are no-ops with stdin, and `redact f -stdout` stays a usage error.

## Spike results

| Spike | Result | Status |
| --- | --- | --- |
| S1 (macOS 26.6): `O_CREAT\|O_EXCL\|O_NOFOLLOW_ANY` | symlink at the name gives `EEXIST`; symlinked parent gives `ELOOP`. Background only: `WriteSibling` creates through `Root.OpenFile`, not this flag | Verified (`TestNofollowAnyExclusiveCreate`) |
| S2 (macOS 26.6 and `golang:1.27` Linux): `Root.OpenFile(O_CREATE\|O_EXCL)` on a planted symlink, `Root.Rename` over a symlink | `EEXIST`; the link itself is replaced and its target is unchanged | Verified (`TestRootSymlinkSemantics`) |
| S3: `link` errno on a filesystem without hard links | No such volume was available | Assumed: `EPERM`, `ENOTSUP`/`EOPNOTSUPP` or `EMLINK`; PR 2 maps all of them to a fixed message. `TestLinkErrnoWithoutHardLinks` records the errno when `REDACTSCAN_NOLINK_DIR` names such a directory |

`Root.Rename` onto a directory returns `EEXIST`; `WriteSibling` reports it as `ErrChanged` with replace, so the CLI maps `EEXIST` to "already exists" only without `-force`.

Also verified on Linux: `O_DIRECTORY|O_NOFOLLOW` on a symlink as the last component gives `ENOTDIR`, so `WriteSibling` classifies it with an `Lstat`.

## Alternatives considered

- **Path-based temp plus `os.Rename`.** Follows a swapped parent. Rejected.
- **Raw `renameat`/`linkat` or `golang.org/x/sys`.** `syscall.Renameat` is not exported on darwin and `x/sys` is a new dependency. Rejected.
- **`O_EXCL` directly on the destination.** Not atomic with respect to content: a partial file would be visible. Rejected.
- **Writer in `internal/cli`.** Duplicates the no-follow logic and splits the trust boundary. Rejected.

## Consequences

- Output needs write permission on the input's directory; in sticky or shared directories another user can create the destination first, so no-clobber refuses (fail closed).
- Hard-link-less filesystems cannot do no-clobber writes (fail closed); replace still works.
- A fatal signal during the write can leave a hidden `.redactscan-*.tmp` holding redacted bytes. No signal handling (accepted).
- The directory fsync is best effort, so a power loss after the rename may lose it.
- A replaced file loses its old mode, owner and hard links (they keep the old content). Inherited ACLs can grant access beyond 0600. Running as root writes a root-owned file.
