# ADR 0002: `safefs` is the filesystem trust boundary for input files

Status: Accepted
Date: 2026-10-25
Spec: `docs/features/safe-input-open/spec.md`

## Context

`redactscan redact FILE` reads a path that may come from untrusted content: a cloned repository or an extracted archive can hold a symlink to `~/.aws/credentials` or `/proc/self/environ`, a FIFO with no writer, or a device. The scanner and quarantine work will open files the same way, so the rule needs one reusable home rather than a check in each caller. Checking only the final path component leaves `logs -> /elsewhere` (a symlinked parent) open.

## Decisions

1. **`internal/safefs.OpenRegular` is the single way to open an input file.** It returns a blocking `*os.File` only for a regular file, and refuses everything else with a fixed error (`ErrSymlink`, `NotRegularError`, `ErrChanged`, `ErrUnsupportedPlatform`) whose text never carries the path, contents or OS error text. Callers (CLI now; scanner and quarantine later) go through it and do not call `os.Open` on untrusted paths.
2. **No symlink in any component of the path as typed.** macOS uses `O_NOFOLLOW_ANY` (`0x20000000`, defined locally; `syscall` does not export it). Linux walks the components with `syscall.Openat` (retrying EINTR), opening each directory with `O_DIRECTORY|O_NOFOLLOW` (Linux reports ENOTDIR for a symlink; a stdlib `Lstat` of the typed prefix classifies it, since `Fstatat` is not available on all architectures), starting from `"."` for relative paths (`AT_FDCWD` is not exported). For relative paths the current directory itself is not re-checked.
3. **macOS system-link allowlist, checked at run time.** `/tmp`, `/var` and `/etc` are root-owned symlinks to `private/<name>`, and `$TMPDIR` is under `/var/folders`. A literal `/tmp/`, `/var/` or `/etc/` prefix is rewritten to `/private/...` only if that entry in `/` is a symlink owned by uid 0 with target exactly `private/<name>`. Nothing else is rewritten.
4. **Unix only.** macOS and Linux are supported; every other GOOS compiles to a stub returning `ErrUnsupportedPlatform`. There is no plain-open fallback.
5. **Standard library only.** No `golang.org/x/sys`, no `openat2`.

## Alternatives considered

- **Final-component protection only.** Smaller, but leaves symlinked parents in cloned repos open. Delivered first as PR 1, then closed by this decision.
- **`golang.org/x/sys` (`openat2` with `RESOLVE_NO_SYMLINKS`, darwin `openat`).** One call per OS, but a new dependency for one flag. Rejected for now.
- **`os.Root`.** Confines to a root but follows in-root symlinks and changes the path contract. Rejected.
- **Refuse the macOS system links.** Simplest, but breaks pasted `$TMPDIR` and `/tmp` paths. Rejected (user-approved allowlist instead).
- **Trust any root-owned link on macOS.** Needs a user-space resolver for the target; much more code. Rejected.
- **Windows support.** Reparse points and file IDs double the code with no Windows CI. Deferred.

## Consequences

- Inputs that previously worked through a symlink anywhere in the path are refused, with no flag to allow them.
- Linux directories on the path need read permission (the walk opens them `O_RDONLY`); search-only directories fail closed.
- If a macOS system lacks the expected root-owned links, `/tmp`-style paths are refused; `/private/...` or relative paths still work.
- `O_NOFOLLOW_ANY` needs macOS 11 or later. Behavior on older kernels is not verified; Go 1.27 requires a newer macOS (Assumed from release notes).
- The pre-open `Lstat` resolves symlinked parents, so metadata traversal (autofs, NFS, FUSE) can occur before the refusal, and a dangling symlinked parent may report `cannot open`. Accepted.
- `task cross` only proves Linux (native, amd64, 386), freebsd and windows compile; behavior is tested natively on macOS and in a Linux container.
- Hard links, content changes after open, and blocking reads on network filesystems remain accepted risks (`docs/threat-model.md`).
- New code that reads untrusted paths must use `safefs` or record why not.
