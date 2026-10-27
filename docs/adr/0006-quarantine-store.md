# ADR 0006: Quarantine store: on-disk format, trust boundary and atomic publish

Status: Accepted
Date: 2026-10-27
Spec: `docs/features/quarantine-store/spec.md`
Builds on: ADR 0002 (typed-path open), ADR 0003 (pinned root through a verified descriptor), ADR 0004 (`os.Root` traversal, `OpenChildDir`)

## Context

Scan decisions `review` and `block` need somewhere inert to keep the content: not executable, not readable by other local users, never mistaken for a complete entry when half written, and described by metadata that later commands trust only after strict validation. The store lives in the user's home and holds hostile content. Other local users and hostile scanned content (bytes, names, URIs, findings derived from them) are the adversaries. Processes running as the same uid and root are out of scope: they can already read 0700/0600 files.

## Decisions

1. **One directory per quarantine event (D1).** ID = `<sha256 hex>-<16 hex random>`, grammar `^[0-9a-f]{64}-[0-9a-f]{16}$`. Each entry is self-contained, so list/inspect/release/delete touch one directory. The grammar cannot express `.`, `..`, `/` or NUL, so a valid ID is always one safe path component and is checked before any filesystem call. Cost: identical bytes are stored twice.
2. **Repair, refuse, never follow (D3).** Store directories owned by the current user with a mode other than exactly 0700 (any group/other bit, setuid, setgid, sticky) are tightened with `fchmod` on the pinned descriptor and reported through `Store.Repaired()`; the mode is re-read and a filesystem that ignores chmod is refused. Symlinks and foreign owners are refused (`ErrUnsafeDir`). Entry directories are checked and refused, never repaired: a wrong mode there was not made by `Put` and signals tampering or corruption.
3. **Base path rules (D4).** Default `os.UserHomeDir()/.redactscan` or an explicit argument; no environment override (any process that sets the environment could redirect quarantine writes). The base must be absolute, clean, not `/`, without NUL, and its parent must already exist (no `MkdirAll`). Symlinks above the base are allowed (for example `/home -> /var/home`); the base and everything below must not be symlinks.
4. **Strict validation on every read, re-hash only in `Verify` (D6).**
5. **Atomic publish with no-replace links (D7).** The ID is reserved with an exclusive `Mkdir`; `content` and then `metadata.json` are placed with `Root.Link`, which refuses an existing name. An entry is complete only when `metadata.json` exists. A plain `Rename` would replace an existing file and a temporary directory plus rename needs per-OS no-replace syscalls.
6. **Store budget checked before any write (D8).** Not serialized across processes (accepted below).
7. **Name and URI are redactor-checked on Put and refused on a hit (D9).** Redacting would silently change the record. URI userinfo, query and fragment are refused.
8. **euid 0 is refused unless `Options.AllowRoot` (D10).** A root-owned store under a user home breaks the ownership model.
9. **`encoding/json/v2` for strict decode (D11), typed finding metadata encoding (D12).** No new dependency.
10. **Fixed-text errors.** No path, ID, name, URI, finding text or OS error text; OS errors unwrap to a bare `syscall.Errno`.
11. **`safefs.OpenRegularIn(root, name)`** opens one component in a pinned root: `Lstat`, `O_RDONLY|O_NONBLOCK|O_NOCTTY`, `SameFile`, regular file, owned by the effective uid, then restores blocking mode. It needs `SameFile` because `Root.OpenFile` follows an in-root symlink on the final component and ignores `O_NOFOLLOW` (ADR 0004).

## Verified behavior (scratch probe: macOS go1.27.1 and Linux `golang:1.27` go1.27.3)

- `Root.Link(tmp, "id/content")` succeeds with a two-component in-root target.
- `Root.Link` onto an existing name returns `EEXIST` and leaves it unchanged.
- `Root.Link` through an escaping symlink returns "path escapes from parent".
- `Root.Mkdir` on an existing name returns `EEXIST`.
- json v2 `Unmarshal` with `json.RejectUnknownMembers(true)` rejects duplicate members, a case-variant member name and trailing data; v1 `encoding/json` accepts all three (duplicate: last wins; case-insensitive match).

The probe was run as root in the container. These behaviors are pinned by tests in PR 2 (json strictness) and PR 3 (`Link` and `Mkdir`), which run on both OSes as a non-root user.

## Alternatives considered

Dedup by sha256 only; shared blobs with a refcount; random-only IDs; move or rename from `incoming`; a `[]byte` input instead of a file; temporary directory plus rename (replace race, per-OS no-replace syscalls); lenient JSON; an environment override for the base; repairing entry directories.

## Accepted risks (user-accepted)

- Raw secrets are stored at rest unencrypted, included in backups, with no retention policy.
- The sha256 is exposed in every ID: offline guessing of low-entropy content by anyone who can see the name, which needs our uid given 0700.
- Orphan `.tmp-*` files holding raw content can remain after a crash; cleanup is deferred to a follow-up issue.
- On macOS, extended or inherited ACLs are independent of mode bits and the store neither inspects nor clears them. A directory or file under a base with an inheritable allow-read ACE (for example a shared folder) can be readable by another account even though the 0700/0600 mode checks pass. The default `~/.redactscan` does not inherit an allow ACE on stock macOS, and Linux POSIX ACLs are neutralised by the 0700/0600 mask. Enforcement would need cgo or `x/sys` (`acl_get_fd`) and is deferred.

Also accepted: the store budget is not serialized across processes, hard links by the same uid are not refused, and the macOS Spotlight marker is best effort.

## Consequences and caller constraints

- Release (REDACT-58) never derives a path from stored Name or URI and verifies content on the descriptor it copies from.
- Name, URI and finding strings are untrusted: CLI output escapes them and MCP marks them as quoted untrusted data.
- Neither `Read` nor any future MCP tool returns content bytes.
- Every `Put` failure (`ErrStoreFull`, `ErrMetadataTooLarge`, ...) is reported as "not quarantined / incomplete", never as clean; callers never clean the store to make room.
- Findings passed to `Put` come from `scanner.Registry.Run` (redactor-checked); other producers must apply the same checks.
- `metadata.json` schema version 1 is a long-lived contract: a future version must remain readable by a new decoder and v1 readers refuse other versions.
