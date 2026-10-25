# Threat Model

This document records the threat model for RedactScan components as they are built. Each section is added by the feature that introduces the component.

## Redaction (`internal/redactor`)

Status: implemented by the redactor-core feature. Decision record: [ADR 0001](adr/0001-redactor-core-pseudonyms-and-fail-closed.md). Spec: `docs/features/redactor-core/spec.md`.

### Purpose and wording

The redactor reduces accidental disclosure of the secret formats it covers. Its output is not "safe to share": docs, errors and any future CLI help must not describe it that way. Anyone sharing redacted output still owns the decision to share it.

### Trust boundary

- Input is untrusted text (logs, files). It is never executed.
- Output crosses to less-trusted consumers: pasted into tickets or chats today, exposed to AI agents through MCP later.

### Adversaries

| Adversary | In scope | Notes |
| --- | --- | --- |
| Developer sharing logs accidentally | Primary | Secrets appear in logs in common, unencoded formats. |
| Hostile log content trying to break redaction | Secondary | Label spoofing, pathological patterns for CPU/memory blowup, encoding tricks (NUL, UTF-16/32), secrets glued to identifiers. |
| Author of the input who deliberately exfiltrates | Non-goal | An adversary who controls the input format can always encode a secret in a way no pattern list recognises. |

### Assets

Credential values of the covered kinds below.

### Covered kinds

| Kind | Coverage |
| --- | --- |
| `AWS_ACCESS_KEY` | `AKIA` or `ASIA` followed by 16 or more upper-case letters or digits, anywhere in the text (no word boundary). The tail is greedy so a stray prefix before a real key cannot leave part of the key behind. |
| `AWS_SECRET_KEY` | Only the 40+ character base64-alphabet value that follows an `aws_secret_access_key`-style name and separator (`=`, `:`, `:=`, `=>`, with optional quotes). The key name, separator and quotes are kept. |
| `GITHUB_TOKEN` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` with 36 or more alphanumerics; `github_pat_` with 22 or more word characters. Greedy, so no tail survives. |
| `PRIVATE_KEY` | PEM and PGP private key blocks (RSA, EC, DSA, OPENSSH, ENCRYPTED, PKCS#8, PGP `BLOCK`). Unterminated or type-mismatched blocks are redacted to end of input; an orphaned END marker redacts back to the end of the previous key span or the start of input. |

Formats and ranges marked Assumed in the spec (AWS key shapes, GitHub token lengths) follow public conventions and have not been checked against a live provider.

### Non-goals (not detected)

- JWTs, bearer/OAuth tokens, passwords, connection strings, cookies, PII, other cloud providers' credentials.
- AWS secret access keys without a key-name anchor, and the AWS key ID prefixes `A3T`, `ABIA`, `ACCA`.
- Encoded or transformed secrets: base64 (including base64-encoded PEM), compressed, URL-encoded, split or line-wrapped tokens, deliberate obfuscation.
- An AWS secret value on the line after its key name (YAML block style): it is neither redacted nor caught, and no error is returned.
- The dotted form `aws.secret.access.key=`.
- 4-dash PEM markers, and a BEGIN marker with no trailing dashes and more than 64 characters of type text (treated as obfuscation): that is the only such form that passes through. A dashed marker with a long single-word type is redacted, and a dashless marker with a gap of 63 characters or fewer fails closed in the verifier.
- UTF-16/32 text. It is rejected (`ErrUnsupportedEncoding`), not decoded.
- Zeroising secret bytes in memory. Go cannot guarantee it; the input and, transiently, matched spans stay in process memory until collected.

### Controls

| Threat | Control |
| --- | --- |
| Detector gap or bug leaks a covered secret | Fail closed: a verification pass, looser than detection, scans the exact bytes about to be returned and returns `ErrVerificationFailed` (kind name only) with nil output. |
| Oversized input exhausts CPU or memory | Hard cap of 10 MiB (`ErrInputTooLarge`); Go `regexp` is linear time; the PEM scan makes a bounded number of forward passes; adversarial 10 MiB inputs are timed in tests. |
| Encoding tricks hide secrets from byte patterns | Inputs containing NUL or starting with a UTF-16/32 BOM are rejected. |
| Input text forges a label (for example `[AWS_ACCESS_KEY_1]`) to confuse a reader or a later consumer | Label-like input text is neutralised to `(AWS_ACCESS_KEY_1)` and counted; the verifier requires every label in the output to be one this call emitted. |
| Overlapping detections leave a fragment | Overlapping spans, and touching secret spans, are unioned; the highest-priority kind wins; no constituent byte survives. A label-like span that only touches another span stays separate so it is neutralised and counted on its own. The AWS key ID tail is greedy, and fuzzing asserts that no 12-byte fragment of a key or token body survives. |
| Secret glued to an identifier (`AWS_KEY_AKIA...`) | No `\b` anchors; over-redaction is the accepted direction. |
| Secrets leak through errors, logs or panics | Errors are constant sentinels; the verification error carries only a kind name. No logging; the only package-level state is read-only (compiled regexps and detector/check tables); fuzzing asserts no panics. |
| Output aliases the caller's buffer | Output is always a fresh slice. |

### Accepted risks

- **Equality and count metadata.** Labels reveal that two redacted values are equal and how many distinct values of each kind appeared. Labels are scoped to one call: the same label in two calls refers to unrelated values, and there is no mapping from a label back to a value. Any future re-hydration or session-wide pseudonym needs its own design and security review.
- **Narrow coverage.** Uncovered formats pass through unchanged.
- **False failures.** The verifier is deliberately broader than detection, so some benign inputs fail the whole input with `ErrVerificationFailed` (the error names the kind). Examples:
  - Any `github_pat_` followed by a word character, including prose, and identifiers ending in `ghs_` or `ghr_` (or another `gh?_` prefix) followed by 20 or more alphanumerics.
  - A truncated 20-35 character `ghp_` token.
  - `secret_access_key` followed by an unanchored 40 character run.
  - STS, IMDS and `credential_process` JSON (`"SecretAccessKey": "..."`) and Rails-style `secret_access_key:`: the detector requires an `aws` prefix on the key name but the verifier does not, so these fail instead of being redacted. Aligning detector and verifier is a possible follow-up.
- **Over-redaction.** Unanchored matches inside longer identifiers, and text lost after a truncated PEM block or before an orphaned END marker.
- **Input held fully in memory.** Whole-input processing is bounded by the 10 MiB cap. Peak heap growth on adversarial 10 MiB inputs (dense keys, label-like spam) is about 9x the input size, roughly 100 MiB per call. Measured with a sampled peak-heap test: 9.1x here, 8.3-9.5x in review runs, against a 10x budget, so the margin is thin. The sampled figure is a lower bound: sampling every 50 microseconds measured 9.4x. A caller that runs `Redact` concurrently must bound the number of in-flight calls.

### Constraints for callers (future CLI, streaming, MCP)

- Bound the number of concurrent `Redact` calls: budget about 100 MiB of heap growth per in-flight call. Real memory use is higher under the default `GOGC`, so budget above that figure or set `GOMEMLIMIT`.
- Read at most `MaxInputSize+1` bytes (`io.LimitReader`) and reject anything longer; never split input across `Redact` calls (labels and multi-line blocks are per call).
- Open only regular files; validate paths and refuse unsafe symlink traversal. Met by `internal/safefs` (see "Safe file opening"): no symlink in any component of the path as typed.
- Write nothing until `Redact` succeeds; write `-o` output through a temp file in the same directory, then rename.
- Treat `ErrVerificationFailed` as a hard stop, not a prompt to retry with fewer detectors.

### Follow-ups

- `docs/architecture.md` still uses the product name "Sentinel" (`sentinel redact`, `cmd/sentinel/`) and says repeated raw values map to the same pseudonym "within a session". The redactor core scopes pseudonyms to one call (ADR 0001). Reconcile the name and that sentence in a separate change.

## Safe file opening (`internal/safefs`)

`safefs.OpenRegular(path)` is the filesystem trust boundary for input files. The path, the file and the directories on the way may be attacker-controlled (cloned repos, extracted archives). See `docs/features/safe-input-open/spec.md`.

### Controls

- **No symlink in any typed component.** macOS opens with `O_NOFOLLOW_ANY` (`0x20000000`, defined locally because `syscall` does not export it); Linux walks the path with `openat`, opening each directory with `O_DIRECTORY|O_NOFOLLOW` from the previous descriptor. A symlinked parent (`logs -> /elsewhere`, as in a cloned repo) is refused with `ErrSymlink`, as is one swapped in after the check. Linux reports `ENOTDIR` rather than `ELOOP` for a symlink opened with `O_DIRECTORY|O_NOFOLLOW`; the walk then `Lstat`s the typed prefix to report `ErrSymlink` (a race can only change which refusal is reported; the open has already failed). Interrupted (`EINTR`) walk syscalls are retried.
- **Final component not followed.** `Lstat` refuses a symlink (to a file, directory or nothing) before opening; the open uses `O_NOFOLLOW`, so a symlink swapped in after `Lstat` fails with `ELOOP` and is reported as `ErrSymlink`.
- **Identity and type re-checked on the open descriptor.** After the open, `Fstat` must be the same file as `Lstat` (`os.SameFile`, else `ErrChanged`) and a regular file (else `NotRegularError`). Directories, FIFOs, devices and sockets are refused with a typed error naming the kind.
- **No blocking.** The open uses `O_NONBLOCK`, so a FIFO swapped in after `Lstat` cannot hang the open; `O_NOCTTY` keeps a terminal device from becoming the controlling terminal. `O_NONBLOCK` is cleared before the file is returned, because Go never clears it.
- **Nothing is read** inside `safefs`; every check passes before any byte is read.
- **Fixed error text.** `Error()` never contains the path, file contents or OS error text; OS errors unwrap to a bare `syscall.Errno` so `fs.ErrNotExist` and `fs.ErrPermission` still match.
- **Fail closed.** Any unexpected condition closes the descriptor and refuses the open. Tests assert no descriptor leaks on every refusal path tests can trigger; the fstat and set-blocking failure paths are verified by inspection.
- **macOS system links.** `/tmp`, `/var` and `/etc` are symlinks to `private/...`, and `$TMPDIR` lives under `/var/folders`. A path with the literal prefix `/tmp/`, `/var/` or `/etc/` is rewritten to `/private/...` only if, at run time, that entry in `/` is a symlink owned by root whose target is exactly `private/<name>`. Other spellings (`//tmp`, `/./tmp`) are not rewritten and are refused. Entries in `/` are writable only by root, so a user or a cloned repo cannot forge them. The rest of the path is still checked by `O_NOFOLLOW_ANY`.
- **Relative paths.** Components after the current directory are checked; the current directory itself, and anything above it, is not re-checked (the kernel already resolved it).
- **Platforms.** macOS and Linux. Every other OS gets `ErrUnsupportedPlatform`; there is no plain-open fallback. `task cross` vets for windows, freebsd and linux (native, amd64 and 386); it proves compilation only, not behavior.

### Accepted risks

- **Directories need read permission on Linux.** The walk opens each directory `O_RDONLY`, so a search-only (`--x`) directory in the path fails with permission denied (fail closed).
- **macOS allowlist depends on the system layout.** If `/tmp`, `/var` or `/etc` are not root-owned links to `private/...`, no rewrite happens and such paths are refused; pass `/private/...` or a relative path.
- **Metadata traversal before refusal.** The pre-open `os.Lstat` resolves symlinked parents, so metadata access to the target (for example an autofs, NFS or FUSE mount) can happen before the refusal. A dangling symlinked parent may be reported as `cannot open` rather than `symlink refused`.
- **Not verified here:** behavior on kernels without `O_NOFOLLOW_ANY` (Go 1.27 requires a newer macOS, Assumed from the release notes, so older systems are out of support) and on filesystems that report unusual errnos.
- **Hard links.** A hard link to a regular file is a regular file and is not detected. Creating one needs only search permission on the target's directories, write permission on the destination directory and the same filesystem (macOS has no `protected_hardlinks`), but the file is still read only with the invoking user's permissions.
- **Content changes after open** (append, truncate) are not detected; the bounded read still applies.
- **Regular files on network or FUSE filesystems** can block on read.

## CLI (`cmd/redactscan`, `internal/cli`)

`redactscan redact [-summary] [FILE|-]` runs `redactor.Redact` over a file or stdin and writes the result to stdout. See `docs/features/redact-command/spec.md`.

### Controls

- **Fail closed.** Stdout receives a single write, only after `Redact` succeeds. Every non-zero exit leaves stdout empty. A verification failure is a hard stop with no retry.
- **Bounded read.** At most `MaxInputSize+1` bytes are read (`io.LimitReader`); longer input is refused.
- **Fixed messages.** Stderr text is built from fixed strings, redactor kind constants and the user-supplied path quoted with `strconv.Quote`. `err.Error()` from the redactor or the OS is never printed, so input bytes cannot reach stderr.
- **Wording.** Help and README never call the output safe; they state that other formats pass through.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, or help requested. |
| 1 | Redaction refused: too large, unsupported encoding, verification failed (kind named), or internal error. |
| 2 | Usage error. |
| 3 | I/O error: open, read, or stdout write. |

### Accepted risks

- **Symlinks anywhere in the input path are refused.** `openInput` uses `safefs.OpenRegular`; `redact logs/app.log` where `logs` is a symlink inside untrusted content (a cloned repo, an extracted archive) exits 3 with `symlink refused`. See ADR 0002.
- **Symlinked input files are refused.** Inputs that previously worked through a symlink now exit 3 with `symlink refused`; there is no flag to allow them.
- **Partial stdout write.** A closed stdout pipe ends the process via SIGPIPE (shell status 141); other write errors, such as a full disk, exit 3. Bytes already written are redacted output, never raw input.
- **`-o` output file** is not implemented; the temp-file-plus-rename rule applies when it is added.
