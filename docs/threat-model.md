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
| A profile or caller narrows redaction (`RedactWith` with `Options.Kinds`) and leaks an unselected kind | Selection only restricts which inputs succeed. All detection and verification always run; if any raw detector span (before merging) has an unselected secret kind, including one nested inside another span, the whole input is refused with nil output and a `VerificationError` naming the first such kind in the fixed order `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `GITHUB_TOKEN`, `PRIVATE_KEY`. Unselected kinds are never passed through. Invalid kind names return the constant `ErrUnknownKind` (case-sensitive, closed set, never echoed). Label-like text is neutralised whatever is selected. See [ADR 0004](adr/0004-kind-selection-refuses-never-passes-through.md). |

### Accepted risks

- **Equality and count metadata.** Labels reveal that two redacted values are equal and how many distinct values of each kind appeared. Labels are scoped to one call: the same label in two calls refers to unrelated values, and there is no mapping from a label back to a value. Any future re-hydration or session-wide pseudonym needs its own design and security review.
- **Narrow coverage.** Uncovered formats pass through unchanged.
- **False failures.** The verifier is deliberately broader than detection, so some benign inputs fail the whole input with `ErrVerificationFailed` (the error names the kind). Examples:
  - Any `github_pat_` followed by a word character, including prose, and identifiers ending in `ghs_` or `ghr_` (or another `gh?_` prefix) followed by 20 or more alphanumerics.
  - A truncated 20-35 character `ghp_` token.
  - `secret_access_key` followed by an unanchored 40 character run.
  - STS, IMDS and `credential_process` JSON (`"SecretAccessKey": "..."`) and Rails-style `secret_access_key:`: the detector requires an `aws` prefix on the key name but the verifier does not, so these fail instead of being redacted. Aligning detector and verifier is a possible follow-up.
- **Kind selection false failures.** With a narrowed selection, an unselected kind nested inside a selected span (for example an `AKIA` string inside a PEM body with only `PRIVATE_KEY` selected) refuses the input, although `Redact` would have covered it. The check runs on raw spans so nesting cannot hide an unselected kind; refusing is the fail-closed direction.
- **Over-redaction.** Unanchored matches inside longer identifiers, and text lost after a truncated PEM block or before an orphaned END marker.
- **Input held fully in memory.** Whole-input processing is bounded by the 10 MiB cap. Peak heap growth on adversarial 10 MiB inputs (dense keys, label-like spam) is about 9x the input size, roughly 100 MiB per call. Measured with a sampled peak-heap test: 9.1x here, 8.3-9.5x in review runs, against a 10x budget, so the margin is thin. The sampled figure is a lower bound: sampling every 50 microseconds measured 9.4x. A caller that runs `Redact` concurrently must bound the number of in-flight calls.

### Constraints for callers (future CLI, streaming, MCP)

- Bound the number of concurrent `Redact` calls: budget about 100 MiB of heap growth per in-flight call. Real memory use is higher under the default `GOGC`, so budget above that figure or set `GOMEMLIMIT`.
- Read at most `MaxInputSize+1` bytes (`io.LimitReader`) and reject anything longer; never split input across `Redact` calls (labels and multi-line blocks are per call).
- Open only regular files; validate paths and refuse unsafe symlink traversal. Met by `internal/safefs` (see "Safe file opening"): no symlink in any component of the path as typed.
- Write nothing until `Redact` succeeds. Output files go through `safefs.WriteSibling` (temp file in the pinned input directory, then atomic link or rename). A future `-o PATH` must reuse that rule; the CLI never writes a file by path.
- Treat `ErrVerificationFailed` as a hard stop, not a prompt to retry with fewer detectors.
- Do not retry a refusal for an unselected kind with a different selection to get past it. Adding the kind redacts it (the safe direction); deselecting a detected kind refuses.
- A future CLI, config or MCP exposure of kind selection must validate kind names through `RedactWith` (`ErrUnknownKind`), not with its own parsing, and must map `ErrUnknownKind` to a fixed message.

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

### Output files (`safefs.WriteSibling`)

`WriteSibling` creates a new file beside an input. The CLI uses it for `redact FILE` (see ADR 0003 and `docs/features/cleaned-file-output/spec.md`).

- **Pinned directory.** The directory is opened without following symlinks and pinned as an `os.Root` opened through that verified descriptor (`/proc/self/fd/<n>` or `/dev/fd/<n>`, never the path again, so a swapped directory or FIFO cannot redirect or hang it), with a `SameFile` check as defense in depth. The input's inode is checked in that directory, as a consistency check only: a lookalike directory holding a hard link passes it. All creates, links, renames and removes are single-component calls on that root, so a directory swapped mid-run cannot redirect the output. The typed path is re-verified before commit (`ErrChanged`).
- **Atomic, no partial output.** A 0600 `O_EXCL` temp file is written, fsynced and closed, then linked (no clobber, atomic `EEXIST`) or renamed (replace). A symlink at the destination is never written through. The temp file is removed on every error path.
- **Mode.** 0600 set with `Chmod` on the descriptor, so umask cannot change it.

Accepted risks: a fatal signal can leave a hidden `.redactscan-*.tmp` with redacted bytes; the directory fsync is best effort; inherited ACLs can widen access; other users can pre-create the destination in shared directories (no-clobber refuses), and in a group- or world-writable directory without the sticky bit they can also rename the closed temp file away and plant their own under its name before link or rename (equivalent risk); hard links to a replaced destination keep the old content; filesystems without hard links refuse no-clobber writes; root writes a root-owned file.

### Directory primitives (`safefs.OpenDirRoot`, `safefs.OpenChildDir`)

Building blocks for directory ingestion (see ADR 0004 and `docs/features/recursive-ingest/spec.md`). `internal/ingest` uses them.

- **`OpenDirRoot(path)`** opens a directory reached without a symlink in any typed component (same rules as `OpenRegular`) and returns it with an `os.Root` pinned through the verified descriptor. A regular file or FIFO root is `ErrNotDir` (the open uses `O_DIRECTORY|O_NONBLOCK`, so a FIFO cannot hang it); a symlink is `ErrSymlink`.
- **`OpenChildDir(parent, name, want)`** opens one component through the parent root with `O_DIRECTORY|O_NONBLOCK`, requires it to be the same file as the caller's `Lstat` result, and builds the child root from that descriptor. Any swap to a different object (FIFO, symlink to a FIFO or to another directory, a different directory, removal, an escaping link) is `ErrChanged`. `OpenDirRoot` also rejects `""` and NUL paths before any I/O.
- **Never `Root.OpenRoot(name)` for traversal.** It opens without `O_DIRECTORY` and `O_NONBLOCK`, so a directory swapped for a FIFO blocks it forever, and it follows a final in-root symlink.
- **Fixed error text,** as for the other `safefs` functions: no path, entry name or OS text.

Accepted risks: a swap to a symlink resolving to the same directory is indistinguishable from the original and is listed; a directory moved out of the root while its descriptor is held is still usable (it is listed under its old name); the primitives do not stay on one filesystem or bound a tree's size, which is the walker's job.

## Directory ingestion (`internal/ingest`)

`ingest.Walk(root, Limits)` lists a directory tree as `artifact.Artifact` values (regular files) and `finding.Finding` values (everything skipped). It reads no file contents. See ADR 0004 and `docs/features/recursive-ingest/spec.md`. The tree is untrusted.

### Controls

- **Pinned root, no symlink followed.** The root is opened with `safefs.OpenDirRoot`; every entry is `Lstat`ed through the pinned `os.Root`, and each child directory is opened with `safefs.OpenChildDir` (`O_DIRECTORY|O_NONBLOCK` plus a `SameFile` check against the `Lstat` result). Symlinks, FIFOs, sockets and devices are never opened or listed. A directory swapped mid-walk is reported as `ingest-changed`.
- **Symlink classification.** Each symlink gives one `ingest-symlink` Finding with `link_kind` `escape` (medium), `loop` (low), `dangling` (info), `in-root` (info) or `unknown` (medium, plus an integer `errno`). It is resolved with `Stat` on the top root and the slash-joined relative path (a child root would report in-root sibling links as escapes); `os.Root` refuses an escape before touching anything outside the tree. The link target is never recorded in a Finding or error.
- **Limits.** Depth 64 and 100,000 entries by default (caps 256 and 1,000,000; every name counts); paths longer than 1015 bytes are skipped. Memory and descriptors are bounded (about depth + 2 descriptors). Symlink classification CPU is not bounded by these limits (see accepted risks).
- **Fail closed.** Depth-skipped directories, entries cut by the limit, read errors, changed directories and over-long paths make `Walk` return the partial result with `ErrIncomplete` and one `ingest-incomplete` Finding. Symlinks and special files alone do not.
- **Fixed error text.** No path, name or OS text in any error or Finding description.

### Constraints for callers

- **Incomplete is never clean.** A result with `ErrIncomplete` is partial; never report it as a complete or clean scan.
- **Names are untrusted.** `RelativePath`, `Name` and `Finding.File` may contain control, ANSI and bidi characters or invalid UTF-8; escape them for display and never join them to a directory. Open `Artifact.Path` only with `safefs.OpenRegular`.
- **`link_kind` is a label, not a guarantee.** `loop` also covers a chain longer than the OS or `os.Root` link limit (about 8 links), not only a cycle. A symlink with an empty target (creatable on macOS only) is labelled `escape`. `unknown` means resolution failed for another reason, for example `errno=EACCES` on a directory without search permission.
- **Future archive extractor.** It must refuse hard links and absolute or escaping link targets; directory ingest does not detect hard links.

### Accepted risks

- **Hard links** to files outside the tree are listed as regular files (see Safe file opening).
- **Directory moved out of the root** while its descriptor is held is listed once under its old relative path. A swap to a symlink that resolves to the same directory is indistinguishable from the original and is listed.
- **Mount points** are crossed. Scanning `/` reaches `/proc` (for example `/proc/self/environ` as a regular file) and `/dev` (devices skipped). Listing reads no content. `-xdev` is a follow-up.
- **No timeout, no `context`.** A hung network filesystem can block the walk, and so can a hostile tree (next item). A `context`/timeout is a follow-up.
- **Symlink classification CPU cost (user-accepted risk).** `Root.Stat` resolves link targets in user space with one `openat(O_NOFOLLOW|O_DIRECTORY)` plus close per target component, across up to 8 chained links. The cost is bounded by target length times hops, not by `MaxDepth` or `MaxEntries`: the walker skips directories deeper than `MaxDepth`, but they still exist and `Stat` walks them. A hostile tree of about 480 nested directories plus up to about 100,000 links that each point deep makes the walk slow. Measured per link: macOS arm64 21.7 ms for a 480-level target versus 4.8 us for a short one (about 4,500x; 5,000 links take about 108 s); Linux (`golang:1.27`) 270 us versus 3.3 us (about 80x). Extrapolated to 100,000 links: about 36 min on macOS and about 27 s on Linux (extrapolated; chaining several hops multiplies it further, assumed, not measured). No confidentiality or integrity impact; a CI job that times out fails closed. The user accepted this risk (no code bound, no child-root-first optimisation). Recommended hardening before running on untrusted uploads or in an MCP service: a classification step budget (a deterministic step count; links past the budget become `unknown`, medium) alongside the `context` follow-up.
- **Mid-walk ancestor swap.** An ancestor directory swapped or moved while the walk runs can only mislabel a link: classification re-resolves from the top root and stays confined to it, so it cannot escape.
- **Stale `Size`** is informational; content readers must re-check.
- **Entries cut by `MaxEntries`** inside a directory depend on filesystem order; the walk is reported incomplete.
- **Descriptors.** `MaxDepth` near 256 can hit `EMFILE` under a 256-descriptor soft limit; it surfaces as `ingest-read-error` (incomplete), not a crash. During symlink classification the count is briefly `MaxDepth + 4`. An `EMFILE` during classification degrades that link's label to `unknown` (errno 24, medium) and does not make the walk incomplete.
- **Memory.** Measured on macOS arm64: about 1.04 KiB (1.07 kB) allocated per Artifact with short paths and about 2.1 KiB at 1015-byte paths, so a walk of 100,000 maximum-length Artifacts allocates about 215 MB (allocation, not retained). Retained heap is about 275 B per short-path Artifact (measured) and about 126 MiB at the cap with 1015-byte paths (extrapolated). Findings are similar in size and are also bounded by `MaxEntries`. There is no total path-bytes budget.

## CLI (`cmd/redactscan`, `internal/cli`)

`redactscan redact [-quiet | -json] [-stdout] [-force] [FILE|-]` runs `redactor.Redact` over a file or stdin. With FILE the result goes to `<name>_cleaned<ext>` beside FILE (mode 0600, no clobber unless `-force`); with stdin, or with `-stdout`, it goes to stdout. See `docs/features/redact-command/spec.md` (superseded for FILE output) and `docs/features/cleaned-file-output/spec.md`.

### Controls

- **Fail closed.** Nothing is created or written until `Redact` succeeds. Stdout receives a single write; the output file appears only through `WriteSibling`. Every non-zero exit leaves nothing written anywhere: stdout is empty and no output or temp file remains (a failed temp removal is reported with a fixed line). A verification failure is a hard stop with no retry.
- **Bounded read.** At most `MaxInputSize+1` bytes are read (`io.LimitReader`); longer input is refused.
- **Fixed messages.** Stderr text is built from fixed strings, redactor kind constants and the user-supplied path quoted with `strconv.Quote` (the derived output path is quoted in the typed spelling, never an OS-resolved path). Write errors are mapped by errno or sentinel to a fixed reason. `err.Error()` from the redactor or the OS is never printed, so input bytes cannot reach stderr.
- **Summary.** Counts by kind on stderr after success only, never values (text and `-json` are built from kind constants and integers); `-quiet` silences success output; `-json` prints counts only; `-quiet` with `-json` is a usage error. No summary is printed on any failure.
- **Wording.** Help and README never call the output safe; they state that other formats pass through.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, or help requested. |
| 1 | Redaction refused: too large, unsupported encoding, verification failed (kind named), or internal error. Nothing is written anywhere. |
| 2 | Usage error. |
| 3 | I/O error: open, read, stdout write, or output create, link or rename failure, including a refused destination (exists without `-force`, symlink, non-regular, changed during write). |

### Accepted risks

- **Symlinks anywhere in the input path are refused.** `readInput` opens FILE with `safefs.OpenRegular`; `redact logs/app.log` where `logs` is a symlink inside untrusted content (a cloned repo, an extracted archive) exits 3 with `symlink refused`. See ADR 0002.
- **Symlinked input files are refused.** Inputs that previously worked through a symlink now exit 3 with `symlink refused`; there is no flag to allow them.
- **Partial stdout write.** A closed stdout pipe ends the process via SIGPIPE (shell status 141); other write errors, such as a full disk, exit 3. Bytes already written are redacted output, never raw input.
- **Breaking default.** `redact FILE` no longer prints; `redact f | cmd` gets empty stdout with exit 0. `-stdout` restores it (ADR 0003).
- **No `-o PATH`.** The output name is derived; an explicit path is not implemented and would need the `WriteSibling` rules.
- **Derived name may escape ignore and sync rules** (`.env` becomes `.env_cleaned`), and uncovered secret formats pass through to the file; stderr carries a fixed reminder on every write.
- **Flags before FILE.** A flag after FILE is a usage error.

## Scanner (`internal/scanner`, `scan` command)

`redactscan scan FILE` runs every registered scanner over one file and prints findings. See `docs/features/scanner-scan-file/spec.md` and ADR 0004. No production scanners exist yet, so every real scan is incomplete (`no scanner ran`, exit 1).

### Trust boundary

Scanned content is untrusted, and so is scanner output, because it is derived from that content. The terminal and later report consumers are less trusted.

### Controls

- **Never executed.** The CLI only reads, through `safefs.OpenRegular` (symlinks, FIFOs, devices and directories refused). No `os/exec` in `internal/scanner` or `internal/cli`; an import-allowlist test keeps `os`, `os/exec`, `syscall`, `net`, `plugin`, `unsafe`, `log` and `internal/safefs` out of `internal/scanner`.
- **Bounded input.** At most `MaxContentSize+1` bytes are read; an over-cap file is incomplete, never truncated.
- **Fail closed.** An error, panic (including `panic(nil)`) or `runtime.Goexit` in a scanner, an invalid finding, cancellation, the 1000-findings cap, an invalid artifact, an empty or all-unsupported registry: each is a recorded `Failure` and exit 1. Each `Supports` and `Scan` call runs on its own goroutine that `Run` waits for.
- **No content in messages.** Error and panic values are never stored or printed. Failure lines use validated scanner names and constant reasons.
- **Output minimisation.** Only severity, ID, File, Line and Title are printed. ID, File and Title are `strconv.Quote`d, so control and bidi characters appear escaped. ID, Title, File and Evidence must pass a `redactor` check (anything but label-like text drops the finding), and ID and Title are bounded to 128 bytes of UTF-8, File to 4096 bytes.
- **Registry.** Names are validated, unique and captured once; `registry` is reserved for failures not tied to a scanner.
- **Scanner contract.** Scanners must not modify `content` or `a.Metadata`, spawn goroutines that outlive `Scan`, exit the process, or put scanned content in errors or panics. `scannertest.AssertNoMutation` checks mutation in each scanner's tests.

### Exit codes (provisional until REDACT-50)

0 complete (any number of findings), 1 incomplete, 2 usage error, 3 open, read or stdout write error.

### Accepted risks

- No per-scanner timeout: a hung scanner blocks the scan until interrupted.
- `content` and `a.Metadata` are shared read-only by contract only; mutation is not detected at runtime.
- A complete scan with high-severity findings exits 0 until REDACT-50 adds a findings exit code.
- A panic in a goroutine a scanner started itself is not recovered; the process crashes with Go's exit status 2, the same as a usage error.
- The redactor check covers only the redactor's covered formats.
- A file modified in place during the read can yield mixed content.
- Invalid-finding floods are not capped: only accepted findings count toward `MaxFindings`, so a scanner returning many invalid findings costs about 1.7 s per million secret-shaped ones (measured). Deferred to REDACT-37 or REDACT-39.
- A legitimate finding whose ID, Title, File or Evidence resembles a covered secret format is dropped as `invalid finding` (fail closed).

## Live log sources (`internal/logs`)

`logs.FileSource` follows one log file like `tail -F` and delivers complete lines to a later redaction pipeline. See `docs/features/file-log-source/spec.md` and ADR 0005. The package is not wired to the CLI yet.

### Trust boundary

The adapter is where untrusted file state (path, content, line lengths) enters a long-running stream. `LogEntry.Line` holds raw, unredacted data.

### Controls

- **Safe open.** The file is opened through `safefs.OpenRegular`: no symlink in any typed component, regular files only, no blocking on a FIFO. A refusal is returned from `Read` before any channel exists.
- **Complete lines only.** A line is emitted only when its `\n` has been read and it is within `MaxLineBytes` (default 64 KiB, at most 1 MiB). A line over the cap, a pending line cut off by truncation or rotation, and the fragment of a line already in progress when reading starts each become one marker with no content, so a secret is never split across what the redactor sees.
- **Bounded memory.** Per `Read`: at most `MaxLineBytes` for the pending line plus a fixed 32 KiB buffer. Lines are found by scanning the fixed buffer; no `bufio.Scanner`, `ReadBytes` or `io.ReadAll`. The channel is unbuffered, so a slow consumer slows reading.
- **Safe reopen on rotation.** Each tick compares `Lstat(path)` with `Fstat` of the held descriptor (never with an earlier `Lstat`) using `os.SameFile`. On a mismatch the old file is read only up to its size at detection, the descriptor is closed, and the path is reopened through `safefs.OpenRegular` (symlink, FIFO, directory and device are refused). The new file must have the same owner uid as the first file and exactly one hard link, or the stream ends with `ErrReopenRefused`. This closes the planted-hard-link and foreign-file gaps at the one point an attacker controls.
- **Fixed error text.** No error contains the path, the label, line content or OS error text. OS errors unwrap to a bare `syscall.Errno`. The label is validated (bounded UTF-8, no control, format or line and paragraph separator characters) and `Name()` never returns the path.
- **Fail closed.** Every reopen refusal, an `Lstat` error other than not-found, and a `Fstat` or read error on the held descriptor end the stream with one final `Err` entry (the descriptor is closed first) and then close the channel. The read-error path cannot be triggered on a local filesystem without fault injection, so it is verified by inspection, as safefs did for `fstat`.
- **Resources.** One descriptor and one goroutine per `Read`; both are released when the channel closes. Every send also waits on `ctx.Done()`, and the read loop checks `ctx` before each read, so cancellation also stops reading a region that produces no entries.
- **Never executed.** The package does not import `os/exec` and logs nothing.

### Constraints for callers

- Redact with context across lines (a PEM block or wrapped token spans several entries): the guarantee is "no partial line", not "a secret stays on one line".
- Never expose `Line` outside the process (MCP, logs) before redaction.
- Escape CR, NUL, ANSI and bidi characters before display.
- Bound concurrent `Read` calls in any MCP layer: each costs one descriptor, one goroutine and up to `MaxLineBytes` plus 32 KiB.
- Always cancel `ctx`. A consumer that stops reading without cancelling pins one goroutine and one descriptor; the adapter cannot detect it.
- Never use `Dropped` as a size for allocation. It is a lower bound on the discarded bytes.

### Accepted risks

- **Huge newline-free regions.** While `ctx` is live, reading a very large file or sparse region without newlines costs CPU, and the truncation and rotation checks wait until that read finishes. There is no per-tick byte cap.
- **No hard-link check on the first open.** A hard link created before `Read` is not detected; this matches the safefs accepted risk. macOS has no `protected_hardlinks`, so any user who can write the log directory can plant a link to a file they cannot read. The file is read with the invoking user's permissions, so when the tool runs as root or another privileged user, a link planted before `Read` can pull that file's content into a less-trusted downstream consumer (an MCP server or AI agent). Rotation reopens are protected by the link-count check.
- **`copytruncate` regrowth.** If the file is truncated and grows past the read offset within one poll interval, the truncation is missed and reading resumes mid-line in the new content. Unlike the start position there is no fragment skip, so a mid-line fragment can be emitted as a line.
- **`/proc` and `/sys` files** report size 0, so the content is re-emitted every poll. Unsupported input.
- **Blocking I/O on network filesystems.** A `Fstat` or read that hangs on NFS or FUSE blocks the loop; cancellation takes effect afterwards.
- **Lost lines around rotation.** Two rotations within one poll interval skip the intermediate file, and bytes a writer appends to the old file after the rotation was detected (past its size at detection) are not read.
- **Ownership or hard-link changes end the stream.** A rotation that changes the file owner, or a log that legitimately has a second hard link, is refused with `ErrReopenRefused`. This is an operational cost of the checks.
- **Inode identity on NFS, FUSE and overlayfs.** `os.SameFile` may report a rotation falsely or miss one.
- **A blocking `Lstat`** on a hung network filesystem blocks the loop until it returns.
- **A removed path with no new file** keeps the held descriptor being read with no error; after a rotation drain with no new file the source waits, holding no descriptor, until the path reappears.
- **Cross-line secret splitting** (see the caller constraints).

## Quarantine store (`internal/quarantine`)

The store keeps suspicious content (scan decision `review` or `block`) and its metadata under `~/.redactscan/quarantine`. See `docs/features/quarantine-store/spec.md` and ADR 0006. Nothing calls it yet except tests; the commands that will (REDACT-57 to 60) inherit the constraints below.

### Trust boundary

The store tree under the base directory, owned by the invoking user. Adversaries are hostile scanned content (bytes, file names, URIs and findings derived from it) and other local users. Out of scope: processes running as the same uid (they can already read mode 0700 and 0600), and root.

### Controls

- **Exact modes.** Directories are 0700 and files 0600, set with `fchmod` on descriptors, never by path and never from the umask. Execute, setuid, setgid and sticky bits never reach the store.
- **Refuse, do not repair, entries.** `Open` repairs only the store's own top-level directories (and reports them). `Read` and `Verify` refuse an entry directory that is a symlink, not a directory, foreign-owned or not exactly 0700 (including setuid, setgid and sticky), and refuse before opening it. A wrong mode on an entry is a tamper signal.
- **Symlink and swap safety.** Every directory is pinned with `safefs.OpenChildDir` and every file opened with `safefs.OpenRegularIn` (Lstat, non-blocking open, `SameFile`, regular file, euid owner), so a FIFO, symlink (including one into the same entry) or other substitute is refused without blocking.
- **Strict metadata.** `metadata.json` must be a euid-owned 0600 regular file of at most 4 MiB, decoded with `encoding/json/v2` (duplicate, case-variant and unknown members and trailing data are refused), with `id` equal to the directory name and `sha256` equal to the ID prefix. Failure is `ErrCorruptMetadata` and no partial metadata.
- **Complete means published.** An entry is complete only once `metadata.json` exists. Content and metadata are placed with a no-replace hard link, so an existing file is never overwritten. `Read` also requires `content` to be a euid-owned 0600 regular file of exactly `metadata.size` bytes.
- **Verification.** `Verify` re-hashes at most `size+1` bytes of `content` (read from offset 0, independent of the descriptor offset) and compares count and SHA-256. Content that is missing, swapped for a non-regular file or symlink, foreign-owned, unreadable or mode-changed, or whose size, count or hash differs is `ErrVerifyFailed`; only an unexpected OS error keeps its bare Errno. `Read` never re-hashes (O(size) work belongs to release); it reports bad `content` state as `ErrIncomplete`.
- **IDs are never paths.** `ValidID` (`^[0-9a-f]{64}-[0-9a-f]{16}$`) runs before any filesystem call; Name and URI are display data and never path components.
- **Bounded and clean input.** Name and URI are bounded and redactor-checked on `Put`, a URI with userinfo, query, fragment or a scheme other than https, http or file is refused, and metadata over 4 MiB is refused before anything is written. The store budget (`MaxEntrySize`, `MaxStoreBytes`, `MaxEntries`) is checked before any write.
- **No content in messages.** Errors have fixed text and OS errors unwrap to a bare `syscall.Errno`: no path, ID, name, URI, finding text or OS error text. Marker tests cover every `Open`, `Put`, `Read` and `Verify` failure path.
- **Root refusal.** euid 0 is refused unless `Options.AllowRoot` is set.

### Constraints for callers (REDACT-57, 58, 59, 60)

- **REDACT-58 (release, delete):** never derive a release path from the stored Name or URI; choose the destination independently. Preferred: hash while copying (`io.MultiWriter` or `io.TeeReader` over `io.LimitReader(f, size+1)`) from the opened content descriptor into a no-clobber temporary destination, and publish only when the count equals `metadata.size` and the SHA-256 matches. Alternative: `verifyContent` on the descriptor, then copy with `ReadAt` or an `io.SectionReader` from offset 0, requiring `n == size`. Verification and copy are two separate reads in the alternative, so only hash-while-copying closes the window in which the bytes can change; REDACT-58 must carry a regression test that a release after `Verify` is byte-identical to the verified content. Never repair or delete to make room for a `Put`.
- **REDACT-57 and CLI output:** escape control and bidi characters in Name, URI and finding strings before printing them.
- **MCP:** treat Name, URI and findings as untrusted quoted data. Nothing, including `Read`, returns content bytes.
- **Failures are not clean.** `ErrStoreFull`, `ErrMetadataTooLarge` and every other `Put` failure mean "not quarantined or incomplete", never "clean".
- **REDACT-59/60 (watcher):** serialize `Put` calls (the budget check is not locked). Findings passed to `Put` must come from `scanner.Registry.Run` (redactor-checked); another producer must apply the same checks.
- **URI schemes:** the allowlist (https, http, file) will need extending for ssh and scp git sources; that is a deliberate change to the validation rule, not a bypass.

### Accepted risks

Recorded as user-accepted in ADR 0006.

- **Raw content at rest.** Quarantined content is stored unencrypted, appears in backups, and has no retention policy; deleting entries is a later command.
- **sha256 in every ID.** Anyone who can see an entry name can test guesses of low-entropy content offline. Seeing the names needs our uid, given 0700.
- **Orphan temp files.** A crash during `Put` can leave `.tmp-*` files holding raw content (0600) or an entry directory without `metadata.json`. They count against the budget; cleanup is deferred (REDACT-58 orphan cleanup, to be filed; no issue exists yet).
- **Unserialized budget.** Concurrent `Put` calls, in one process or several, can exceed the entry and byte budget.
- **Same-uid hard links.** An extra hard link to an entry file by the same user is not refused (an `nlink` of 2 can also be legitimate after a failed temp removal).
- **Spotlight marker.** `.metadata_never_index` is best effort; whether current macOS honours it for a non-volume-root folder is not verified.
- **macOS ACLs.** Extended and inherited ACLs are not inspected or cleared. A base under a folder with an inheritable allow-read ACE can expose entries despite the 0700 and 0600 checks. Linux POSIX ACLs are neutralised by the mode mask. Enforcement would need cgo or `x/sys` and is deferred.

### Open residual risks (acceptance pending)

Not yet accepted by the user and not recorded in ADR 0006.

- **Budget counts files only (not directory blocks or in-flight temps).** Directory blocks, `.meta-*.tmp` files in incomplete entries and concurrent overshoot are not counted.
- **Post-link cleanup failure.** If a `Put` fails after `metadata.json` was linked (for example on an fsync) and the best-effort removal of that entry also fails, the call reports an error but a valid entry remains; a retry stores the content again as a second entry.
- **`file:` URIs** store local paths in plaintext metadata.
- **Source modified in place.** A same-size in-place modification during the copy is not detected; the stored hash still matches the stored bytes.
