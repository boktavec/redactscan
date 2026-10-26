# Redact command: spec

Status: implemented, pending PR.
Superseded in part: FR1 and FR7 describe `redact FILE` printing to stdout. Since REDACT-11 (`docs/features/cleaned-file-output/spec.md`, ADR 0003) FILE writes `<name>_cleaned<ext>` by default and `-stdout` restores the behavior below; stdin is unchanged.
Story: [REDACT-2](http://localhost:8080/issue/REDACT-2) "redact command: file or stdin to stdout".
Follow-up: [REDACT-10](http://localhost:8080/issue/REDACT-10) "Safe input file opening" replaces the `openInput` seam (see 3.3).
Branch: `feat/redact-command`. Packages: `cmd/redactscan`, new `internal/cli`, small change to `internal/redactor` (Go stdlib only).
Related: `docs/architecture.md` section 14, `docs/threat-model.md` "Constraints for callers", ADR `docs/adr/0001-redactor-core-pseudonyms-and-fail-closed.md`, `docs/features/redactor-core/spec.md`.

> Spec text and tests never contain realistic secret values. Tests build secret-shaped input at runtime.

## 1. Feature overview

**Purpose.** Give users a command that runs the existing redactor core over a file or stdin and writes the redacted text to stdout, failing closed: if the redactor refuses, nothing reaches stdout and the input is never echoed.

**In scope**

- `redactscan redact [-summary] [FILE|-]`.
- Thin `cmd/redactscan/main.go`; all logic in `internal/cli.Run(args, stdin, stdout, stderr) int`.
- Bounded read (`MaxInputSize+1` bytes) and refusal of longer input.
- Exit codes 0 ok, 1 refused by the redactor, 2 usage, 3 I/O.
- Fixed, CLI-owned stderr messages; verification failures name the kind only.
- Opt-in `-summary` on stderr.
- Typed `redactor.VerificationError` so the CLI can read the kind without parsing strings.
- Threat model CLI section; short README usage section.

**Non-goals**

- Safe file opening (regular files only, no symlinks, FIFOs, devices): REDACT-10. This story uses plain `os.Open` behind one seam.
- `-o` output file (the threat model's temp-file-plus-rename rule applies when it is added).
- Streaming, chunked or multi-file input; directory scanning; config; profiles; the `scan` command; MCP.
- TTY detection on stdin (an interactive terminal waits for input, like `cat`).
- Fixing `docs/architecture.md` naming ("Sentinel"); already tracked as a follow-up in the threat model.

**Wording.** Help text, README and messages never call the output "safe to share" or "safe". They say the command replaces covered secret formats and that other formats pass through.

## 2. Functional requirements and acceptance criteria

| ID | Requirement | Acceptance |
| --- | --- | --- |
| FR1 | `redactscan redact FILE` reads FILE, redacts, writes output to stdout. | Exit 0; stdout equals `Redact(content).Output`; stderr empty. |
| FR2 | `redactscan redact -` and `redactscan redact` (no FILE) read stdin. | Same as FR1 for both forms. When FILE is given, stdin is not read. |
| FR3 | Input is read with `io.LimitReader(r, MaxInputSize+1)`. Input longer than `MaxInputSize` is refused. | Exactly 10 MiB: exit 0. 10 MiB + 1: exit 1, stdout empty, stderr `redactscan: redaction refused: input exceeds 10 MiB limit`. |
| FR4 | Unsupported encoding is refused. | NUL byte or UTF-16/32 BOM input: exit 1, stdout empty, stderr `redactscan: redaction refused: unsupported encoding (NUL byte or UTF-16/32)`. |
| FR5 | Verification failure is a hard stop, no retry. | Exit 1, stdout empty, stderr `redactscan: redaction refused: output could not be verified (kind: <KIND>)`; `Redact` called exactly once. If the kind cannot be determined: `(kind: unknown)`. |
| FR6 | Any other error from `Redact` fails closed. | Exit 1, stdout empty, stderr `redactscan: redaction refused: internal error`. |
| FR7 | Stdout receives exactly one write, only after `Redact` succeeds. | On every non-zero exit, stdout is empty. |
| FR8 | No message ever contains input bytes. | For every refusal and I/O test, stderr contains none of the input (tests assert the secret-shaped bytes and a marker string from the input are absent). Messages are built from fixed text, the kind constant and the quoted path; `err.Error()` from the redactor or the OS is never printed. |
| FR9 | I/O failures exit 3 with a fixed reason and the quoted path. | Missing file: `redactscan: cannot open "<path>": not found`. Permission: `... permission denied`. Other open errors: `... cannot open`. Read failure (including a directory): `redactscan: cannot read "<path>": read failed` (stdin uses `stdin` in place of the quoted path). Stdout write failure or short write: `redactscan: cannot write output: write failed`. Path is quoted with `strconv.Quote` so control characters in a filename cannot drive the terminal. |
| FR10 | Usage errors exit 2 with usage on stderr. | No subcommand, unknown subcommand, unknown flag, more than one positional argument: exit 2, stdout empty, stderr starts with a one-line reason then usage. A flag after FILE (`redact app.log -summary`) counts as a second positional argument (Go `flag` stops at the first non-flag). |
| FR11 | Help exits 0 with usage on stdout. | `redactscan -h`, `redactscan -help`, `redactscan redact -h`, `--help` variants: exit 0, usage on stdout, stderr empty. |
| FR12 | **Superseded by `docs/features/redaction-summary/spec.md` (REDACT-13): the summary is now on by default in every mode, `-summary` is a no-op, and `-quiet`/`-json` control it.** `-summary` writes one line to stderr after a successful stdout write. | Kinds sorted by name: `redactscan: redacted AWS_ACCESS_KEY=2 GITHUB_TOKEN=1`. No secret kinds: `redactscan: no covered secret formats found`. If `Counts[KindLabelLike] > 0`, append `; neutralised N label-like`. Without `-summary`, stderr is empty on success. Counts are distinct values per kind (as `Result.Counts`). `--summary` also works. |
| FR13 | Help text never describes output as safe. | Test: usage text does not contain `safe to share` (case-insensitive) or `safely`. Help lists covered formats, says other formats pass through unchanged, gives the 10 MiB limit and the exit codes. |
| FR14 | Empty input succeeds. | Exit 0, stdout empty. |

## 3. Technical design

### 3.1 Layout

```
cmd/redactscan/main.go        os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
internal/cli/cli.go           Run, subcommand dispatch, usage text, exit codes
internal/cli/redact.go        redact subcommand: parse, open, read, Redact, write, summary
internal/cli/cli_test.go      table-driven tests through Run
internal/redactor/redactor.go VerificationError type; verifyError returns it
```

Splitting `cli.go` and `redact.go` is optional; one file is fine if it stays under about 200 lines.

### 3.2 Flow of `redact`

1. Parse flags with a per-call `flag.NewFlagSet("redact", flag.ContinueOnError)`, output to `io.Discard` (the CLI prints its own usage so the message format is controlled). `flag.ErrHelp` maps to help (exit 0). Any other parse error maps to usage (exit 2).
2. Zero or one positional argument; `-` or none means stdin.
3. Open input through `openInput(path string) (io.ReadCloser, error)`. Stdin is simply never closed by the CLI. The file is closed on every path (`defer`).
4. `data, err := io.ReadAll(io.LimitReader(r, redactor.MaxInputSize+1))`. Read error: exit 3.
5. `res, err := redactor.Redact(data)`. `Redact` itself rejects `len(data) > MaxInputSize`, so the CLI does not need its own length check; it maps `ErrInputTooLarge` like the other refusals. Mapping uses `errors.Is` / `errors.As` only.
6. One `stdout.Write(res.Output)`. Error or short write: exit 3. Skip the write when the output is empty.
7. If `-summary`, write the summary line to stderr. Exit 0.

### 3.3 The `openInput` seam (known gap until REDACT-10)

`openInput` is the only function that touches the filesystem. In this story it is `os.Open(path)`. That means:

- A symlink is followed, a FIFO with no writer blocks the open, a device is read, and a directory opens and then fails on read (exit 3).
- REDACT-10 replaces the body with `safefs.OpenRegular(path)` and adds its typed errors to the exit-3 message mapping. No other code changes.

This gap is recorded in the threat model CLI section and in the PR.

### 3.4 Typed verification error

```go
// VerificationError reports which kind failed verification. It matches
// ErrVerificationFailed with errors.Is and carries no input data.
type VerificationError struct{ Kind Kind }

func (e *VerificationError) Error() string { /* "redactor: verification failed: KIND" (unchanged text) */ }
func (e *VerificationError) Is(target error) bool { return target == ErrVerificationFailed }
```

`verifyError(kind)` returns `&VerificationError{Kind: kind}`. The error text is identical to today's `fmt.Errorf("%w: %s", ...)` form, so existing tests and `errors.Is` callers keep working. The CLI uses `errors.As(err, &ve)`; if `errors.Is(err, ErrVerificationFailed)` holds but `errors.As` does not, it prints `kind: unknown`.

### 3.5 Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, or help requested. |
| 1 | Redaction refused: too large, unsupported encoding, verification failed, or unexpected redactor error. |
| 2 | Usage error. |
| 3 | I/O error: open, read, or stdout write. |

### 3.6 Third-party (stdlib) behavior relied on

- **Verified** (`go doc flag`, Go 1.27.1): one or two dashes are equivalent, so `--summary` works; parsing stops before the first non-flag argument and `-` is a non-flag argument; `flag.ErrHelp` is returned for `-h`/`-help` when not defined.
- **Verified** (`go doc flag`): `ContinueOnError` makes `Parse` return the error instead of exiting.
- **Assumed**: on macOS and Linux, `os.Open` on a directory succeeds and the first `Read` fails, so a directory argument exits 3 via the read path. The directory test confirms this; if `Open` fails instead, it still exits 3 via the open path, and the test asserts exit 3 only.
- **Assumed**: `errors.Is(err, fs.ErrNotExist)` / `fs.ErrPermission` classify `*PathError` from `os.Open` on both platforms (documented behavior of `os`; confirmed by the missing-file test, permission test skipped when running as root).

## 4. Data/API changes and migrations

- New package `internal/cli` with exported `Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int`.
- New exported type `redactor.VerificationError`. Error text unchanged. No other API change.
- No data, config or migrations.

## 5. Engineering decisions and rationale

| Decision | Rationale | Alternatives |
| --- | --- | --- |
| Subcommand `redactscan redact` | Matches architecture section 14 and leaves room for `scan`. | Top-level `redactscan FILE`: blocks future subcommands. |
| Stdlib `flag`, per-call `FlagSet` | No dependency; testable without global state. | cobra/urfave: a dependency for one flag. |
| Exit code 3 for I/O | Keeps 1 as a clean "refused" security signal for scripts and future wrappers. | Fold I/O into 1: scripts cannot tell missing file from refusal. |
| CLI-owned messages, never `err.Error()` | The "never echo input" guarantee must not rest on library or OS error formatting. | Print errors as is: least code, weaker guarantee. |
| Typed `VerificationError` | Honest contract; cannot drift silently like string matching. | Match `err.Error()` against kind constants: brittle. |
| `-summary` opt-in | Quiet default for pipes; feedback when asked. | Always-on summary; no summary. |
| One stdout write after success | Nothing partial reaches stdout on refusal. | Streaming write: impossible with whole-input redaction anyway. |
| `openInput` seam with plain `os.Open` | REDACT-10 is a separate story; one function keeps its change local. | Block on REDACT-10: delays a usable CLI. |

No ADR: these are local, reversible CLI conventions. If exit codes become a published contract for MCP or wrappers, record them in an ADR then.

## 6. Risks and failure modes

| Risk | Handling |
| --- | --- |
| Symlink, FIFO or device as FILE (plain `os.Open`) | Known gap until REDACT-10; documented. A FIFO with no writer blocks; the user can Ctrl-C. Nothing is written on failure. |
| Partial stdout write (closed pipe, full disk) | Exit 3. Bytes already written cannot be recalled; they are redacted output, never raw input. |
| SIGPIPE when stdout is a closed pipe | Go's runtime exits on SIGPIPE for writes to fd 1/2 (Verified: reproduced on macOS, shell status 141); either way no raw input is written. |
| Stdin is a terminal | Waits for EOF, like `cat`. Documented in help. |
| Memory | One `Redact` call per process: about 100 MiB peak on adversarial 10 MiB input (threat model). No concurrency. |
| False verification failures | Exit 1 with the kind, so the user knows which pattern fired (documented in the threat model). |
| Kind text in stderr | From fixed constants only, never input. |

## 7. Security

- Input is untrusted and never executed; never echoed to stdout on refusal or to stderr ever.
- Fail closed: any redactor error means exit 1 and empty stdout; no retry with fewer detectors.
- Only the user-supplied path is echoed, quoted with `strconv.Quote`.
- Bounded read enforces the threat model's `MaxInputSize+1` rule.
- Known gap: no symlink or file-type checks until REDACT-10.
- Wording: output is never described as safe.
- Security reviewer required (scanned-content parsing, redaction, file handling).

## 8. Performance/scalability

Single in-memory read of at most 10 MiB + 1 and one `Redact` call. No concurrency, no caching. Nothing further needed.

## 9. Implementation steps

Each step ends with `task test` passing.

1. **Typed verification error** (`internal/redactor`). Depends on: nothing. Add `VerificationError`, make `verifyError` return it. Tests: `errors.As` yields the kind for a known false-fail input; `errors.Is(err, ErrVerificationFailed)` still true; `err.Error()` text unchanged. Expected: existing redactor tests pass unchanged.
2. **`internal/cli` skeleton and usage.** Depends on: nothing. `Run` with subcommand dispatch, usage text, help (exit 0, stdout) and usage errors (exit 2, stderr). Tests: no args, unknown subcommand, `-h` at both levels, unknown flag, two positional args, flag after FILE, help text wording (FR13).
3. **`redact` happy path.** Depends on 2. `openInput` seam, bounded read, `Redact`, single write. Tests: temp file with runtime-built secrets; stdin via `-` and no argument; empty input; FILE given while stdin has data (stdin ignored).
4. **Refusals and I/O errors.** Depends on 1 and 3. Error mapping to exit 1 and 3 with fixed messages. Tests: exactly 10 MiB passes; 10 MiB + 1 refused; NUL; UTF-16 BOM; verification failure (runtime-built truncated `ghp_` token) names `GITHUB_TOKEN`; missing file; directory; unreadable file (skip as root); failing stdout writer; short-write writer; reader that errors mid-read. Every case asserts empty stdout and that stderr contains no input bytes.
5. **`-summary`.** Depends on 3. Tests: sorted kinds; no secrets message; label-like suffix; `--summary`; absent flag means empty stderr.
6. **`main.go`.** Depends on 2. One line calling `cli.Run`. Manual check with `go run`.
7. **Docs.** Depends on 1-6. Add a `## CLI (cmd/redactscan, internal/cli)` section to `docs/threat-model.md` (exit codes, stderr rules, the `openInput` gap and REDACT-10, wording). Add a short usage section to `README.md` and reword its "safely redacting" phrase so it does not imply safe output.

Expected size: about 130 lines of code, 15 in `redactor`, 250 of tests, under the 500-line split point. One PR.

## 10. Testing strategy

- Table-driven tests through `Run` with `bytes.Buffer` / `strings.Reader` and real temp files (`t.TempDir()`); no mocks of the CLI or redactor.
- Fakes only at the outer boundary: a failing writer, a short writer, and a reader that errors after some bytes (to simulate I/O faults the OS will not produce on demand). Each is noted in the test.
- Secret-shaped inputs built at runtime (no literals that gitleaks would flag).
- Negative paths weighted equally: every refusal and I/O case asserts exit code, empty stdout, exact stderr message, and absence of input bytes in stderr.
- Break-the-guard check before finishing: temporarily write stdout before `Redact` succeeds, and print `err.Error()`; confirm tests fail; revert.

## 11. Observability, deployment, rollback

- No logging beyond the fixed stderr messages. Exit codes are the machine-readable signal.
- Ships in the binary; rollback is reverting the PR. The `VerificationError` change is backward compatible.

## 12. Definition of done

- All FRs covered by tests; `task test` passes.
- `task verify` passes (fmt, lint, test, gosec + govulncheck, gitleaks).
- `docs/threat-model.md` CLI section and README usage updated.
- Manual: `go run ./cmd/redactscan redact <tempfile>`, `cat <tempfile> | go run ./cmd/redactscan redact -summary`, a missing file (`echo $?` is 3), a NUL file (`echo $?` is 1).
- PR uses the template, links REDACT-2 and this spec, and names REDACT-10 as the follow-up for `openInput`.
- Staff and security reviewers pass.

## 13. Pseudo-code (user-written)

Waived. The user explicitly waived writing pseudo-code; the implementer designed the code from this spec.
