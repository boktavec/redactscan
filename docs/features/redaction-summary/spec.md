# Redaction summary on stderr: spec

Status: approved by the user.
Story: [REDACT-13](http://localhost:8080/issue/REDACT-13). Depends on REDACT-2 (`redactscan redact`, Done) and builds on REDACT-11 (cleaned file output, merged).
Branch: `feat/redact-13-redaction-summary` from `main`. One PR.
Packages: `internal/cli` only. Go standard library only (`encoding/json`); no new dependency. `internal/redactor`, `internal/safefs` and `cmd/` do not change.
Related: `docs/architecture.md` section 14, `docs/threat-model.md` (CLI), `docs/features/redact-command/spec.md` (FR12 is superseded), `docs/features/cleaned-file-output/spec.md` (FR1 stderr order).

> Spec text and tests never contain realistic secret values. Tests build secret-shaped input at runtime, as the existing `awsKey(n)` helper does.

## 1. Feature overview

**Purpose.** A user can see how many items of each kind were redacted, so they can tell the tool did something, without exposing values or offsets. The summary goes to stderr, so stdout stays pipeable.

**Concrete example.**

```
$ cat app.log | redactscan redact > clean.log
redactscan: redacted AWS_ACCESS_KEY=2 GITHUB_TOKEN=1; neutralised 1 label-like
$ redactscan redact logs/app.log
redactscan: redacted AWS_ACCESS_KEY=2
redactscan: wrote "logs/app_cleaned.log"
redactscan: note: output may still contain uncovered secret formats
$ redactscan redact -json logs/app.log
{"counts":{"AWS_ACCESS_KEY":2,"LABEL_LIKE":1}}
$ redactscan redact -quiet logs/app.log      # stderr empty on success
$ redactscan redact -quiet -json app.log     # exit 2, usage error
```

**What exists today.** `-summary` (REDACT-2 FR12) is opt-in and prints the text line above. In file mode stderr always has the `wrote` and note lines. In stream mode (stdin or `-stdout`) stderr is empty on success.

**Scope.**

- The summary is on by default in every mode.
- `-quiet` silences all success output on stderr.
- `-json` replaces all success output on stderr with one JSON object holding only the counts.
- `-summary` is still accepted, does nothing, and is documented as deprecated.

**Breaking change (user decided, accepted).** Stream-mode stderr is no longer empty on success. Scripts that check for an empty stderr or merge streams with `2>&1` see one more line. `-quiet` restores the old behavior. Stdout does not change in any mode.

**Non-goals.**

- Offsets, values, labels, hashes or the output path in any summary.
- JSON error messages (errors stay plain text and constant).
- A `"version"` field or a JSON schema document.
- Per-file summaries for several files (the command takes one FILE).
- Changing `Result.Counts` or the text format of the summary line.

## 2. Functional requirements and acceptance criteria

"Success" means exit 0 after the output has been completely written (to stdout or through `WriteSibling`).

| ID | Requirement | Acceptance criteria |
| --- | --- | --- |
| FR1 | Text summary by default, stream mode. | `redact` with stdin, `redact -`, and `redact -stdout FILE`: exit 0, stdout is exactly `Redact(input).Output`, stderr is exactly one line `redactscan: <summaryText(Counts)>\n`, in today's format (kinds sorted by name, `no covered secret formats found`, `; neutralised N label-like`). |
| FR2 | Text summary by default, file mode. | `redact FILE`: exit 0, stdout empty, stderr is the summary line, then `redactscan: wrote "<out>"`, then the note line, in that order. |
| FR3 | `-summary` is a no-op alias. | `-summary` and `--summary` produce byte-identical stdout, stderr and exit code to the same run without the flag, in both modes. |
| FR4 | `-quiet` silences success output. | `-quiet` (and `--quiet`) in both modes: exit 0, stderr empty, stdout and the output file unchanged. In file mode the `wrote` and note lines are also suppressed. |
| FR5 | `-json` prints one JSON object. | `-json` (and `--json`) in both modes: exit 0, stderr is exactly one line, `{"counts":{...}}\n`. Keys are the `redactor.Kind` strings, values are the `Result.Counts` integers, keys sorted, no whitespace. Decoding the line gives a map equal to `Result.Counts` from a direct `redactor.Redact` call on the same input, including `LABEL_LIKE`. Zero counts are absent. Nothing to report gives `{"counts":{}}` (never `null`). In file mode there is no `wrote` line and no note line. |
| FR6 | `-quiet` with `-json` is a usage error. | Exit 2, stdout empty, stderr is `redactscan: -quiet and -json cannot be used together\n` followed by usage. No input is read and no file is created. Flag order does not matter. |
| FR7 | No summary on failure. | For every failing exit (1 refused, 2 usage, 3 I/O: open, read, stdout write, write refused or failed), under the default, `-json`, `-quiet` and `-summary`, stderr contains only the existing constant error line (plus usage for exit 2, plus the `temporary file may remain` line when it applies). No summary line, no JSON, no `wrote`, no note. |
| FR8 | The temp-file warning is never suppressed. | When `WriteSibling` reports `tempLeft`, `redactscan: temporary file may remain` is printed with or without `-quiet` and `-json`, on success and failure. On success with `-json`, the JSON line comes first and the warning is the last line. On success with `-quiet`, it is the only line. |
| FR9 | No values ever. | Summary output (text and JSON) contains only `Kind` constant names, integers and fixed text. No input bytes, labels, offsets or paths. |
| FR10 | Help documents the flags. | `-h` lists `-quiet`, `-json`, `-summary (deprecated, no effect)`, states that the summary is on by default and goes to stderr, and states the `-quiet`/`-json` conflict. |

## 3. Technical design

All changes are in `internal/cli`.

### 3.1 Summary mode

```go
type summaryMode int

const (
	summaryText summaryMode = iota // default
	summaryJSON
	summaryNone // -quiet
)
```

`summaryText` is already the name of the existing formatter function. The implementer picks non-clashing names (for example rename the function to `formatSummary` or name the constants `modeText`, `modeJSON`, `modeQuiet`).

`runRedact`:

1. Define `quiet := fl.Bool("quiet", ...)`, `jsonOut := fl.Bool("json", ...)`, and keep `fl.Bool("summary", ...)` with its value ignored.
2. After `fl.Parse` and the existing positional-argument check: if `*quiet && *jsonOut`, return `usageError(stderr, "-quiet and -json cannot be used together")`. This runs before `readInput`, so nothing is opened.
3. Work out the mode: JSON if `-json`, none if `-quiet`, otherwise text.
4. Stream path: after the existing successful stdout write, call `printSummary(stderr, mode, res.Counts)`.
5. File path: pass the mode to `writeCleaned` instead of `summary bool`.

`writeCleaned(path, input, res, mode, force, stderr)` on success:

- text: summary line, `wrote` line, note line (unchanged order);
- JSON: the JSON line only;
- none: nothing.

The deferred `temporary file may remain` line stays as it is, so it always prints last and is never suppressed.

### 3.2 Output functions

```go
// printSummary writes the success summary for mode. It prints nothing for summaryNone.
func printSummary(w io.Writer, mode summaryMode, counts map[redactor.Kind]int)
```

- Text: `fmt.Fprintf(w, "redactscan: %s\n", <existing formatter>(counts))`.
- JSON: marshal `struct{ Counts map[redactor.Kind]int \`json:"counts"\` }`, replacing a nil map with an empty one first so the result is `{}`, never `null`. Write the bytes plus `"\n"` in one write. `json.Marshal` cannot fail for this type. If it ever did, print nothing and return: the redacted output has already been written, so changing the exit code would mislead, and the fixed-message rule forbids printing the error text.

The `wrote` and note lines stay in `writeCleaned` and are printed only in text mode.

**Verified** (`go doc encoding/json Marshal`, Go 1.27.2): map values encode as JSON objects with sorted keys, and keys of any string type are used directly, so `map[redactor.Kind]int` encodes with the kind names as keys in a fixed order. `Marshal` produces compact output. Its default HTML escaping does not matter because kind names are `[A-Z_]`.

### 3.3 Stderr contract (after this change)

| Mode | Stream success | File success | Any failure |
| --- | --- | --- | --- |
| default / `-summary` | summary line | summary, `wrote`, note | constant error line only |
| `-json` | JSON line | JSON line | constant error line only |
| `-quiet` | empty | empty | constant error line only |
| `-quiet -json` | n/a | n/a | exit 2: reason plus usage |

Plus `temporary file may remain` (last line) whenever `tempLeft` is true, in every row.

### 3.4 Files

```
internal/cli/redact.go       flags, conflict check, summary mode, printSummary, writeCleaned signature
internal/cli/cli.go          usageText
internal/cli/cli_test.go     stream-mode tests (update expectations, add new)
internal/cli/output_test.go  file-mode tests (update expectations, add new)
README.md                    usage and flag list
docs/threat-model.md         CLI section usage line and a stderr control bullet
docs/features/redact-command/spec.md      note: FR12 superseded by this spec
docs/features/cleaned-file-output/spec.md note: FR1 stderr contents superseded by this spec
```

## 4. Data/API changes and migrations

- CLI surface: new flags `-quiet` and `-json`. `-summary` is deprecated and does nothing.
- New machine-readable contract: `{"counts":{"<KIND>":<int>,...}}` on stderr with `-json`. It is unversioned (version 0). Adding new kinds or new top-level fields later is backward compatible. Renaming or removing `counts` or a kind name is breaking.
- No data migrations or persisted state.

## 5. Engineering decisions and rationale

| Decision | Rationale | Alternatives rejected |
| --- | --- | --- |
| Summary on by default in every mode, `-quiet` to turn it off (user decided) | One rule, matches the story's `--quiet`. Stdout is never affected, so pipes keep working. Pre-1.0 and REDACT-11 already shipped a breaking change. | Keep opt-in `-summary` (does not fit the story); default on in file mode only (rule depends on mode). |
| `-quiet` hides every success line, including `wrote` and the note (user decided) | Unix `-q` convention: success is silent, so scripts can treat any stderr as a problem. Warnings and errors still print. The note's message stays in help and the docs. | Hide only the summary; hide summary and `wrote` but keep the note. |
| `-json` prints one counts-only object and nothing else on success (user decided) | One object to parse, no filename escaping problem (`encoding/json` would turn invalid UTF-8 in a path into U+FFFD), and it matches "counts by kind, never values". An `"output"` field can be added later without breaking parsers. | JSON line plus text lines; JSON with the output path. |
| `-quiet -json` is a usage error (user decided) | The two flags ask for opposite things, and refusing is clearer than quietly choosing one (fail closed). | Quiet wins; JSON wins. |
| JSON keys are exactly `Result.Counts`, including `LABEL_LIKE` | The acceptance criterion says the summary matches `Counts` exactly. It is a direct encoding with no CLI-side mapping to drift. | Separate `label_like` field (a second shape to maintain). |
| Errors stay plain text under `-json` | The criterion says a failure prints only the constant error. Exit codes already classify the failure. | JSON error objects (more surface, outside scope). |
| `-summary` kept as a no-op | Existing scripts and docs using `-summary` keep working. | Remove it (a second breaking change for no benefit). |

No ADR: this is a contained CLI output default, not a long-term architecture choice. The breaking change is recorded here, in the help text, in the README and in the PR description.

## 6. Risks and failure modes

- **Scripts expecting an empty stderr** (stream mode). Accepted breaking change, fixed with `-quiet`. Called out in the help text, the README and the PR.
- **`2>&1` merges** put the summary into the output stream. This is a user choice. Documented by the help text saying the summary goes to stderr.
- **Stdout write failure.** The summary is printed only after a complete stdout write, so a failed write prints only the error line (FR7). This is unchanged.
- **Summary after a partial file write.** `writeCleaned` prints the summary only when `WriteSibling` returned nil (unchanged), so a failed write never shows counts.
- **Stderr write failure.** Errors writing the summary are ignored (`_, _ =`), as they are today, and the exit code stays 0 because the output was already written. A closed stderr cannot make the run look failed after success. Accepted.
- **JSON consumers and `tempLeft`.** On a successful write that leaves a temp file, stderr has the JSON line plus one text warning line. Documented: the JSON object is always the first line of stderr under `-json`, and any later line is a warning.

## 7. Security

- **No values (FR9).** Text and JSON are built only from `redactor.Kind` constants, integers and fixed strings. `Result.Counts` holds kind keys and counts, never values, labels or offsets. The output path is not in the JSON.
- **Fixed messages.** No `err.Error()` text from `encoding/json` or the OS is printed. This follows the existing rule in the `internal/cli` package doc and the threat model.
- **Fail closed.** The flag conflict is rejected before any input is opened. No summary is printed on any failure path. Output is never written before `Redact` succeeds (unchanged).
- **No new trust boundary or parsing of untrusted input.** The user decided that a design-stage `security-reviewer` pass is not needed. Per AGENTS.md, the post-implementation `security-reviewer` run still applies because the change touches redaction output messages.

## 8. Performance/scalability

There is one extra `json.Marshal` of a map with at most five keys per run. This is negligible. No change to the read limit (10 MiB) or memory use.

## 9. Implementation steps

One PR, target about 200 changed lines including tests (split before about 500).

1. **Summary mode and printing.** Add the summary mode type, `printSummary` (text and JSON), and the nil-to-empty map handling. Rename the existing formatter if names clash. Depends on nothing.
   Expected result: the code compiles and behavior is unchanged because nothing calls the new code yet.
   Tests: `printSummary` unit tests for text, JSON with empty, nil, secrets only, label-like only and mixed counts, and that nothing is printed in quiet mode. Each JSON result is decoded and compared with the input map.
2. **Flags and wiring.** Add `-quiet` and `-json`, make `-summary` a no-op, add the conflict usage error before `readInput`, choose the mode, call `printSummary` on the stream path, and change `writeCleaned` to take the mode (text: summary, `wrote`, note; JSON: JSON line only; none: nothing). Depends on 1.
   Expected result: FR1-FR9 hold.
   Tests: update existing exact-stderr expectations that assumed an empty stderr without `-summary` (stream-mode tests in `cli_test.go` and file-mode tests in `output_test.go`).
   - Stream mode: default text, `-summary` equivalence, `--quiet`, `--json`, and JSON equal to direct `redactor.Redact(input).Counts` for several inputs.
   - File mode: default text order, `-json` with no `wrote` or note line, `-quiet` with an empty stderr and the file still written.
   - `-quiet -json` and `-json -quiet` give exit 2 with no file created.
   - Failure matrix (refused NUL input, missing file, stdout write failure, existing destination, injected `writeSibling` error) times (default, `-json`, `-quiet`): only the error line.
   - `tempLeft` on success through the `writeSibling` seam: JSON first and the warning last; with `-quiet`, only the warning.
   - Stdout byte-identical across flag combinations.
3. **Help and docs.** Update `usageText`, `README.md`, the threat-model CLI usage line, and a Controls bullet ("Summary: counts by kind on stderr after success only, never values; `-quiet` silences success output; `-json` prints counts only"). Add superseded notes to `redact-command` FR12 and `cleaned-file-output` FR1. Depends on 2.
   Expected result: FR10 holds.
   Tests: the existing help test is updated for the new usage text.

## 10. Testing strategy

- Table-driven tests through `cli.Run` with in-memory stdin, stdout and stderr (existing pattern), plus the existing `writeSibling` seam for the injected file-write failure and `tempLeft`.
- **Exact matching.** JSON assertions decode stderr with `encoding/json` and compare with `redactor.Redact` called directly on the same bytes (the acceptance criterion "matches `Counts` exactly"). They also check the exact bytes for one case, to pin key order, compact form and the trailing newline.
- **Regression.** All existing tests keep passing, with expectations updated only where the default changed. A specific test pins that `-summary` output equals default output.
- **Failure path.** The failure matrix in step 2 covers every exit code with every output flag.
- **No secrets.** Test inputs use runtime-built secret shapes. Assertions check that stderr never contains the input secret, extending the existing no-leak checks to `-json`.
- Run with `task test` during development and `task verify` before completion.

## 11. Observability, deployment, rollback

- Observability: none beyond the summary itself. It is a local CLI.
- Deployment: ships in the next release. Release notes and the PR description call out the stderr default change and `-quiet`.
- Rollback: revert the PR. There is no persisted state. Scripts that adopted `-json` or `-quiet` would get a usage error after a rollback. This is acceptable before 1.0.

## 12. Definition of done

- FR1-FR10 implemented and covered by tests in `internal/cli`.
- `task test` and `task verify` succeed (verify runs fmt, lint, test, security, vuln, secrets and cross-build per `Taskfile.yml`).
- `usageText`, `README.md`, `docs/threat-model.md` (CLI section) and the superseded notes in `docs/features/redact-command/spec.md` and `docs/features/cleaned-file-output/spec.md` updated.
- `staff-engineering-reviewer` PASS (or PASS WITH ADVISORIES) and `security-reviewer` PASS.
- PR uses `.github/pull_request_template.md`, links this spec and REDACT-13, and states the breaking stderr change.
- Manual checks:
  - `printf 'x\n' | go run ./cmd/redactscan redact` prints `x` on stdout and `redactscan: no covered secret formats found` on stderr.
  - `go run ./cmd/redactscan redact -json <file>` prints `{"counts":{...}}` on stderr and creates `<name>_cleaned<ext>`.
  - `-quiet` gives an empty stderr.
  - `-quiet -json` exits 2.
  - A NUL-byte file exits 1 with only the refusal line under each flag.
