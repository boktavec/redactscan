# Scan reports: text and versioned JSON: spec

Status: approved by the user (design review after interview questions 1-5; 3 stacked PRs chosen). `security-reviewer` design review (CHANGES REQUIRED, no P0/P1): all required and non-blocking items accepted by the user and folded in (FR1-FR4, FR6-FR9, FR12, FR15-FR16, FR20-FR22, R1-R7, sections 6-8).
Story: [REDACT-38](http://localhost:8080/issue/REDACT-38) "As a user, I want readable and machine-readable scan reports".
Branch: create a feature branch per PR (for example `feat/redact-38-finding-checks`, `feat/redact-38-report`, `feat/redact-38-scan-output`); PR 2 stacks on PR 1 and PR 3 on PR 2. Do not implement on `main`.
Packages: changes to `internal/scanner` (finding checks), new `internal/report`, changes to `internal/cli`. Go standard library only, no new dependency.
Depends on (merged): REDACT-35 (`internal/artifact`, `internal/finding`), REDACT-36 (`internal/scanner`, `scan FILE`).
Related: REDACT-37 (first production scanners), REDACT-39 (directory ingestion; `scan ./dir` wiring is not part of this story), REDACT-50 (findings exit code).
Decision record: [ADR 0005](../../adr/0005-report-escaping-and-versioned-json.md).
Refs: `docs/architecture.md` sections 2 (explainable findings, fail closed) and 6 (findings model), `docs/threat-model.md` Scanner section, `AGENTS.md` security principles.

> Spec text and tests never contain realistic secret values. Tests build secret-shaped input at runtime.

## 1. Feature overview

**Purpose.** `redactscan scan FILE` prints one report on stdout: readable text by default, or a versioned JSON document with `-json`. Both say whether the scan was complete, list findings with evidence and reasoning, list failures, and give counts by severity. Every untrusted string is neutralised so it cannot drive a terminal or hide content with bidi, zero-width or other invisible characters.

The story text says terminal escape sequences are "stripped". In this spec, **"stripped" means "neutralised by visible escaping"** (user decision): dangerous runes are replaced by a visible escape such as `\x1b` or `\u202e`, never deleted, so tampering stays visible and the evidence keeps its meaning.

**Concrete example.** A registry with scanner `script` (one finding whose evidence holds an ANSI colour sequence) and scanner `filetype` (panics):

```text
$ redactscan scan ./install.sh
redactscan scan report
status: incomplete

== high (1) ==
- script-curl-pipe-sh: Remote script piped to shell
  file: ./install.sh:12
  category: execution
  reasoning: Downloads a script and runs it without verification.
  evidence: curl -s https://[HOST_1]/i.sh | sh \x1b[31m
  metadata: interpreter="sh", line_count=40

failures (1):
- filetype: panic

summary: incomplete, 1 finding (critical 0, high 1, medium 0, low 0, info 0)
$ echo $?
1
```

```text
$ redactscan scan -json ./install.sh
{"schema_version":1,"status":"incomplete","summary":{"total":1,"by_severity":{"critical":0,"high":1,"medium":0,"low":0,"info":0}},"findings":[{"id":"script-curl-pipe-sh","severity":"high","category":"execution","title":"Remote script piped to shell","description":"Downloads a script and runs it without verification.","file":"./install.sh","line":12,"evidence":"curl -s https://[HOST_1]/i.sh | sh \u001b[31m","metadata":{"interpreter":"sh","line_count":40}}],"failures":[{"scanner":"filetype","reason":"panic"}]}
```

**Scope.**

- `internal/scanner`: `checkFinding` adds grammars for ID, Category and Metadata keys, bounds and checks Category and Description, and runs the redactor check on Category, Description and string Metadata values (PR 1).
- New `internal/report`: `Text` and `JSON` renderers over `scanner.Result`, one shared escaping rule, golden tests (PR 2).
- `internal/cli`: `scan` prints the text report by default and the JSON report with `-json`; renderer errors map to exit 3; `writeFindings`, `printFailures` and `registryFailureText` are removed (the failure texts move to `report`); usage text (PR 3).
- Docs: ADR 0005 (PR 2); `docs/threat-model.md` Scanner section, `docs/architecture.md` section 6 note, README `scan` usage (PR 1 and PR 3).

**Non-goals.**

- Any real scanner (REDACT-37). Tests use fake scanners and hand-built `scanner.Result` values.
- `scan ./dir` or multi-artifact reports. The renderer takes one `scanner.Result`; a directory story adds aggregation later (follow-up F2).
- A findings-present exit code or any policy decision (REDACT-50, policy engine). Exit codes are unchanged.
- Colours, terminal detection, a `-format` flag, SARIF, pretty-printed JSON, a published JSON Schema file.
- Changes to `redact` or its `-json` summary.
- A UTF-8 rule for `Finding.File` (names from disk can be invalid UTF-8; see section 6).

## 2. Functional requirements and acceptance criteria

### Finding checks (PR 1)

- **FR1. Order and short-circuit.** `checkFinding` runs cheap checks first and stops at the first failure: `Validate`, ArtifactID, lengths, UTF-8, grammars (FR2), then the redactor checks (FR3) one field at a time. No redactor call is made for a finding that already failed a cheap check (R6).
- **FR2. Grammars and bounds.**
  - ID: `^[a-z0-9][a-z0-9._-]*$`, 1..`MaxIDBytes` (128).
  - Category: empty, or `^[a-z0-9][a-z0-9._-]*$` up to `MaxCategoryBytes = 64`.
  - Description: valid UTF-8, at most `MaxDescriptionBytes = 1024`.
  - Metadata keys: `^[a-z][a-z0-9_]{0,63}$`. All current ingest keys fit (`link_kind`, `errno`, `file_type`, `op`, `depth_skipped`, `entries_capped`, `read_errors`, `changed`, `path_too_long`).
  - The 64 and 1024 limits are **Assumed** sizes (D6). Grammars are checked with byte loops, not `regexp`.
- **FR3. Redactor checks.**
  - ID, Title, File, Evidence and string Metadata values: `redactorClean` as today (nothing detected except label-like text).
  - Category, Description and each Metadata key: `redactorStrict`, which rejects any detected kind including `KindLabelLike`. Constant reasoning text never needs a label.
  - A redactor error rejects the finding.
- **FR4. Result.** A rejected finding is dropped and recorded as `invalid finding` for that scanner, so `Result.Incomplete()` is true. No content appears in any message.

### Escaping (PR 2)

- **FR5. Dangerous rune.** One unexported predicate is used by both renderers:

  ```go
  isDangerous(r) = !strconv.IsPrint(r) ||
      unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) ||
      unicode.Is(unicode.Variation_Selector, r)
  ```

  - It covers C0 controls (including ESC), DEL, C1 controls (including U+0085 and 8-bit CSI U+009B), bidi controls (U+061C, U+200E-200F, U+202A-202E, U+2066-2069), and zero-width and other format characters (U+200B, U+FEFF, tag characters).
  - It also covers line and paragraph separators, non-ASCII spaces, and invisible fillers and joiners that `strconv.IsPrint` accepts: U+034F, U+115F, U+3164, U+17B4, U+FFA0, variation selectors U+FE0F and U+E0100.
  - **Verified** on go1.27.1; see D3.
  - Emoji presentation selectors (U+FE0F) are therefore shown as escapes (accepted, ADR 0005).
- **FR6. Text escaping.**
  - Every dangerous rune is written as its `strconv.QuoteRuneToASCII` escape without the quotes (`\n`, `\t`, `\x1b`, `\x7f`, `\u009b`, `\u202e`, `\ufe0f`, `\U000e0100`).
  - Every invalid UTF-8 byte is written as `\xNN`, and a backslash as `\\`. All other runes are copied, including a literal U+FFFD, so an invalid byte (`\xff`) and a real U+FFFD stay distinguishable (R1).
  - No quotes are added, except for metadata string values (FR10).
  - Text output contains no dangerous rune except the `\n` line terminators the renderer writes.
- **FR7. JSON escaping** (R2).
  - The document is produced with `encoding/json`.
  - `escapeJSON` then walks the **whole** marshaled output (keys, values and structure) and replaces every dangerous rune at or above U+007F with `\uXXXX`, using a UTF-16 surrogate pair above U+FFFF.
  - There is no special case for U+2028/2029: they are dangerous and `encoding/json` already escapes them.
  - If the marshaled bytes contain invalid UTF-8 (not expected), `escapeJSON` returns an error and nothing is written (fail closed).
  - Runes below U+0020 are escaped by `encoding/json` inside strings, and compact output has none outside strings.
  - Output contains no dangerous rune except the final newline, and decoding it returns exactly the marshaled strings.
  - Invalid UTF-8 in a field cannot be carried in JSON: `encoding/json` replaces it with U+FFFD before `escapeJSON` runs (section 6).
- **FR8. Fields escaped.** Every string from a finding or failure is escaped: ID, Title, Category, Description, File, Evidence, Metadata keys and string values, scanner name and reason. Constant renderer text is not escaped.
- **FR9. No reflection formatting** (R5). Non-test code in `report` does not import `fmt` and never formats a `Finding`, `Result` or `any` value. Numbers use `strconv`. An import-allowlist test (as in `scanner/imports_test.go`) allows only `bytes`, `encoding/json`, `errors`, `io`, `math`, `slices`, `strconv`, `unicode`, `unicode/utf8`, `internal/finding` and `internal/scanner`.

### Text report (PR 2)

- **FR10. Layout**, with one `\n` per line:
  1. `redactscan scan report`
  2. `status: complete` or `status: incomplete`
  3. A blank line, then one group per severity that has findings, from critical to info. Each group has a header `== <severity> (<count>) ==`, then each finding in `Result` order:
     - `- <ID>: <Title>`
     - `  file: <File>`, plus `:<Line>` when Line > 0. The line is omitted when File is empty.
     - `  category: <Category>`, `  reasoning: <Description>` and `  evidence: <Evidence>`, each omitted when empty.
     - `  metadata: k=v, k=v`, omitted when empty.
       - Keys are sorted bytewise.
       - A string value is written as `"` + escaped value + `"`, with `"` also escaped as `\"`, so `k=v` stays unambiguous.
       - bool and int values use `strconv`; float64 uses `strconv.FormatFloat(v, 'g', -1, 64)`.
  4. When there are no findings: `no findings`.
  5. When there are failures: a blank line, `failures (<n>):`, then one `- <text>` line each in `Result` order.
     - Registry failures use fixed text: `file exceeds 10 MiB limit`, `invalid artifact`, `no scanner ran`.
     - Other failures use `<scanner>: <reason>`.
  6. A blank line, then `summary: <status>, <n> finding|findings (critical a, high b, medium c, low d, info e)`.
- **FR11.** An invalid severity (cannot occur after `checkFinding`) is grouped under `invalid` after `info` rather than dropped.

### JSON report (PR 2)

- **FR12. Document.** The output is one compact JSON object followed by `\n`, with keys in this order:
  - `schema_version`: integer, `1`.
  - `status`: `"complete"` or `"incomplete"`, derived **only** from `res.Incomplete()` (R3).
  - `summary`: `total` and `by_severity`, which always has all five names.
  - `findings`: array, never `null`.
  - `failures`: array, never `null`.

  The same status rule applies to text.
- **FR13. Finding and failure fields.**
  - Each finding has `id`, `severity` (the `Severity.String()` name), `category`, `title`, `description`, `file`, `line` (0 when unknown), `evidence` and `metadata` (an object, `{}` when nil; keys sorted by `encoding/json`).
  - `ArtifactID` is not emitted.
  - Each failure has `scanner` and `reason` (the `scanner.Reason` string).
- **FR14. Versioning.** `schema_version` changes only for a breaking change: a removed or renamed field, or a changed type or meaning. Adding a field does not change it. The package doc and ADR 0005 record this.

### Writing (PR 2)

- **FR15. API.**
  - `report.Text(w io.Writer, res scanner.Result) error` and `report.JSON(w io.Writer, res scanner.Result) error` build the whole output in one buffer and call `w.Write` once.
  - A write error or short write returns `report.ErrWrite`.
  - A marshal or `escapeJSON` error returns `report.ErrRender` and writes nothing.
  - Both errors are constant text with no content.

### CLI (PR 3)

- **FR16. Command.** `redactscan scan [-json] FILE`. Without `-json` the text report goes to stdout; with `-json` the JSON report does. Flags must come before FILE, as today. The renderers are called through unexported package variables (`renderText`, `renderJSON`), a test seam like `defaultRegistry`.
- **FR17. stderr.** On success stderr is empty in both modes, because failures and the summary are in the report. stderr carries only errors that stop the report:
  - usage errors
  - open and read errors (existing messages)
  - an invalid registry
  - the FR18 lines
- **FR18. Renderer errors.** Every non-nil renderer error gives a non-zero exit and a fixed stderr line:
  - `errors.Is(err, report.ErrWrite)`: `redactscan: cannot write output: write failed`, exit 3.
  - Any other error: `redactscan: internal error: cannot render report`, exit 3.

  This is tested with an injected failing renderer for both cases, and the test also checks that nothing reaches stdout in the `ErrRender` case.
- **FR19. Exit codes.** These are unchanged: 0 complete, 1 incomplete, 2 usage, 3 I/O (now including renderer errors). An incomplete scan is shown both in the report (`status`) and in the exit code.
- **FR20. Usage text.** It documents:
  - `-json`, the report and `schema_version`
  - the breaking change: the stdout format changed, and failures and the summary moved from stderr to stdout
  - the consumer rule (R4): check the exit code first, and treat empty or unparseable output as a failed scan, never as clean
  - that invalid UTF-8 in file names shows as U+FFFD in JSON

### Acceptance criteria (story)

1. **Golden tests for text and JSON.** Files under `internal/report/testdata/*.golden` are compared byte for byte and regenerated only with `go test ./internal/report -update`.
2. **Control characters are neutralised.** Hostile-rune tests cover untrusted evidence and every other untrusted field. They assert:
   - no dangerous rune in either output
   - the expected visible escapes in text
   - an exact JSON round-trip
3. **The JSON schema version field is present.** Every JSON test asserts `schema_version == 1` as the first key.

## 3. Technical design

```text
safefs.OpenRegular -> readArtifact -> Registry.Run (checkFinding: FR1-FR4)
                                           |
                                     scanner.Result
                                           |
                         +-----------------+-----------------+
                         |                                   |
                 report.Text (default)               report.JSON (-json)
                         \___ shared isDangerous rune rule ___/
                                           |
                         one Write to stdout; error -> fixed stderr line, exit 3
```

`internal/scanner/check.go`:

- Add `MaxCategoryBytes` and `MaxDescriptionBytes`.
- Add byte-loop grammar helpers `validID`, `validCategory` and `validMetadataKey`.
- Add `redactorStrict` next to `redactorClean`.
- Reorder the checks per FR1.

`internal/report` files:

- `report.go`:
  - the package doc: escaping contract, schema-version rule, no reflection formatting, and the consumer rule (exit code first; empty or unparseable output means failure)
  - `ErrWrite`, `ErrRender` and `SchemaVersion = 1`
  - the single-write helper
  - the severity order and counts
  - the registry failure texts
  - `status(res)`, which returns `incomplete` iff `res.Incomplete()`
- `escape.go`: `isDangerous` (FR5), `appendText` and `appendQuotedText` (FR6, FR10), and `escapeJSON(b []byte) ([]byte, error)` (FR7).
- `text.go`: `Text` (FR10-FR11).
- `json.go`: unexported document structs with explicit `json` tags in FR12/FR13 order, and `JSON`.
- Tests: `escape_test.go`, `text_test.go`, `json_test.go`, `golden_test.go` (shared `-update` flag and fixtures), `imports_test.go`, and `testdata/*.golden`.

`report` imports only `internal/scanner`, `internal/finding` and the standard library allowlist (FR9). It performs no file I/O except reading and writing golden files in tests.

Why the JSON post-processing is safe: compact `encoding/json` output only contains runes at or above U+007F inside string literals (keys or values), so replacing them with `\uXXXX` never changes the structure. Running over the whole output means keys are covered too.

`internal/cli/scan.go`:

- Add a `-json` bool flag.
- After `Run`, call `renderJSON` or `renderText` (package variables defaulting to `report.JSON` and `report.Text`). Map any error per FR18. Otherwise return `exitIncomplete` when `res.Incomplete()`, else `exitOK`.
- Delete `writeFindings`, `printFailures` and `registryFailureText`.

## 4. Data/API changes and migrations

- **New public Go API (internal module):**
  - `report.Text`, `report.JSON`, `report.ErrWrite`, `report.ErrRender` and `report.SchemaVersion`
  - `scanner.MaxCategoryBytes` and `scanner.MaxDescriptionBytes`
  - new grammar rules on ID, Category and Metadata keys (stricter finding contract)
- **New external contract:** the JSON report, `schema_version` 1 (FR12-FR14).
- **Breaking CLI change:** `scan` stdout format changes, and the failure and summary lines move from stderr to stdout. This is acceptable because REDACT-36 marked the format provisional (REDACT-36 spec D11). There is no data migration.
- **Test fixtures that change in PR 1:** `internal/cli/scan_test.go` uses a hostile finding ID (`"id\x1b[31m\r\u202ex"`, around line 170), which FR2 now rejects. PR 1 changes that test to assert the finding is dropped as `invalid finding`. Hostile-character coverage for printed fields moves to the report tests (PR 2) and the File seam test (PR 3).

## 5. Engineering decisions and rationale

| # | Decision | Rationale | Alternatives rejected | ADR |
|---|---|---|---|---|
| D1 | Package plus CLI wiring, 3 stacked PRs (user) | Meets the user story. Keeps each PR under about 400 lines, and security review can focus on each layer | Package only (dead code); 2 PRs | - |
| D2 | Visible escaping, not deletion; no quotes in text except metadata string values (user, security review) | Keeps tampering visible and evidence intact. Quoted metadata values keep `k=v` unambiguous | Quote every field (noisy); strip (hides tampering, changes meaning) | 0005 |
| D3 | Dangerous rune = `!strconv.IsPrint(r)` plus `Other_Default_Ignorable_Code_Point` plus `Variation_Selector`, one predicate for both renderers (user, security review) | Standard library tables. `strconv.IsPrint` alone already escapes C0, DEL, C1, bidi, format, separator and non-ASCII space runes, but **accepts** invisible fillers and selectors. **Verified** with `go run` on go1.27.1: `IsPrint` was false for U+001B, U+007F, U+0085, U+009B, U+200B, U+200E, U+202A, U+202E, U+2066, U+2069, U+061C, U+FEFF, U+E0041, U+2028, U+00A0 and U+00AD. It was true for U+034F, U+115F, U+3164, U+17B4 and U+FFA0 (all in `Other_Default_Ignorable_Code_Point`) and for U+FE0F and U+E0100 (in `Variation_Selector`), and also true for U+00E9, U+FFFD and `\`. | Hand-written range list (drifts) | 0005 |
| D4 | JSON: `encoding/json` plus `\uXXXX` for dangerous runes at or above U+007F over the whole output, failing closed on invalid UTF-8 (user, security review) | `encoding/json` alone writes DEL, C1, bidi and zero-width runes raw. **Verified**: `json.Marshal` on go1.27.1 escaped U+001B, U+2028, `<` and `&`, but wrote U+007F, U+009B, U+202E and U+200B raw, and replaced 0xFF with U+FFFD. The escapes keep the data exact | Plain JSON (terminal injection via `-json \| cat`); pre-escaped text (lossy) | 0005 |
| D5 | Self-describing document with `status` and `failures` on stdout, status only from `res.Incomplete()`; text mirrors it (user) | A stdout-only consumer cannot mistake an incomplete scan for a clean one | Findings-only JSON with stderr failures (fail open) | 0005 |
| D6 | Registry-level checks: grammars for ID, Category and Metadata keys; Category 64 B, Description 1 KiB; strict redactor check (no labels) on Category and Description; redactor check on string Metadata values (user, security review) | The report is the first output to print these fields, so the contract is enforced where every finding passes. Grammars make Category and keys identifiers, not prose. Sizes are **Assumed** (one paragraph of reasoning); revisit with REDACT-37 | Placeholder text in the report only (a bad finding still counts as accepted); contract only (not fail closed) | 0005 |
| D7 | Integer `schema_version` starting at 1, bumped only on a breaking change (user) | Simple for consumers to check; added fields need no bump | Semver string; URI-style version | 0005 |
| D8 | The renderer input is `scanner.Result` (recommended, approved) | No new aggregate type until multi-artifact scans need one | A new `report.Report` type now (speculative) | - |
| D9 | Compact JSON, one line plus a newline | It is a machine format, it matches `redact -json`, and users can pretty-print with `jq` | Indented output (bigger goldens, no requirement) | - |
| D10 | Renderer errors map to exit 3 with fixed lines, through a renderer seam (security review) | No renderer error can end in exit 0 or 1 with partial or no output | Ignoring a marshal error (fail open) | - |

ADR 0005 records D2-D7 because the JSON schema, the escaping rule and the stricter finding contract are long-lived external contracts.

## 6. Risks and failure modes

| Risk / failure | Handling |
|---|---|
| Stdout write fails or is short | One `Write` and `ErrWrite`. The CLI prints the fixed line and exits 3. A partial report is possible only if the writer writes part of the output before failing; the exit code says it failed. |
| Marshal or escape error, or a Metadata value that is not a string, bool, int, int64 or finite float64 (NaN, Inf, nil, named types, slices, maps) | `ErrRender` from both renderers via one shared check: nothing is written, a fixed line is printed, exit 3 (FR15, FR18). |
| Scanner puts a secret, a blob or prose in Description, Category, Metadata or ID | Dropped by FR1-FR4, and the scan is incomplete. |
| A legitimate description looks like a covered secret format or label | Dropped (fail closed), as Title already is. Detectors use constant text. |
| The redactor covers only four secret formats (AWS access key, AWS secret key, GitHub token, PEM private key) | Description (up to 1 KiB) can carry an uncovered secret if a scanner breaks the constant-text contract. Accepted. The threat model records it, and REDACT-37 scanners must include a test that Description and Category are constant (R7). |
| Invalid UTF-8 in `File` (allowed today: only the length and redactor check apply) | Text shows the exact bytes as `\xNN`. JSON shows U+FFFD (lossy; documented in the package doc and usage). `file` is display-only per the threat model. |
| A Unicode update changes `strconv.IsPrint` or the property tables | The golden tests and the exhaustive rune test catch it on a toolchain bump. |
| Emoji with U+FE0F appear as `\ufe0f` | Accepted. Readability costs less than missing an invisible selector. |
| A consumer relies on the old `scan` output or stderr lines | The breaking change is documented in the usage text, the README and the PR. |
| A consumer treats empty or truncated JSON as "no findings" | The usage text and package doc say: check the exit code first; empty or unparseable output is a failure (R4). |
| **F1 (follow-up, accepted risk):** 8-bit C1 controls on terminals not in UTF-8 mode | Output is UTF-8, so the byte 0x9B can appear as a continuation byte of a printable character (for example U+00DB is `C3 9B`), and a terminal in 8-bit mode may read it as CSI. Escaping operates on runes, not bytes, so this is not prevented. Accepted and recorded in the threat model. |
| **F2 (follow-up):** `scan ./dir` wiring | When the CLI renders a directory scan, `status` must be `incomplete` when `ingest.Walk` returns `ErrIncomplete`, not only when `Result.Incomplete()` is true. Recorded in the threat model and in the `report` package doc for the directory story. |

## 7. Security

- **Trust.** Every Finding string and Metadata value is derived from untrusted content (threat model). The terminal, files and later JSON consumers (policy, MCP) are less trusted readers.
- **Neutralisation.** FR5-FR8 apply to both formats with one predicate.
  - The backslash is escaped in text, and the quote in metadata string values, so an attacker cannot forge text that looks like an escape or a field boundary.
  - Invisible fillers and variation selectors are covered.
- **No secrets.** FR1-FR4 extend the redactor and grammar checks to every printed field. The renderer never formats with reflection (FR9).
- **Fail closed.**
  - `status` and `failures` are part of the document, and `status` comes only from `res.Incomplete()`.
  - Every renderer error is exit 3, and `ErrRender` writes nothing.
  - Consumers are told to treat empty or unparseable output as failure.
- **No new I/O, no execution, no new dependency.** The `internal/scanner` import allowlist is unchanged, and the new `report` allowlist excludes `fmt`, `os`, `os/exec`, `net`, `syscall`, `unsafe` and `log`.
- **Threat-model update (PR 1 and PR 3, R7).**
  - Category and Description are now printed, and Description can be up to 1 KiB.
  - The redactor recognises only four formats.
  - The new grammars.
  - Follow-ups F1 and F2.
  - REDACT-37 scanners need a test that Description and Category are constant text.
- **Review.** `security-reviewer` reviews PR 1 and PR 2 (redaction checks, output of scanned content) and PR 3 (output path and exit codes).

## 8. Performance/scalability

Per-finding raw bytes are bounded:

| Field | Max |
|---|---|
| ID | 128 B |
| Title | 128 B |
| Category | 64 B |
| Description | 1 KiB |
| File | 4 KiB |
| Evidence | 256 B |
| Metadata | 32 x (64 B + 256 B) = 10 KiB |

That is about 16 KiB per finding, or about 16 MiB raw at `MaxFindings` (1000).

Escaping blow-up:

- **Text:** up to **4x** (a 1-byte control or invalid byte becomes 4 bytes, such as `\x1b`; multi-byte runes grow less).
- **JSON:** up to **6x** (a 1-byte control becomes `\u001b`; a 4-byte rune becomes a 12-byte surrogate pair, 3x).

The worst-case JSON output is therefore about 96 MiB. The marshal buffer and the escaped copy are alive at the same time, so peak memory is roughly **200 MiB** in the worst case. That needs a scanner emitting 1000 maximal findings made entirely of controls that still pass the redactor check.

**Decision:** we accept this explicitly. It is a local CLI, the total is bounded, and the input that reaches it is scanner output that has already been checked. `escapeJSON` sizes its output buffer once from a first counting pass, so it does not grow repeatedly.

Typical reports are a few KiB. The extra redactor calls run only after the cheap checks pass (FR1). No caching, no concurrency.

## 9. Implementation steps

Each PR runs `task test` while developing and `task verify` before review. Keep each PR under about 400 changed lines; split before 500.

### PR 1: finding checks (`internal/scanner`), about 150 lines

Depends on: nothing.

1. Add `MaxCategoryBytes` and `MaxDescriptionBytes`, the grammar helpers and `redactorStrict`. Rewrite `checkFinding` in the FR1 order.
   - Table tests in `check_test.go`:
     - ID, Category and Metadata-key grammar: accept and reject cases, including uppercase, leading `-`, a space, a control rune and non-ASCII. Every current ingest key is accepted.
     - Category and Description at the limit are accepted; limit+1 is rejected.
     - Invalid UTF-8 in Description is rejected.
     - Secret-shaped Description, Category and Metadata string values (built at runtime) are rejected.
     - Label-like text is rejected in Category and Description but accepted in Evidence and Metadata values.
     - Non-string Metadata is unaffected.
     - `Run` records `invalid finding` and the result is incomplete.
   - A test with a counting fake proves no redactor work happens after a cheap failure. Alternatively, a benchmark or a code-structure assertion shows the redactor checks come last.
2. Update the existing `internal/cli/scan_test.go` hostile-ID test to expect the finding to be dropped (section 4).
3. Update the package doc, and add the threat-model Scanner bullets for the new checks plus F1.
   - Expected result: all tests pass and `task verify` is green.

### PR 2: `internal/report`, about 400 lines including tests and goldens

Depends on PR 1.

1. Write `escape.go` and `escape_test.go`.
   - Table of hostile inputs with exact expected text escapes:
     - an ESC CSI sequence, 8-bit CSI U+009B, DEL, U+0085
     - bidi U+202E and U+2066, U+200B, U+FEFF, U+2028, a tag character
     - U+034F, U+FE0F, U+E0100, U+3164, U+17B4
     - backslash, `"` (in a metadata value), `\n`, `\r`
     - invalid byte 0xFF next to a literal U+FFFD (R1), and mixed valid text
   - An exhaustive loop over runes 0-0x10FFFF (excluding surrogates) asserts:
     - `appendText` output has no dangerous rune
     - for valid UTF-8, `escapeJSON(json.Marshal(s))` decodes back to `s` and contains no dangerous rune
   - `escapeJSON` on invalid UTF-8 returns an error.
2. Write `report.go`, `text.go` and `json.go` per FR9-FR15.
3. Add golden fixtures (`golden_test.go`, `-update` flag), each as `.txt.golden` and `.json.golden`:
   - `empty-complete`
   - `no-scanner-incomplete`
   - `mixed-severities`: all five severities; metadata of each scalar type; Line 0 and Line > 0; empty optional fields
   - `hostile`: every field holding hostile runes, including U+034F, U+FE0F, U+E0100, U+3164 and U+17B4
4. Add tests beyond the goldens:
   - JSON decodes into a generic map, and `schema_version == 1` is first in the byte stream.
   - `findings`, `failures` and `metadata` are never `null`, and `by_severity` has all five keys.
   - `status == "incomplete"` iff `len(res.Failures) > 0`, in both formats, as a table over Results with and without findings and failures (R3).
   - Neither output contains a dangerous rune except `\n`.
   - Single-write and short-write writer fakes give `ErrWrite`.
   - An import-allowlist test, which also forbids `fmt` in non-test files (FR9).
5. Write ADR 0005.
   - Expected result: the CLI does not use the package yet, and `task verify` is green.

### PR 3: CLI wiring and docs, about 200 lines

Depends on PR 2.

1. In `scan.go`:
   - Add the `-json` flag.
   - Add the `renderText` and `renderJSON` seams and the FR18 error mapping.
   - Delete `writeFindings`, `printFailures` and `registryFailureText`.
   - Update `usageText` (FR20).
2. Update `scan_test.go` and `output_test.go`:
   - Text by default: status, the failures section and the summary on stdout, with stderr empty.
   - `-json`: valid JSON, `status` incomplete with the empty production registry, and stderr empty.
   - Exit codes 0/1/2/3.
   - A failing stdout gives exit 3 and the write-failed line.
   - An injected renderer returning `ErrWrite` and one returning another error each give exit 3 and the matching fixed line, with no stdout in the `ErrRender` case (FR18).
   - `-json` after FILE is a usage error.
   - Hostile filename (Unix only): create a temp file whose name contains ESC and U+202E. Replace `defaultRegistry` with a fake scanner that returns one finding with `File = a.RelativePath`. Assert both modes show the name escaped and contain no dangerous rune.
3. Docs:
   - In the threat-model Scanner section: report output, escaping, the consumer rule, lossy invalid UTF-8 in JSON, F2, and the breaking change.
   - A short note in architecture section 6 pointing to `internal/report` and ADR 0005.
   - The README `scan` usage.
   - Expected result: `task verify` is green.

## 10. Testing strategy

- **Unit:** the escape rule (exhaustive rune loop plus a table), the `checkFinding` table (grammars, limits, strict and normal redactor checks, short-circuit), and renderer behaviour (FR10-FR15), including the status rule.
- **Golden:** byte-exact text and JSON for four fixtures. They are updated only with `-update`, never automatically, and are reviewed in the PR diff.
- **Regression:** the hostile fixture pins neutralisation, including invisible fillers and selectors. The JSON round-trip pins losslessness. A test pins that an invalid byte and a literal U+FFFD render differently.
- **Failure paths:** short and failing writers; an injected failing renderer (both error kinds); `escapeJSON` on invalid UTF-8; an invalid finding dropped; incomplete status.
- **CLI integration:** as in PR 3, step 2. There are no secret-shaped literals in tests or goldens: build them at runtime. Goldens contain only constant text and labels.
- Follow `.agents/skills/test-writing/SKILL.md`.

## 11. Observability, deployment, rollback

- **Observability:** the CLI has no logs or metrics. The report itself is the observable output, and `status` plus the exit code show incompleteness.
- **Deployment:** ship with the next release. Note the breaking `scan` output change and the stricter finding contract in the release notes and the usage text.
- **Rollback:** revert PR 3 to restore the old output. PR 1 only rejects more findings, and PR 2 is unused without PR 3, so both are safe to keep.

## 12. Definition of done

- FR1-FR20 and R1-R7 are covered by passing tests.
- Acceptance criteria 1-3 are demonstrated by named tests: `TestGolden*`, the hostile-rune tests, and the `schema_version` assertions.
- `task test` runs during development, and `task verify` is green on each PR before it is marked ready.
- ADR 0005 is added; `docs/threat-model.md` (including F1, F2 and the R7 notes), `docs/architecture.md`, the README and the usage text are updated.
- `security-reviewer` reports PASS on PRs 1-3, and `staff-engineering-reviewer` reports PASS or PASS WITH ADVISORIES.
- Each PR uses `.github/pull_request_template.md` and links REDACT-38, this spec and ADR 0005.
- **Manual steps.** The production registry is empty until REDACT-37, so a real scan can only show the incomplete report.
  1. Run `redactscan scan <tmpfile>` and `redactscan scan -json <tmpfile>` on an ordinary temp file. Confirm:
     - `status: incomplete`, a `failures` section with `no scanner ran`, and the summary line in text
     - `schema_version` 1, `"status":"incomplete"` and `failures` `[{"scanner":"registry","reason":"no scanner"}]` in JSON
     - exit 1 and empty stderr in both modes
  2. Run `scan` on a missing path whose name contains ESC and U+202E, and confirm the open error on stderr shows them escaped.
  3. Hostile-name rendering inside the report is covered by the automated seam test, because no production scanner emits findings yet.
- Each PR description states the breaking output change.
