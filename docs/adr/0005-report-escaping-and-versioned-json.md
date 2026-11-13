# ADR 0005: Report output: visible escaping, a stricter finding contract, and a versioned, self-describing JSON document

Status: Accepted (REDACT-38)
Date: 2026-11-13
Spec: `docs/features/scan-reports/spec.md`

## Context

REDACT-38 replaces the provisional `scan` output from REDACT-36 with a readable text report and a machine-readable JSON report.

- **New fields on screen.** The report is the first output to print Description ("reasoning"), Category, Evidence and Metadata.
- **Untrusted content.** Every finding string comes from untrusted scanned content. It can carry:
  - ANSI or C1 control sequences
  - bidi overrides
  - zero-width characters
  - invisible fillers and variation selectors
- **External contract.** The JSON report becomes a contract for scripts and, later, for the policy engine and the MCP path.

The story asks for escape sequences to be "stripped", for golden tests, and for a schema version field. A `security-reviewer` design review then asked for the rules below to be tightened. The user accepted all of them.

## Decisions

1. **Neutralise by visible escaping, never deletion.** A dangerous rune is defined as:

   ```go
   !strconv.IsPrint(r) ||
       unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) ||
       unicode.Is(unicode.Variation_Selector, r)
   ```

   - `strconv.IsPrint` alone already rejects C0, DEL, C1, bidi, format, separator and non-ASCII space runes. But it accepts invisible fillers such as U+034F, U+3164 and U+17B4, and variation selectors such as U+FE0F and U+E0100. This was **Verified** on go1.27.1.
   - The text renderer writes the `strconv.QuoteRuneToASCII` escape without its quotes (it also escapes printable invisible runes such as U+034F), `\xNN` for each invalid UTF-8 byte, and `\\` for a backslash. Fields get no surrounding quotes.
   - Metadata string values are the one exception: they are written as `"..."` with `\"` inside, so `k=v` stays unambiguous.
   - A real U+FFFD is copied as is, so it stays distinguishable from an invalid byte.
   - "Stripped" in the story means this visible escaping.
   - **Trade-off:** emoji with U+FE0F appear with a visible `\ufe0f`.
2. **JSON uses the same rule, as `\uXXXX`.**
   - The document is built with `encoding/json`. Then every dangerous rune at or above U+007F anywhere in the output, keys included, is replaced by its `\uXXXX` escape. U+2028 and U+2029 get no special case.
   - `encoding/json` alone writes DEL, C1, bidi and zero-width runes raw. This was **Verified** on go1.27.1.
   - If the marshaled bytes are not valid UTF-8, rendering fails and nothing is written.
   - Decoding returns the exact strings. Invalid UTF-8 in a field has already become U+FFFD, which is an `encoding/json` limit.
3. **One self-describing document on stdout.**
   - Both formats carry `status`, the failures, and counts by severity, so a consumer that reads only stdout cannot mistake an incomplete scan for a clean one.
   - `status` comes only from `Result.Incomplete()`.
   - stderr is used only for errors that stop the report. Every renderer error exits 3 with a fixed line. The other exit codes are unchanged.
   - Consumers must check the exit code first, and treat empty or unparseable output as a failure.
4. **Integer `schema_version`, starting at 1.**
   - It changes only on a breaking change: a removed or renamed field, or a changed type or meaning.
   - Adding a field does not change it.
   - Arrays and objects are never `null`.
5. **Every printed field is checked at the registry, cheap checks first.** A finding that fails any check is dropped as `invalid finding` (fail closed). The renderers still escape everything, as defence in depth.

   | Field | Rule |
   |---|---|
   | ID | `^[a-z0-9][a-z0-9._-]*$`, at most 128 bytes |
   | Category | empty, or the same grammar as ID, at most 64 bytes |
   | Description | valid UTF-8, at most 1024 bytes |
   | Metadata keys | `^[a-z][a-z0-9_]{0,63}$` |

   - The 64-byte and 1024-byte limits are **Assumed** sizes.
   - **Redactor check:** after the cheap checks pass, `redactor.Redact` runs on each field, stopping at the first failure.
     - ID, Title, File, Evidence and Metadata string values are rejected if anything is detected other than label-like text.
     - Category, Description and Metadata keys are rejected if anything is detected, label-like text included.
6. **No reflection formatting in `internal/report`.** It never imports `fmt` and never formats a Finding, a Result or an `any` with reflection. An import allowlist test enforces this.

## Alternatives considered

- **Delete dangerous runes.** Matches the story wording, but hides tampering and can change meaning (bidi, zero-width characters). Rejected.
- **Quote every field with `strconv.Quote`.** Least code, but a quoted multi-field report is hard to read. Rejected for text. Only metadata values are quoted.
- **`strconv.IsPrint` alone.** Misses invisible fillers and variation selectors. Rejected.
- **Pre-escape strings with the text escapes before marshaling.** Terminal-safe, but consumers would get the literal text `\x1b` instead of the data. Rejected.
- **Plain `encoding/json`, leaving escaping to consumers.** Leaves `scan -json | cat` as a terminal-injection path. Rejected.
- **Findings-only JSON, with failures on stderr.** Fails open for JSON consumers. Rejected.
- **Placeholder text in the renderer for unchecked fields.** A bad finding would still count as accepted, and the scan could look complete. Rejected.
- **A semver or URI schema version.** Nothing requires minor versions, and an integer is simpler to check. Rejected.

## Consequences

- **Breaking CLI change.** The `scan` stdout format changes, and the failure and summary lines move from stderr to stdout. The REDACT-36 format was provisional.
- **Report input.** `internal/report` depends on `internal/scanner` and `internal/finding`, and the renderers take one `scanner.Result`. Reports covering several artifacts will need an aggregate type later.
  - Directory scans must also mark the report incomplete when `ingest.Walk` returns `ErrIncomplete`.
- **Fail-closed drops.**
  - A legitimate Description or Category that resembles a covered secret format or a label is dropped.
  - IDs, Categories and Metadata keys that do not match the grammars are dropped.
  - REDACT-37 scanners need tests showing that Description and Category are constant text.
- **Toolchain changes.** A Go toolchain update can change `strconv.IsPrint` or the Unicode property tables. The golden tests and the exhaustive rune test detect this.
- **Lossy file names in JSON.** In JSON, `file` values containing invalid UTF-8 become U+FFFD. Text output shows the exact bytes.
- **Accepted risk: 8-bit terminals.** A terminal not in UTF-8 mode may read the byte 0x9B inside a printable UTF-8 character as CSI. Escaping works on runes, not bytes, so it cannot prevent this.
- **Memory.** The worst case is bounded: about 96 MiB of JSON and roughly 200 MiB peak at 1000 maximal findings. This is accepted for a local CLI.
