# Redactor kind selection with fail-closed verification: spec

Status: approved by the user (design review after interview questions 1-3). `security-reviewer` design review: requirements R1-R7 are folded in below. R6 is recorded as a follow-up only.
Story: REDACT-16, "Redactor option to select detector kinds with fail-closed verification".
Branch: `feat/redact-16-redactor-kinds` from `main` (worktree `redactscan-redact-16`). One PR, about 300 changed lines including tests and docs. Split before about 500.
Packages: `internal/redactor` (API), plus one `refusalReason` case in `internal/cli`. Go standard library only; no new dependency.
Related: `docs/architecture.md` section 14 (profiles), `docs/threat-model.md` (Redaction), ADR 0001, `docs/features/redactor-core/spec.md`.

> Spec text and tests never contain realistic secret values. Tests build secret-shaped input at runtime, as the existing helpers in `internal/redactor/*_test.go` do.

## 1. Feature overview

**Purpose.** A profile author can choose which secret kinds the redactor redacts, so that profiles can differ, without making any profile less safe than the default.

**Model.** For each covered secret kind, a selection means one of two things:

- **selected:** the kind is redacted to a label, as `Redact` does today;
- **not selected:** input that contains the kind is **refused** as a whole (`VerificationError{Kind}`, nil output). An unselected kind is never passed through.

Selection only restricts which inputs succeed. It never reduces what is detected or verified. On success, the output of `RedactWith` is byte-identical to the output of `Redact` on the same input.

**Concrete example.**

```go
// Profile "ci-logs" redacts tokens and AWS keys but refuses any input with a private key.
res, err := redactor.RedactWith(input, redactor.Options{
    Kinds: []redactor.Kind{redactor.KindAWSAccessKey, redactor.KindAWSSecretKey, redactor.KindGitHubToken},
})
// Input with a PEM private key   -> err is *VerificationError{Kind: PRIVATE_KEY}, res is zero.
// Input with only a GitHub token -> success; output equals Redact(input).Output.
```

**Scope.**

- `type Options struct{ Kinds []Kind }` and `func RedactWith(input []byte, opts Options) (Result, error)`.
- `Redact(input)` becomes `RedactWith(input, Options{})`. Its behaviour does not change.
- New sentinel `ErrUnknownKind`. `internal/cli` maps it to a fixed string (security R5).
- Docs: threat model, ADR 0004, a note in architecture section 14.

**Non-goals.**

- Passing an unselected kind through, or relaxing the verifier for it.
- A distinct "kind not selected" error (R6, follow-up).
- Profiles, config files, CLI flags or MCP exposure of kind selection.
- Exported kind lists or a `ParseKind` helper.
- New detectors or kinds.

## 2. Functional requirements and acceptance criteria

| ID | Requirement | Acceptance criteria |
| --- | --- | --- |
| FR1 | `Redact` is unchanged. | All existing tests pass unmodified. `Redact(x)` is implemented as `RedactWith(x, Options{})`. |
| FR2 | Default selection. | A nil `Kinds`, an empty `Kinds` and all four secret kinds give results identical to `Redact` (the same `Output` bytes, the same `Counts`, and the same error or no error) on every fixture (deterministic table test). |
| FR3 | Validation. | Each entry must be exactly one of `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `GITHUB_TOKEN` or `PRIVATE_KEY`. Anything else returns `ErrUnknownKind` with a zero `Result`. Rejected examples: `LABEL_LIKE`, `""`, `aws_access_key`, `Github_Token`, `EMAIL`. Duplicates are accepted and count once. |
| FR4 | Validation runs first. | Invalid options together with an oversized (> `MaxInputSize`) or NUL-containing input return `ErrUnknownKind`, not `ErrInputTooLarge` or `ErrUnsupportedEncoding`. |
| FR5 | Error text is constant. | `ErrUnknownKind.Error()` is `"redactor: unknown kind"`. It never contains the rejected value or its index. |
| FR6 | An unselected kind refuses the input. | If any raw `detect()` span (regex detector or PEM) has a secret kind that is not selected, return `*VerificationError{Kind}` (matching `ErrVerificationFailed` via `errors.Is`) with a zero `Result`, before any rendering. |
| FR7 | Nested unselected spans are refused (R2). | With `Kinds=[GITHUB_TOKEN]`, a `ghp_` token whose tail contains `AKIA` + 16 upper-case letters or digits fails with `AWS_ACCESS_KEY`. With `Kinds=[AWS_ACCESS_KEY]`, the same input fails with `GITHUB_TOKEN`. Neither returns partial output. |
| FR8 | All detection always runs (R1). | With `Kinds=[GITHUB_TOKEN]`, `aws_secret_access_key` with more than 16 spaces or tabs around the separator, followed by a 40-character value, fails with `AWS_SECRET_KEY`. That shape is found by the detector, not by the verifier, which allows at most 16 characters. Every detector, the PEM scan and the label-like scan run whatever is selected. |
| FR9 | The failure order is fixed. | When several unselected kinds are present, the error names the first in this order: `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `GITHUB_TOKEN`, `PRIVATE_KEY`. It names no value or offset. |
| FR10 | The verifier is unchanged. | `verify` runs all `looseChecks` and the label check on every successful render, whatever is selected. |
| FR11 | Label-like text is independent of selection (R3). | `KindLabelLike` is never subject to the selection check. A forged `[PRIVATE_KEY_1]` in input with `Kinds=[GITHUB_TOKEN]` and no real private key succeeds: it is neutralised to `(PRIVATE_KEY_1)` and `Counts[LABEL_LIKE]` is incremented. `labelRe` keeps all four label names. |
| FR12 | The caller's slice is safe (R4). | `RedactWith` copies `opts.Kinds` into a local fixed-size set at call start. It never modifies or keeps the caller's slice (the test compares the slice before and after). The doc comment states that one `Options` value may be shared across goroutines as long as no goroutine modifies `Kinds` during a call. |
| FR13 | Success equals `Redact` (R7). | For any input and any valid subset S, `RedactWith` either returns an error with a zero `Result`, or returns `Output` byte-identical to `Redact(input).Output`, with `Counts` keys limited to S plus `LABEL_LIKE`. It never succeeds when `Redact` errors. |
| FR14 | CLI mapping (R5). | `refusalReason` maps `ErrUnknownKind` to the fixed string `invalid redaction options` and never prints `err.Error()`. The CLI does not call `RedactWith` in this story; the case is defensive and unit-tested directly. |

**Accepted false failure (R2, documented).** With `Kinds=[PRIVATE_KEY]`, a PEM body that happens to contain `AKIA` + 16 upper-case letters or digits fails with `AWS_ACCESS_KEY`, even though `Redact` would have covered it with the `PRIVATE_KEY` span. The selection check runs on raw spans, before merging, so nesting can never hide an unselected kind. Refusing is the fail-closed direction.

## 3. Technical design

**Flow of `RedactWith`:**

```text
opts.Kinds --validate+copy--> selected set (fixed array, 4 entries)     [ErrUnknownKind]
input --size/encoding checks-->                                         [ErrInputTooLarge / ErrUnsupportedEncoding]
      --detect()  (all detectors, PEM, labelRe; unchanged)
      --checkSelected(raw spans, selected)  BEFORE mergeSpans           [VerificationError{first unselected kind}]
      --mergeSpans --> render --> verify (unchanged)                    [VerificationError]
      --> Result
```

**Code layout (internal/redactor):**

- `redactor.go`
  - `Options` with a doc comment covering the default (nil or empty means all four kinds), validation, refusal semantics, sharing across goroutines, and the rule that the caller's slice is never kept.
  - `ErrUnknownKind` in the sentinel block.
  - `RedactWith`.
  - `Redact` delegates to it.
  - An unexported `secretKinds = [...]Kind{KindAWSAccessKey, KindAWSSecretKey, KindGitHubToken, KindPrivateKey}`, the canonical order used for validation and FR9.
  - An unexported `kindSet [len(secretKinds)]bool` with:
    - `newKindSet(kinds []Kind) (kindSet, error)`: nil or empty gives all true; an unknown entry gives `ErrUnknownKind`;
    - `has(k)`.
- `detect.go` or `redactor.go`: `checkSelected(spans []span, sel kindSet) error`. It records which unselected secret kinds appear among the raw spans, skips `KindLabelLike`, and returns `verifyError` for the first in `secretKinds` order. It must run before `mergeSpans`, which reuses and overwrites the span slice.
- `verify.go`, `pem.go` and the detector table do not change.

**Why the check runs on raw spans.** `mergeSpans` gives a merged span the highest-priority kind, so an unselected `AWS_ACCESS_KEY` nested in a selected `GITHUB_TOKEN` would disappear from view after merging. Filtering spans before rendering instead would leave fragments of an unselected token below the verifier's thresholds (for example `ghp_[AWS_ACCESS_KEY_1]...`) and leak them silently. Rejecting on raw spans avoids both.

**Why success equals `Redact` (FR13).** If no raw span has an unselected kind, the span set is exactly the one `Redact` would use. Merging, rendering and verification are then identical.

## 4. Data/API changes and migrations

- New exported API: `Options`, `RedactWith` and `ErrUnknownKind`. This adds to the package API without breaking it.
- `Redact` keeps its signature and behaviour.
- No persisted data, wire format or migration. `Counts` keys and the `-json` CLI contract do not change.

## 5. Engineering decisions and rationale

| Decision | Why | Alternatives rejected |
| --- | --- | --- |
| Unselected means refuse; the verifier is never relaxed (user, question 1). | Selection cannot weaken the safety net, which fits ADR 0001 and fail-closed behaviour. | Pass-through with the verifier skipping that kind: silent credential leak. Selection only for future non-secret kinds: speculative. |
| Nil or empty `Kinds` means all kinds (user, question 2). | The zero value gives maximum protection, and `Redact` is `RedactWith(x, Options{})`. Nil and empty are treated the same. | An error for empty `Kinds`. "No kinds", which would turn `Options{}` into refuse-everything. |
| Reject on raw detector spans before merging (user, question 3; security R2). | Closes nested-span and partial-fragment leaks with a total, simple rule. | Filtering before merge (leaks fragments). Tracking constituents through merge (more complex, same result). |
| Reuse `VerificationError{Kind}` (user, question 3). | No CLI change and no new error-handling path. | `ErrKindNotSelected` (R6): deferred until profiles exist. |
| Validate options before input checks. | A configuration error is reported deterministically, whatever the input. | Input checks first. |
| Constant `ErrUnknownKind` with no echo. | Config values may later come from untrusted files; keeps errors constant like the other sentinels. | Echoing the bad name to help authors (left to a future config layer, which knows its own input). |

**ADR.** Write `docs/adr/0004-kind-selection-refuses-never-passes-through.md`. It records that kind selection narrows redaction only by refusing input, that detection and verification always run in full, and that a future distinct error belongs to the profile work. Future profile, config and MCP work depends on this.

## 6. Risks and failure modes

| Risk | Mitigation |
| --- | --- |
| Partial leak of an unselected token cut by a selected span. | Raw-span rejection (FR6, FR7) plus the fuzz oracle (FR13). |
| Selection accidentally disables a detector or verifier check. | No code path consults the selection outside `checkSelected`. FR8 and FR10 tests. |
| A caller retries with a different selection to get past a refusal. | Documented as forbidden in the threat model. Retrying cannot succeed by deselecting a detected kind, because that also refuses. Retrying by adding the kind just redacts it (the safe direction). |
| False failures increase (the R2 nested case, deselected kinds). | Accepted and documented; the error names the kind. |
| Caller mutates `Kinds` concurrently. | Copied at call start (FR12). Concurrent writes by the caller are a caller data race, as documented. |
| Error text leaks config or input. | Constant sentinel; `refusalReason` uses fixed strings (FR5, FR14). |

## 7. Security

- Trust boundary unchanged: input is untrusted and never executed, and the output goes to less-trusted consumers.
- Kind names are configuration, but are treated as untrusted: validated against a closed set, case-sensitive, and never echoed.
- Fail-closed: refusal returns a zero `Result` before rendering. Nothing derived from the input is produced.
- Label spoofing protection is unchanged and independent of selection (FR11).
- Threat-model additions (step 4):
  - selection only restricts and never reduces detection or verification;
  - an unselected kind, including one nested in another span, refuses the whole input with nil output, naming the kind in the fixed order;
  - callers must not retry with a different selection to get around a refusal;
  - a future CLI, config or MCP exposure must validate kind names through `RedactWith` (`ErrUnknownKind`), not with its own parsing;
  - the accepted false failure from R2.

## 8. Performance/scalability

- `checkSelected` is one linear pass over spans that already exist, plus a fixed four-entry array. It adds no allocation beyond that array and no regex work.
- The input cap, linear-time guarantees and memory budget are unchanged. Refusal happens before render, so refused inputs use less memory than successful ones.

## 9. Implementation steps

Each step leaves `task test` green.

1. **API and validation.** Depends on: none.
   - In `redactor.go`, add `secretKinds`, `kindSet`, `newKindSet`, `Options`, `ErrUnknownKind` and `RedactWith`, and make `Redact` delegate.
   - In this step `RedactWith` validates, then behaves exactly like `Redact`.
   - Tests (new `options_test.go`):
     - FR2 deterministic equivalence over the existing fixtures and a mixed input (nil, empty, all four, all four with duplicates);
     - FR3 rejection table;
     - FR4 ordering (invalid options with oversize input and with a NUL input);
     - FR5 error text;
     - FR12 slice unchanged.
   - Expected result: existing tests pass unmodified.
2. **Selection check.** Depends on step 1.
   - Add `checkSelected` and call it on the raw `detect()` result before `mergeSpans`.
   - Tests:
     - each kind selected alone with input containing each other kind (refused with that kind, zero Result) and its own kind (redacted, output equals `Redact`);
     - FR7 nested cases in both directions;
     - FR8 long-whitespace AWS secret;
     - FR9 ordering with several unselected kinds;
     - FR11 forged label for an unselected kind (success, `Counts[LABEL_LIKE]`);
     - the R2 accepted false failure as a pinned test, so a behaviour change is deliberate;
     - a PEM block containing a GitHub token with `Kinds=[GITHUB_TOKEN]` fails with `PRIVATE_KEY`.
3. **Fuzz oracle and concurrency.** Depends on step 2.
   - Add `FuzzRedactWith` to `robustness_test.go`, reusing `fuzzSecrets` and the seeds, plus a `uint8` subset mask (0 maps to nil `Kinds`). Assert FR13.
   - Add a concurrent test that shares one `Options` value across goroutines.
   - Run `go test -fuzz FuzzRedactWith -fuzztime 60s ./internal/redactor` locally once and record it in the PR, using `-fuzzminimizetime 1s` and reporting the real exec count.
4. **CLI mapping and docs.** Depends on step 2.
   - Add the `ErrUnknownKind` case to `refusalReason` in `internal/cli/redact.go` and a row to its table test in `cli_test.go`.
   - Update `docs/threat-model.md`: a kind-selection control row, the R2 accepted risk, and the caller constraints from section 7.
   - Write ADR 0004.
   - Add a note to `docs/architecture.md` section 14 below the profile YAML: excluding a secret kind refuses input containing it, and never passes it through.
   - Update the `redactor-core` spec only with a pointer to this spec if needed.
   - Expected result: `task verify` passes.

Total size is about 60 lines of production code, 150-200 lines of tests and about 60 lines of docs. One PR.

## 10. Testing strategy

- **Unit (table-driven):** FR2-FR12 and FR14, as listed in section 9. Secret-shaped values are built at runtime.
- **Regression:** the existing redactor and CLI tests run unchanged (FR1).
- **Fuzz (FR13):** for any input and valid subset, the call either errors with a zero `Result`, or its output equals `Redact`'s output and its counts keys are within the subset plus `LABEL_LIKE`; it never succeeds when `Redact` errors.
- **Concurrency:** a shared `Options` value under the race detector (`task test` runs race-enabled where the repo already does).
- **Failure paths:** every refusal asserts `res.Output == nil && res.Counts == nil`.

## 11. Observability, deployment, rollback

- No logging or metrics: the package does not log, by design.
- Deployment: a library addition. No caller passes options yet, so CLI behaviour is unchanged.
- Rollback: revert the PR. Nothing persisted depends on it.

## 12. Definition of done

- FR1-FR14 are covered by tests, and existing tests pass unmodified.
- `task test` and `task verify` succeed.
- `docs/threat-model.md`, `docs/architecture.md` section 14 and ADR 0004 are updated or written.
- `staff-engineering-reviewer` reports PASS (or PASS WITH ADVISORIES), and `security-reviewer` reports PASS, because this touches redaction.
- The PR uses `.github/pull_request_template.md` and links this spec and ADR 0004.

## Follow-ups (not in scope)

- R6: a distinct `ErrKindNotSelected` that still matches `ErrVerificationFailed` via `errors.Is`, introduced with the profile/config layer, together with its CLI message.
- A profile/config layer that maps profile names such as `credentials` and `tokens` to kinds through `RedactWith` validation.
