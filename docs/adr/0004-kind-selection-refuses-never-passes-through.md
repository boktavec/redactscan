# ADR 0004: Kind selection refuses input, it never passes a kind through

Status: Accepted
Date: 2026-10-26
Spec: `docs/features/redactor-kinds/spec.md`
Related: ADR 0001 (fail-closed redaction)

## Context

Profiles (architecture section 14) will let authors choose which secret kinds are redacted. A selection that simply skipped a kind would leak that kind, and relaxing the verifier for it would weaken the safety net that ADR 0001 relies on.

## Decisions

1. **Selection only restricts.** `redactor.RedactWith(input, Options{Kinds})` redacts the selected kinds. Input containing a kind that is not selected is refused as a whole (`*VerificationError{Kind}`, nil output). An unselected kind is never passed through.
2. **Detection and verification always run in full.** No code path consults the selection except `checkSelected`. On success the output is byte-identical to `Redact`'s.
3. **The check runs on raw detector spans, before merging.** Merging keeps only the highest-priority kind of overlapping spans, so a nested unselected kind would vanish; filtering spans before rendering would leave fragments of an unselected token below the verifier's thresholds. Accepted consequence: an unselected kind nested in a selected span (such as an AWS key shape inside a PEM body) refuses the input.
4. **Nil or empty `Kinds` means all four secret kinds**, so `Options{}` is maximum protection and `Redact` is `RedactWith(x, Options{})`.
5. **Validation first, constant error.** Unknown kinds (case-sensitive, closed set, `LABEL_LIKE` included) return `ErrUnknownKind` before any input check, with fixed text that never echoes the value. The CLI maps it to a fixed string.
6. **Reuse `VerificationError`.** The refusal names the first unselected kind in the order `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `GITHUB_TOKEN`, `PRIVATE_KEY`.

## Alternatives considered

- **Pass-through with the verifier skipping the kind.** Silent credential leak. Rejected.
- **Filter spans before merge.** Leaks fragments. Rejected.
- **Track constituents through merge.** More complex, same result. Rejected.
- **Empty `Kinds` as an error or as "no kinds".** Makes the zero value unsafe or unusable. Rejected.

## Consequences

- More false failures with narrowed selections; the error names the kind.
- A distinct `ErrKindNotSelected` (still matching `ErrVerificationFailed`) is deferred to the profile and config work, together with its CLI message.
- Callers must not retry a refusal with a different selection to get around it (threat model).
