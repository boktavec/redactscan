# ADR 0001: Redactor core uses per-call pseudonyms, bounded in-memory input and a fail-closed verifier

Status: Accepted
Date: 2026-10-24
Spec: `docs/features/redactor-core/spec.md`

## Context

RedactScan needs a redaction core that later backs a CLI, a streaming wrapper and an MCP log path. `docs/architecture.md` section 14 sketches typed pseudonyms (`[EMAIL_1]`) that map repeated raw values to the same pseudonym "within a session", and requires redaction to fail closed. We had to decide how long pseudonyms live, how much input one call handles, and how the core behaves when its own detectors may be wrong.

## Decisions

1. **Numbered labels are scoped to one `Redact` call.** Labels look like `[AWS_ACCESS_KEY_1]`, are numbered per kind in order of first appearance, and equal values share a label inside the call. The equality map is keyed by SHA-256 digests of the matched bytes and dropped on return.
2. **The whole input is processed in memory under a 10 MiB cap** (`MaxInputSize`), with `ErrInputTooLarge` above it. Multi-line constructs (PEM blocks) and numbering are then trivially correct.
3. **Fail closed through a verification pass that is looser than detection.** After output is built, broader patterns scan the exact bytes to be returned; any hit returns `ErrVerificationFailed` wrapped with the kind name only, and nil output. NUL bytes and UTF-16/32 BOMs are rejected up front for the same reason.
4. **Truncated or mismatched PEM redacts to end of input; an orphaned END redacts back to the previous PEM span.** Key material is never left behind, at the cost of text around damaged blocks.

## Alternatives considered

- **Session-wide pseudonyms (as the architecture sketch says).** Stable labels across calls help correlation, but need retained state holding secret-derived data and a lifecycle, and invite label re-hydration. Rejected for now; per-call labels keep the useful "same secret?" signal without retaining anything.
- **Opaque placeholders such as `[REDACTED]`.** No metadata exposure at all, but loses the equality signal that makes redacted logs debuggable. Rejected by the user in favour of numbered labels.
- **Streaming or chunked redaction.** Needed eventually for live logs, but cross-chunk matches, per-call numbering and PEM spans make it a design of its own. Deferred.
- **Detector-only checking (no verifier).** Simpler, but a detector bug becomes a silent leak. The verifier is a second, independent net.
- **Verifier flag for base64 of the PEM marker.** Would also fire on base64-encoded certificates (for example kubeconfig CA data), failing common inputs. Base64-encoded keys are a documented non-goal instead.

## Consequences

- Labels expose equality and per-kind distinct counts (accepted). The same label in two calls means different values, and nothing maps a label back to a value. Session-wide pseudonyms or re-hydration require a new ADR and a security review.
- Some benign inputs fail verification (a truncated `ghp_` token, a key-name followed by a 40 character run). The error names the kind.
- Over-redaction is the intended failure direction for ambiguous matches.
- Callers must not chunk input across calls and must treat the three sentinel errors as hard stops (see the threat model).
- Memory is bounded per call by the cap; peak heap growth on adversarial 10 MiB inputs is about 9x the input (roughly 100 MiB per call; 10x budget, thin margin). A future CLI or MCP caller must bound the number of concurrent `Redact` calls.
- `docs/architecture.md` is not updated here: it still says "Sentinel" and describes session-scoped pseudonyms. Reconcile in a follow-up.
