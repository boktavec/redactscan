---
name: debugging
description: Structured bug debugging - reproduce, form 3-5 hypotheses from logs/artifacts/code, try to disprove each from least to most likely, then apply the simplest fix. Use when the user reports a bug, incident, failing job, wrong output, or says "debug this".
---

# Debug

Follow the phases in order. Do not edit code before Phase 4. Report each phase's result in a few lines before moving on.

## 1. Recreate the bug
- State expected vs actual in one sentence each, with numbers (e.g. "1,222 should be enqueued, 297 were").
- Reproduce locally with the smallest command that shows it: an existing replay script, a test, or a curl. Reuse what the repo has before writing anything.
- Capture the failing output. If you can't reproduce, say so and list what differs from production (config, flags, data volume, time, image). Don't move on until you've reproduced it or named the gap.

## 2. Gather evidence, then write 3-5 hypotheses
- Read the logs, artifacts, config/deploy diffs and the code on the failing path. Use structured logs that already exist before adding prints.
- Find the **last known good boundary** and the **first incorrect boundary** along the data flow (input -> client -> job -> queue -> worker -> output). The bug lives between them.
- Distrust success signals. "Status=success", "Complete 1/1", empty DLQ and 99% success rates are measured against whatever the system saw, not what it should have seen. Check the denominator.
- Treat recent changes and loud errors as leads, not conclusions. They are often red herrings (an unrelated retry policy change, an error spike at the wrong time).
- Write 3-5 hypotheses. Each one gets:
  - a one-line claim about the mechanism,
  - the evidence for it,
  - the specific check that would **disprove** it.
- Rank by how well they fit **all** the evidence, not by "what changed". Re-rank whenever new evidence arrives.

## 3. Try to disprove each hypothesis, least likely first
- Work from least likely to most likely. Run the cheapest check that could kill each one, and record the result: killed or survived, and why.
- A hypothesis is only killed by a check that would have come out differently if it were true. Don't dismiss one on a hunch.
- If a check surprises you, go back to Phase 2 and re-rank. Add a new hypothesis if all of them die.
- Stop when one survives. Then prove it positively: the failure chain explained end to end, and a minimal repro that fails because of exactly that mechanism. Be able to explain why it wasn't caught earlier (staging data too small, flag off, etc.).

## 4. Simplest fix
- Write a regression test first, following the `write-tests` skill (real code paths, minimal fakes, production-shaped data). It must **fail on the old code for the reason you identified** and pass after the fix. A test that passes on the old code proves nothing. List any fakes and what they leave unverified in the close-out.
- Fix at the root cause, in the shared function, not at the symptom. Grep every caller/sibling of what you change; if others share the assumption, say so.
- Smallest diff that works. No refactors, no new abstractions, no unrelated cleanup. Remove any debug prints and keep existing logging/observability.
- Re-run the repro and the full test suite. Report before/after numbers.

## Close out (short)
- Root cause and failure chain in 3-4 sentences.
- What the verification proved and what it did not (prod data volume, other consumers, edge cases like an empty page).
- Remaining work, kept separate from the fix: data repair or reconciliation for damage already done, monitoring for the real invariant (not the success flag), and a rollback trigger if the fix ships.
