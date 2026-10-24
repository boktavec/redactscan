---
name: test-writing
description: How to write tests - real code paths over mocks, production-shaped fixtures, end-to-end through the real entry point. Use whenever writing or reviewing tests, including regression tests during debugging and tests for new features.
---

# Write tests

## Principles
- Use real code paths: the real functions, classes and calls, real parsing/serialization, and real storage (e.g. seeded SQLite or a local test server) wherever feasible. Every mock or fake is a place where the test can diverge from production and miss a regression.
- Fake only what you cannot run locally (third-party network, payment gateways, wall-clock time). Fake at the outermost boundary, not in the middle of your own code.
- Never fake the component under test or anything between it and the behavior you assert.
- Keep fixtures production-shaped: sizes that cross page/batch boundaries, real flag values, real field names, realistic edge data. Small happy-path data is how staging misses bugs.
- If you must fake something, read the real implementation and confirm the fake behaves the same on the case being tested. Note each fake and what it leaves unverified.
- Prefer one end-to-end style test through the real entry point over several unit tests with mocked collaborators. Add a narrow unit test only for edge cases (e.g. empty input, empty page).
- Assert on business outcomes (counts, totals, final state), not on internal calls.

## Keep infrastructure-dependent tests separate
- `task test` must run with no running services. Tests that need the local stack (databases, identity provider, queues, a browser) are integration or E2E tests: name them `*.integration.test.ts` or put them under `e2e/`, and run them with `task test:integration`.
- Integration tests should fail loudly, not skip silently, when the stack is down.
- Say in the PR which suites need the stack and whether CI runs them.

## Cover the unhappy path for security behavior
- For authentication, authorization, tenant isolation, and input validation, test the negative paths with the same weight as the happy path: missing, malformed, expired, and tampered credentials; forged cookies or IDs; another tenant's resource; unverified accounts; the dependency being down.
- Assert that failures are indistinguishable to the caller where they should be (same status and body) and that secrets never appear in logs or responses.
- Generate hostile inputs with the real mechanism where possible (sign a real token with a real key and break one property) rather than hand-written strings.

## Check before finishing
- Does the test fail if the behavior breaks? For a bug fix, run it against the old code and confirm it fails for the identified reason. For new code, break the logic temporarily (for example remove the throttle, flip the check, delete the guard) and confirm the test fails; revert afterward. If a test fails the first time you run it, decide whether the test or the code is wrong before changing either.
- Run the full suite, not just the new test.
- Match the repo's existing test framework and conventions. Don't add dependencies or frameworks.
