# Summary

<!-- Briefly explain what this PR adds, changes, or fixes. -->

## Related Work

<!-- Link the spec, ADR, and issue if they exist. Use commit-SHA permalinks or the default-branch path, not the feature branch. -->

Spec / ADR / issue:

## Context

<!-- Why is this being built? What problem or requirement does it address? -->

## Implementation

<!-- Explain the main implementation approach. Focus on architecture and important decisions, not a file-by-file walkthrough. -->

### Why this approach?

<!-- Why was this solution chosen? Mention meaningful alternatives considered and the tradeoffs made. -->

## Security Considerations

<!--
RedactScan treats scanned content as untrusted. Cover what applies: filesystem path validation and symlink handling,
fail-closed behavior, secret/redaction handling (nothing sensitive in logs, errors, or test output),
parsing of untrusted input, and CI/workflow permissions or credentials.
Write N/A only if the change cannot affect any of these.
-->

## Manual Testing

<!--
Provide clear steps a reviewer can follow to verify the change manually (commands and sample input).
Do not substitute unit tests for manual verification.
-->

1.
2.
3.

### Expected Result

<!-- What should the reviewer observe if the change is working correctly? -->

## Automated Tests

### Unit Tests

<!-- What behavior is covered by unit tests? -->

-

### Regression Tests

<!-- What previously working behavior is explicitly protected from regression? -->

-

## Edge Cases

<!--
List important edge cases and failure scenarios.

Clearly identify anything known but NOT currently handled.
Do not claim "none" without considering failure modes, invalid or hostile input, symlinks, large files, and concurrency where relevant.
-->

### Covered

-

### Not Yet Covered / Follow-up

-

## New Dependencies

<!-- List each new module and why it is needed. Write N/A if none. -->

-

## Running Locally

<!-- Commands to build and run the change (for example `task build`, `task run`, `task verify`). -->

## Additional Notes

<!-- Optional: compatibility concerns, migration, observability, follow-up work, etc. -->
