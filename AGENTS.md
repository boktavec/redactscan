# RedactScan Agent Instructions

## Project

RedactScan is a security-focused Go CLI.

Its responsibilities will include:

- scanning files and repositories
- identifying suspicious files or behavior
- quarantining suspicious content
- redacting sensitive information from logs and files

Future versions may expose redacted log streams to AI agents through MCP.

## Security Principles

Treat all scanned content as untrusted.

Never execute scanned files.

Never expose secrets or unredacted sensitive information.

Validate filesystem paths before performing filesystem operations.

Avoid unsafe symlink traversal.

Prefer fail-closed behavior for security-sensitive operations.

Security-sensitive behavior requires tests.

## Engineering

Use Go standard library where practical.

Avoid unnecessary dependencies.

Keep business logic outside `cmd/`.

Prefer small packages with clear responsibilities.

Add tests for new behavior.

## Development

Use the project Taskfile.

Run:

task test

during development.

Before completing work run:

task verify

Do not claim a task is complete unless `task verify` succeeds.

## External Libraries

Before using unfamiliar external libraries:

1. Inspect the version used by this repository.
2. Consult current documentation using Context7 when available.
3. Prefer existing project patterns.
4. Do not invent APIs.
