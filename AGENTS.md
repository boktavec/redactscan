# AGENTS.md

## Project

RedactScan is a security-focused Go CLI.

- `cmd/redactscan/`: CLI entry point. Keep business logic out of `cmd/`.
- `internal/`: `scanner/`, `redactor/`, and `config/` packages (quarantine is not built yet).
- `docs/`: `architecture.md`, `threat-model.md`, and `adr/`.
- `testdata/`: fixtures for scanner and redactor tests.
- `.github/workflows/`: `pr-visual-recap.yml` (PR recaps).

Responsibilities:

- scanning files and repositories
- identifying suspicious files or behavior
- quarantining suspicious content
- redacting sensitive information from logs and files

Future versions may expose redacted log streams to AI agents through MCP.

## Security Principles

- Treat all scanned content as untrusted. Never execute scanned files.
- Never expose secrets or unredacted sensitive information.
- Validate filesystem paths before performing filesystem operations. Avoid unsafe symlink traversal.
- Prefer fail-closed behavior for security-sensitive operations.
- Security-sensitive behavior requires tests.

## Engineering Principles

- Use the Go standard library where practical. Avoid unnecessary dependencies; a new one needs a clear reason to exist.
- Prefer small packages with clear responsibilities.
- Start simple; add complexity only for real requirements and measured problems.
- Add tests for new behavior.

## Project Skills

Read the relevant skill file before starting that kind of work. The files live in this repository so every agent uses the same guidance:

| Skill | File | When to use it |
| --- | --- | --- |
| Pragmatic development | [`.agents/skills/pragmatic-development/SKILL.md`](.agents/skills/pragmatic-development/SKILL.md) | Default approach for implementing and reviewing features. |
| Test writing | [`.agents/skills/test-writing/SKILL.md`](.agents/skills/test-writing/SKILL.md) | Whenever writing or reviewing tests, including regression tests. |
| Debugging | [`.agents/skills/debugging/SKILL.md`](.agents/skills/debugging/SKILL.md) | Bugs, incidents, failing jobs, and wrong results. |
| Security audit | [`.agents/skills/security-audit/SKILL.md`](.agents/skills/security-audit/SKILL.md) | Security questions and focused design/code reviews: use guidance mode. Run its full audit workflow only when explicitly requested; follow its sandbox and authorization requirements. |
| Distributed systems review | [`.agents/skills/distributed-systems-review/SKILL.md`](.agents/skills/distributed-systems-review/SKILL.md) | Concurrency, external dependencies, resource limits, or the future MCP/streaming path. Apply lightly to local-only work. |
| Open Code Review (delegate) | [`.agents/skills/open-code-review-delegate/SKILL.md`](.agents/skills/open-code-review-delegate/SKILL.md) | Supplementary file selection and review rules via `ocr delegate`, used by `staff-engineering-reviewer`. Needs no LLM provider. Read `SOURCE.md` for local constraints. |
| Visual plan | [`.agents/skills/visual-plan/SKILL.md`](.agents/skills/visual-plan/SKILL.md) | All planning (see Planning and PR Recaps). |
| Visual recap | installed with the user's skills | Preview a PR recap locally. CI generates it automatically. |

## MCP Tools

These MCP servers are configured for the user's local Claude Code (this repo has no project `.mcp.json`). Check that a server is connected before relying on it; tool names and availability can vary by client.

- **`context7`** provides current third-party library documentation. Use it before using an unfamiliar library: inspect the version in `go.mod`, then consult current docs. Do not invent APIs. The repository and the threat model remain the authority for RedactScan requirements and decisions.
- **`plan`** (hosted Agent-Native Plan MCP) is not used. `visual-plan` runs in local-files mode: plans are MDX under `plans/<slug>/`, checked with `npx @agent-native/core@latest plan local check` and viewed through a localhost bridge, so plan content is not uploaded. Do not call hosted Plan tools. Never commit `.plan-url` (a local token file).

Keep MCP credentials out of the repository and do not paste them into issues, plans, logs, or PRs. If a server is unavailable, say which lookup could not be completed and continue with the work that does not depend on it.

## Planning and PR Recaps

All planning must use the `visual-plan` skill in local-files mode; the `senior-engineering-planner` agent creates the plan under `plans/<short-slug>/`. Save an approved spec at `docs/features/<short-slug>/spec.md` and record an ADR in `docs/adr/` for decisions with long-term impact. Label claims about third-party behavior **Verified** (and how) or **Assumed**.

PRs marked ready for review get a visual recap from `.github/workflows/pr-visual-recap.yml` (draft PRs are skipped; pushes do not re-run it, so add the `recap` label to regenerate). Use `visual-recap` to preview one locally. The workflow disables AGENTS.md loading for the recap agent so it does not run the checks below; normal CI owns testing and security verification.

## Agent Pipeline

Agent definitions live in `.claude/agents/` (Claude Code) and `.pi/agents/` (Pi); the Pi definitions reuse the corresponding Claude prompt as their role source of truth. Agents do not invoke one another; the main agent orchestrates the pipeline using the client's available subagent mechanism:

1. **Plan:** use `senior-engineering-planner` to interview the user (relay one question at a time, resuming it with the answer), which saves the spec and creates the local visual plan itself. For new trust boundaries or security-sensitive design, have `security-reviewer` review the design before seeking approval and incorporate its requirements.
2. **Implement:** after the user approves the plan, use `senior-software-engineer` with the spec path. Run parallel implementers in separate worktrees or sequentially; never in the same files at once.
3. **Review:** use `staff-engineering-reviewer` with the spec path, the diff, and the implementer's handoff. Independently use `security-reviewer` for changes that touch file or path handling, symlinks, quarantine, redaction, scanned-content parsing, secrets, or CI credentials; give it the same context. Do not substitute the general reviewer's security checks.
4. **Fix loop:** on CHANGES REQUIRED from either reviewer, resume the implementer with the findings, then re-run the relevant reviewer. Repeat until the staff reviewer reports PASS or PASS WITH ADVISORIES and, when invoked, the security reviewer reports PASS.
5. **Escalate to the user** (do not loop) on planning-level findings, a security BLOCK or NEEDS CONTEXT, reviewer BLOCKED / INCONCLUSIVE, risks requiring human acceptance, or after 3 review rounds without approval.

In Pi, use its `pi-subagents` extension with these project agents. If the extension is unavailable, report that blocker rather than silently pretending a subagent ran.

Commits, pushes, PRs, merges, and deploys still need explicit user instruction.

## Architecture Decisions

Do not silently make significant architectural decisions. For meaningful choices, consider reasonable alternatives, evaluate tradeoffs, choose the simplest solution that satisfies current requirements, and record an ADR when the decision has long-term impact.

## Development

Use the project Taskfile. Run `task test` during development.

## Pull Requests

When creating a PR, always use [`.github/pull_request_template.md`](.github/pull_request_template.md) and complete all applicable sections. PRs should clearly include:

- summary of what was built, and links to the spec and ADR when they exist
- context for why the change is needed, why it was designed this way, and meaningful alternatives and tradeoffs
- security considerations: path and symlink handling, fail-closed behavior, secret and redaction handling, untrusted input, and CI permissions
- manual testing steps and expected results (never replace these with automated test results)
- unit and regression test coverage
- important edge cases, including any not yet handled
- new dependencies and why each is needed
- how to run the change locally

Mark sections `N/A` only when they genuinely do not apply. Never put secrets or unredacted sensitive data in a PR description, comment, or test output. Run `task verify` before marking a PR ready for review: that triggers the paid visual recap.

## Agent Instruction Files

The root `AGENTS.md` is the source of agent guidance; the root `CLAUDE.md` only imports it.

## Definition of Done

Before completing meaningful work:

- run `task verify` and do not claim a task is complete unless it succeeds
- add or update tests for new behavior; security-sensitive behavior requires them
- consider failure modes and fail-closed behavior
- update relevant documentation (`docs/architecture.md`, `docs/threat-model.md`, ADRs)

Stay within scope. Document future improvements instead of implementing unrelated complexity.
