# Upstream source

Vendored from [alibaba/open-code-review](https://github.com/alibaba/open-code-review), commit `375f64cd6f67a48a135da83cfcf59c52669a09cb` (the `skills/open-code-review/` directory). `LICENSE` is copied from the repository root. No upstream files were modified.

## RedactScan usage constraints

These override the upstream `SKILL.md` where they conflict:

- `ocr review` sends diffs to the configured LLM endpoint. Use it only with a provider the user has configured; never put credentials in the repository.
- Do not install `ocr` (`npm i -g ...`) or upgrade it without the user's approval. If it is missing or has no configured provider, report that and continue the review without it.
- Reviewers stay read-only: skip the upstream "Step 4: Fix". Treat `ocr` output as advisory, and verify each finding against the code before reporting it.
