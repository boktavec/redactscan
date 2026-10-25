# Upstream source

Vendored from [alibaba/open-code-review](https://github.com/alibaba/open-code-review), commit `375f64cd6f67a48a135da83cfcf59c52669a09cb` (the `skills/open-code-review-delegate/` directory). `LICENSE` is copied from the repository root. No upstream files were modified.

## RedactScan usage constraints

These override the upstream `SKILL.md` where they conflict:

- Use delegation mode only. `ocr` makes no LLM calls here, so no provider or credentials are needed; never run `ocr review` or `ocr scan`, which send code to an LLM endpoint.
- Do not install or upgrade `ocr` (`npm install -g ...`) without the user's approval. If it is missing, report that and continue the review without it.
- Reviewers stay read-only: skip the upstream "Step 7: Fix". Treat the rules and file list as input to your own review, and verify every finding against the code.
- Write temporary diff files only to the session scratchpad, never inside the repository.
