# Redactor core: spec

Status: implemented (branch `feat/redactor-core`); fix round applied after staff and security review.
Package: `internal/redactor` (Go stdlib only).
Related: `docs/features/redactor-kinds/spec.md` (kind selection, `RedactWith`), `docs/architecture.md` section 14, `docs/threat-model.md` (redaction section added by this feature), ADR `docs/adr/0001-redactor-core-pseudonyms-and-fail-closed.md` (written by this feature).

> Spec text never contains realistic secret values. Examples use placeholders such as `AKIA<16 upper/digits>`; tests generate secrets at runtime (see 10).

## 1. Feature overview

**Purpose.** Provide a single, pure library function that replaces well-known secret formats in text with typed, per-call numbered labels, and that fails closed when it cannot vouch for its output. It is the foundation that the later `redact` CLI, streaming wrapper and MCP log path build on.

**In scope**

- `redactor.Redact(input []byte) (Result, error)` over a whole in-memory input with a hard size cap.
- Four detectors, held in a plain internal table: AWS access key IDs, AWS secret access keys (context-anchored only), GitHub tokens, PEM/PGP private key blocks.
- Per-call numbered labels (`[AWS_ACCESS_KEY_1]`), equality-preserving within one call.
- Neutralisation of pre-existing label-like text in the input.
- A verification pass, looser than detection, over the exact returned bytes.
- Encoding guard (NUL bytes, UTF-16/32 BOMs).
- Threat model redaction section and ADR 0001.

**Non-goals (this feature)**

- CLI command, config, profiles, scanner, quarantine, streaming, MCP.
- Session-wide or cross-call pseudonyms; label re-hydration (mapping a label back to a value). Any future re-hydration needs its own design and security review.
- Detecting JWTs, bearer/OAuth tokens, passwords, connection strings, PII, other cloud credentials, AWS secret keys without a key-name anchor, and the extra AWS key-ID prefixes `A3T`, `ABIA`, `ACCA` (Assumed formats; deferred).
- Further documented non-goals (see `docs/threat-model.md`): (a) an AWS secret value on the line after its key name (YAML block style) is neither redacted nor caught; (b) the dotted form `aws.secret.access.key=`; (c) `SecretAccessKey` JSON and Rails-style `secret_access_key:` without an `aws` prefix, which fail verification (false-fail, possible follow-up to align detector and verifier); 4-dash PEM markers; BEGIN markers without trailing dashes or with more than 64 characters of type text.
- Encoded or transformed secrets: base64-encoded (including base64-encoded PEM), compressed, URL-encoded, split or line-wrapped tokens, deliberately obfuscated secrets, and UTF-16/32 text (rejected, not decoded).
- Deliberate exfiltration by an adversary who controls the input format.
- Zeroising secret bytes in memory (Go cannot guarantee it; not promised).

The redactor reduces accidental disclosure of the covered formats. Docs, errors and any future CLI help must not describe its output as "safe to share".

## 2. Functional requirements and acceptance criteria

| ID | Requirement | Acceptance criteria |
| --- | --- | --- |
| FR1 | Size cap | `len(input) > MaxInputSize` (10 MiB = `10 << 20`) returns `ErrInputTooLarge`, nil `Output`, nil `Counts`. Exactly `MaxInputSize` bytes is accepted. The error text is a constant and contains no size. |
| FR2 | Encoding guard | Any `0x00` byte, or input starting with `FE FF` or `FF FE`, returns `ErrUnsupportedEncoding`, nil `Output`, nil `Counts`. A UTF-8 BOM (`EF BB BF`) is accepted. Checked after the size cap. |
| FR3 | AWS access key ID | `(?:AKIA\|ASIA)[A-Z0-9]{16,}` with no `\b` anchors and a greedy tail, so a stray `AKIA`/`ASIA` just before a real key cannot end the match partway into it and leave the rest of the body (security finding F1). Matches inside `AWS_KEY_AKIA...`, back-to-back keys and a key followed by `x`. The verifier keeps `{16}`. Label `AWS_ACCESS_KEY`. |
| FR4 | AWS secret access key | Context-anchored only: `(?i:aws[_-]?secret[_-]?access[_-]?key)["']?[ \t]*(?:=>\|:=\|[:=])[ \t]*["']?([A-Za-z0-9/+]{40}[A-Za-z0-9/+=]*)`. Only capture group 1 (the value, extended over trailing base64 characters) is redacted; key name, separator and quotes are preserved. Covers `KEY=v`, `key: v`, `"key": "v"`, `key = 'v'`, `export KEY="v"`. Label `AWS_SECRET_KEY`. |
| FR5 | GitHub tokens | `gh[pousr]_[A-Za-z0-9]{36,}` and `github_pat_[A-Za-z0-9_]{22,}`, no anchors, no upper bound (greedy, so no tail fragment survives). Label `GITHUB_TOKEN`. |
| FR6 | PEM/PGP private key blocks | BEGIN marker `(?i)-----BEGIN ((?:[A-Z0-9]+ ){0,4})PRIVATE KEY( BLOCK)?-----`, END marker the same with `END`. Covers RSA, EC, DSA, OPENSSH, ENCRYPTED, plain PKCS#8, PGP `... BLOCK` and the empty type. Terminated block: BEGIN line through END marker. Label `PRIVATE_KEY`. |
| FR7 | Unterminated / mismatched PEM | A BEGIN with no later END, or whose next END has a different type (case-insensitive compare), is redacted from BEGIN to end of input as one `PRIVATE_KEY` span; scanning stops. |
| FR8 | Orphaned PEM END | An END marker not inside any BEGIN-claimed span is redacted from the end of the previous PEM span (or offset 0 if none) through the END marker. `Proc-Type:` / `DEK-Info:` headers and base64 body lines are covered because they lie inside these spans. |
| FR9 | Labels | Format `[KIND_N]`, closed grammar `\[(AWS_ACCESS_KEY\|AWS_SECRET_KEY\|GITHUB_TOKEN\|PRIVATE_KEY)_[1-9][0-9]*\]`. `N` starts at 1 per kind per call and increases in order of first appearance by merged-span start offset. Equal (kind, merged bytes) get the same label. `N` never depends on a hash, prefix, suffix, length or the AKIA/ASIA type. |
| FR10 | Span merge | Spans that overlap are unioned to `[min start, max end)`; spans that merely touch are also unioned when both are secret kinds. A `LABEL_LIKE` span that only touches another span stays separate, so each label is neutralised and counted on its own (FR11). The merged span's kind is the highest priority constituent: `PRIVATE_KEY` > `GITHUB_TOKEN` > `AWS_SECRET_KEY` > `AWS_ACCESS_KEY` > `LABEL_LIKE`. No byte of any constituent span survives in output. |
| FR11 | Label-like input | Text in the input matching the label grammar (and not inside a merged secret span) is neutralised by replacing `[`/`]` with `(`/`)`, e.g. `(AWS_ACCESS_KEY_1)`, and counted in `Counts[KindLabelLike]` (occurrences). Input with a pre-existing `[AWS_ACCESS_KEY_1]` plus one real key yields exactly one real label in output. |
| FR12 | Verification | After building output, run loose checks (section 3.5) on the exact bytes to be returned. Any hit returns `ErrVerificationFailed` wrapped with the kind name only (`fmt.Errorf("%w: %s", ErrVerificationFailed, kind)`), nil `Output`, nil `Counts`. Never a value or offset. |
| FR13 | Output ownership | `Output` is always a freshly allocated slice that never aliases `input`, even with zero matches. Empty input returns `Output` = `[]byte{}` (non-nil) and empty non-nil `Counts`. |
| FR14 | Counts | On success, `Counts[kind]` is the number of distinct labels emitted for each secret kind present, plus `Counts[KindLabelLike]` occurrences when non-zero. Kinds with zero are absent. Nil on any error. |
| FR15 | No leaks via side channels | No logging, no package-level mutable state (the compiled regexps and detector/check tables are read-only), no caches or maps, no secret bytes or offsets in errors, no panics on any input. |
| FR16 | Concurrency | `Redact` is safe for concurrent use; compiled regexps and the detector and verifier tables are package-level read-only values (the only package-level state). |

## 3. Technical design

### 3.1 Public API (`internal/redactor/redactor.go`)

```go
package redactor

const MaxInputSize = 10 << 20 // 10 MiB

type Kind string

const (
    KindAWSAccessKey Kind = "AWS_ACCESS_KEY"
    KindAWSSecretKey Kind = "AWS_SECRET_KEY"
    KindGitHubToken  Kind = "GITHUB_TOKEN"
    KindPrivateKey   Kind = "PRIVATE_KEY"
    KindLabelLike    Kind = "LABEL_LIKE" // neutralised pre-existing label text, not a secret
)

var (
    ErrInputTooLarge       = errors.New("redactor: input exceeds maximum size")
    ErrUnsupportedEncoding = errors.New("redactor: unsupported encoding")
    ErrVerificationFailed  = errors.New("redactor: verification failed")
)

type Result struct {
    Output []byte       // fresh copy; nil on error
    Counts map[Kind]int // distinct labels per kind; nil on error
}

func Redact(input []byte) (Result, error)
```

### 3.2 Pipeline

```text
input
  -> size cap (FR1)            -> ErrInputTooLarge
  -> encoding guard (FR2)      -> ErrUnsupportedEncoding
  -> detect: token table spans + PEM cursor spans + label-like spans
  -> merge (union, priority)   (FR10)
  -> label (per-call, sha256-keyed equality map)  (FR9)
  -> build fresh output, record emitted label offsets
  -> verify exact output bytes (FR12) -> ErrVerificationFailed
  -> Result{Output, Counts}
```

All per-call state (span slice, equality map, emitted-offset list) is local to `Redact` and dropped on return.

### 3.3 Detector table (`detect.go`)

A plain slice of `{kind Kind, re *regexp.Regexp, group int}` for the regex detectors (AWS access key, AWS secret key with `group: 1`, GitHub classic, GitHub fine-grained), iterated with the `eachMatch` helper (one `FindSubmatchIndex` call per match, restarting after each match). `eachMatch` replaces `FindAll*` so the full match list is never held at once, which bounds memory on inputs with hundreds of thousands of matches. It is valid only while every pattern has no anchors, no `\b`, and cannot match the empty string, so restarting is equivalent to `FindAll`; a unit test guards this for every row. Adding a detector later means adding a row. The PEM detector is not a table row because RE2 has no backreferences; it is a dedicated function. The label-like detector is a separate regex producing `KindLabelLike` spans.

### 3.4 PEM cursor scan (`pem.go`)

Linear, a bounded number of forward passes:

1. `pos := 0`. Find the next BEGIN marker at or after `pos`. None: go to step 4.
2. From the BEGIN marker's end, find the next END marker.
   - None: span `[beginStart, len)`; stop BEGIN scanning.
   - Type equal (case-insensitive on the text between `BEGIN `/`END ` and the trailing `-----`): span `[beginStart, endEnd)`; `pos = endEnd`; repeat step 1. BEGIN markers inside this span are skipped by construction.
   - Type mismatch: span `[beginStart, len)`; stop.
3. (Covered above.)
4. Orphan pass: iterate all END markers with `eachMatch` (linear, no full match list held). For each END not inside a claimed span, emit span `[prevPEMEnd, endEnd)` where `prevPEMEnd` is the end of the nearest preceding PEM span (claimed or orphan) or 0.

Every byte is examined a bounded number of times, so the scan is O(n) apart from RE2's own linear guarantee.

### 3.5 Verification (`verify.go`)

Verification is deliberately looser than detection. It runs on the exact `[]byte` that will be returned. Checks, each naming its kind on failure:

| Kind reported | Loose check |
| --- | --- |
| `AWS_ACCESS_KEY` | `(?:AKIA\|ASIA)[A-Z0-9]{16}` |
| `AWS_SECRET_KEY` | `(?i)secret[_-]?access[_-]?key[^\n]{0,16}[A-Za-z0-9/+]{40}` |
| `GITHUB_TOKEN` | `gh[pousr]_[A-Za-z0-9]{20,}` or `github_pat_[A-Za-z0-9_]` |
| `PRIVATE_KEY` | `(?i)-----(?:BEGIN\|END)[^\n]{0,64}PRIVATE KEY` or `(?i)PRIVATE KEY(?: BLOCK)?-----` |
| `LABEL_LIKE` | every label-grammar match in output must be exactly at an offset this call emitted; any other match fails |

Decision: the optional `LS0tLS1CRUdJTi` (base64 of `-----BEGIN`) flag is **not** added. It would also fire on base64-encoded certificates (for example kubeconfig CA data), making whole common inputs fail; base64-encoded keys are a documented non-goal instead.

### 3.6 Equality map

`map[Kind]map[[32]byte]int` keyed by `sha256.Sum256(mergedBytes)` per kind (defense in depth: the map holds digests, not extra string copies of secrets). This is not a confidentiality guarantee; the input itself is in memory throughout.

### 3.7 Future CLI constraints (recorded, not built)

- Read input via `io.LimitReader(r, MaxInputSize+1)`; reject when more than `MaxInputSize` bytes arrive. Never chunk input into multiple `Redact` calls (labels and multi-line blocks are per call).
- Open only regular files; validate paths and refuse unsafe symlink traversal per AGENTS.md.
- Write nothing until `Redact` returns successfully.
- `-o` writes via a temp file in the same directory, then rename.
- Help text must not claim output is "safe to share".

## 4. Data/API changes and migrations

New package API only (section 3.1). No persisted data, no schemas, no migrations, no config. No existing callers.

## 5. Engineering decisions and rationale

| Decision | Rationale | ADR |
| --- | --- | --- |
| Numbered labels scoped to one call (user decided) | Keeps "same secret?" debugging signal without retaining secrets across calls. Same label in two calls refers to different values. Accepted risk: labels expose equality and count metadata. | ADR 0001 |
| Whole input in memory, 10 MiB cap (user decided) | Simplest correct multi-line handling and fail-closed behavior; streaming deferred. Cap value is Assumed adequate for typical logs. | ADR 0001 |
| Fail closed via a verification pass looser than detection | Detector bugs become errors, not leaks. | ADR 0001 |
| No `\b` anchors; unbounded GitHub token tail | Over-redaction is the safe direction; RE2 `\b` treats `_` as a word char and has no lookbehind. | spec only |
| Union merge with kind priority | Guarantees no constituent byte survives partial overlaps. | spec only |
| Unterminated/mismatched BEGIN redacts to EOF; orphaned END redacts from previous PEM span end (user decided BEGIN case) | Never leaks key material; loses trailing/leading text on truncated logs. | ADR 0001 |
| Reject NUL / UTF-16/32 BOM | Verified (security-reviewer, go1.27): UTF-16LE secrets are not matched; rejecting is fail-closed. | spec only |
| Stdlib only (`bytes`, `cmp`, `crypto/sha256`, `errors`, `fmt`, `regexp`, `slices`, `strconv`) | AGENTS.md; no dependency needed. | none |

Third-party/stdlib behavior claims:

- Go `regexp` runs in time linear in input size. **Verified**: `go doc regexp` on go1.27.1 states it is "guaranteed to run in time linear in the size of the input".
- Go `\b` is an ASCII word boundary where `\w` includes `_`. **Verified**: `go doc regexp/syntax` on go1.27.1, plus security-reviewer reproduction showing `AWS_KEY_AKIA...` was missed with anchors.
- RE2 has no lookbehind or backreferences. **Verified**: RE2 syntax referenced from `go doc regexp`; drives the PEM cursor design.
- 500k dense matches in 10 MiB in about 156 ms. **Verified** by security-reviewer measurement on go1.27; re-measure with the benchmark in step 6.
- AWS key ID format `AKIA`/`ASIA` + 16 `[A-Z0-9]`; extra prefixes `A3T`, `ABIA`, `ACCA`. **Assumed** (public AWS/gitleaks conventions).
- GitHub classic tokens `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36 alphanumerics; fine-grained `github_pat_` + 22+ `[A-Za-z0-9_]`. **Assumed** (GitHub's published token format announcements); confirm during implementation.
- AWS secret access key is 40 chars of `[A-Za-z0-9/+]`. **Assumed**.
- `gitleaks` allowlists/flags: not relied upon; tests avoid literal secrets entirely.

## 6. Risks and failure modes

| Risk | Handling |
| --- | --- |
| Uncovered secret formats leak | Accepted (user): narrow coverage. Documented non-goals; threat model states it. |
| Equality/count metadata via labels | Accepted (user). Documented in threat model and ADR. |
| False-fail: verification looser than detection (e.g. a truncated `ghp_` token of 20-35 chars, or `secret_access_key` text followed by a 40-char base64 run) returns an error for the whole input | Accepted fail-closed trade-off; error names the kind so the user knows why. |
| Over-redaction (unanchored AWS match inside longer identifiers; text lost after truncated PEM) | Accepted; safe direction. |
| Label collision with input text | Neutralisation (FR11) plus emitted-offset verification. |
| Pathological input (many BEGINs, many prefixes) causing CPU blowup | RE2 linear time; cursor scan; 10 MiB adversarial test with time budget. |
| Memory blowup | 10 MiB cap; output growth bounded (~1.3x input, not capped by `MaxInputSize`); peak heap growth about 9x input (about 100 MiB per call) checked by the sampled peak-heap test. Callers must bound concurrent `Redact` calls. |
| Panic on malformed bytes (invalid UTF-8) | RE2 treats invalid bytes as U+FFFD; fuzzing asserts no panic. |
| Secrets in test fixtures trip `task secrets` | Runtime-generated secrets only; no literal key material in repo. |

## 7. Security

- Trust boundary: input is untrusted text; output crosses to less-trusted consumers (later: AI via MCP).
- Adversary model (to be written into `docs/threat-model.md`): primary is accidental disclosure by a developer sharing logs; secondary is hostile log content trying to break redaction (label spoofing, pathological patterns, encoding tricks); deliberate exfiltration by the input author is a non-goal.
- Assets: credential values of the covered kinds.
- Fail-closed paths: size, encoding, verification. All return nil `Output`.
- No secret bytes or offsets in errors, logs or panics. Errors are constant sentinels; only the verification error is wrapped, with a kind name.
- No zeroisation promise.
- Labels are display-only.

## 8. Performance/scalability

- Single call bounded by `MaxInputSize`; O(n) time (RE2 + linear cursor scan).
- Budgets (asserted in tests/benchmarks): 10 MiB adversarial inputs complete within 5 s on a developer machine (assertion skipped under `-short` and under the race detector); peak heap growth under 10x input size, asserted by a sampled peak-heap test (aggressive GC percent, 10 MiB dense-key and label-like-spam inputs). Measured about 9.1x worst case, so the margin to the budget is thin and the figure is a sampled approximation. `BenchmarkRedact` still reports allocations.
- No caching, no goroutines.

## 9. Implementation steps

Single PR; the change is small (one package plus docs), so stacked PRs are unnecessary. Work on a feature branch (for example `feat/redactor-core`); do not implement on `main`.

1. **API skeleton and guards.** Add `redactor.go` with the section 3.1 API; implement size cap, encoding guard, empty input, fresh-copy output with no detectors yet. Replace the placeholder test.
   Depends on: none. Result: `Redact` returns a copy of input or the right sentinel error.
   Tests: exact cap and cap+1; NUL anywhere; `FE FF`/`FF FE` prefixes; UTF-8 BOM accepted; empty input gives non-nil empty output; output does not alias input (mutate output, input unchanged); `Counts` nil on error; error strings contain no digits from the size.
2. **Runtime secret generators (test helpers).** `secrets_test.go` with functions that build AWS key IDs, AWS secret values, GitHub classic/fine-grained tokens and PEM blocks of each type from a seeded `math/rand` source.
   Depends on: 1. Result: no literal secrets in the repo. Tests: generated values match the documented formats.
3. **Regex detector table.** `detect.go` with the four table rows and the label-like regex producing spans.
   Depends on: 1, 2. Result: spans for FR3, FR4, FR5, FR11.
   Tests: table-driven positives and near-misses per detector; `AWS_KEY_` prefix, back-to-back keys, key+`x`; AWS secret key forms (env, YAML, JSON, quoted, `=>`), value-only redaction with quotes preserved, unanchored 40-char run not matched; GitHub token at 36/255/256+ length, all prefixes.
4. **PEM cursor scan.** `pem.go` per section 3.4.
   Depends on: 1, 2. Result: FR6, FR7, FR8.
   Tests: each key type including PGP and empty type; LF and CRLF; lowercase markers; nested BEGIN inside a block; type mismatch to EOF; unterminated to EOF; orphaned END at start and after an earlier block (span starts at previous block end); `Proc-Type`/`DEK-Info` headers removed.
5. **Merge, labeling, output build.** Union merge with priority, sha256-keyed equality map, label numbering by merged start offset, neutralisation, emitted-offset record, `Counts`.
   Depends on: 3, 4. Result: FR9, FR10, FR11, FR13, FR14.
   Tests: nested, partial-overlap, touching and identical spans (assert no constituent byte survives); repeated value gets same label; distinct values numbered by first appearance; pre-existing `[AWS_ACCESS_KEY_1]` plus a real key gives exactly one real label and `Counts[KindLabelLike]==1`; label number independent of AKIA vs ASIA.
6. **Verification pass.** `verify.go` per section 3.5, wired before return.
   Depends on: 5. Result: FR12.
   Tests: each loose check fails closed on crafted output (unit-test the verifier directly); error unwraps to `ErrVerificationFailed` and contains only the kind; regression: GitHub token adjacent to AWS key does not false-fail; emitted labels for a sample of N in [1, 10^6] (1..1000, 999999, 1000000, random sample) match no detector or loose check other than the label grammar.
7. **Property, fuzz, race, performance.**
   Depends on: 6. Result: FR15, FR16, section 8 budgets.
   Tests: `FuzzRedact` that does not depend on detectors: embed runtime-generated secrets in fuzzed surrounding bytes and assert `err != nil` or that neither the secret nor any 12-byte window of its body (key/token body, each PEM body line) survives in the output, plus no panic; seeds: back-to-back keys, `_` prefixes, CRLF, orphaned END, nested BEGIN, token at 255. Parallel `Redact` test (run with `-race`). 10 MiB adversarial inputs (repeated BEGIN without END, repeated `AKIA` prefixes, repeated `ghp_`+35 chars, repeated label-like text) with time budget. `BenchmarkRedact` dense-match and no-match 10 MiB with `ReportAllocs`.
8. **Docs.** Fill `docs/threat-model.md` with the redaction section (adversary model, assets, covered kinds, non-goals, accepted risks, "not safe to share" wording). Write `docs/adr/0001-redactor-core-pseudonyms-and-fail-closed.md`. Add a follow-up note that `docs/architecture.md` still uses the "Sentinel" name (do not rename in this PR).
   Depends on: 1-7 (documents final behavior). Result: DoD docs items.

## 10. Testing strategy

- Unit, table-driven, per detector and per guard (steps 1, 3, 4).
- Merge/label invariants (step 5) and verifier unit tests (step 6).
- Regression tests for each security-reviewer case named above.
- Property/fuzz test independent of detector regexes (step 7); run `go test -fuzz=FuzzRedact -fuzztime=60s ./internal/redactor` locally before PR.
- `go test -race ./internal/redactor/...`.
- Performance: adversarial time-budget test and benchmark.
- Secrets: generated at runtime only; never printed in `t.Log`/failure messages (failure messages report kind and length, not the value).

## 11. Observability, deployment, rollback

- Observability: none by design (library; no logging to avoid leaks). Callers get typed errors and `Counts`.
- Deployment: internal package, no callers yet; nothing to roll out.
- Rollback: revert the PR.

## 12. Definition of done

- All FRs implemented with the tests in step 1-7 passing.
- `task test` passes; `go test -race ./internal/redactor/...` passes; fuzz run of 60 s finds nothing.
- `task verify` passes (fmt, golangci-lint, tests, gosec, govulncheck, gitleaks).
- No new dependencies in `go.mod`.
- `docs/threat-model.md` redaction section and ADR 0001 written; architecture "Sentinel" naming follow-up noted.
- No literal secret material anywhere in the repo or PR description.
