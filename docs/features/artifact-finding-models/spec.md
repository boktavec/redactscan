# Artifact and Finding models: spec

Status: approved by the user (design review, interview questions 1-4). `security-reviewer` design review: CHANGES REQUIRED, no BLOCK. Findings F1-F5 and I1-I3 are folded in below, with the user choosing metadata option (i).
Story: [REDACT-35](http://localhost:8080/issue/REDACT-35) "Artifact and Finding models".
Branch: `feat/redact-35-artifact-finding-models` (PR 2 stacks on PR 1; see section 9).
Packages: new `internal/artifact`, new `internal/finding`. Go standard library only, no new dependency, no I/O.
Related: `docs/architecture.md` sections 4-7 and 10, `AGENTS.md` security principles.

> Spec text and tests never contain realistic secret values. Tests build secret-shaped input at runtime.

## 1. Feature overview

**Purpose.** Give every future detector, the redact pipeline, the policy engine and the report code the same shared types: `artifact.Artifact` (with `SourceMetadata`), `finding.Finding` and `finding.Severity`.

- `Severity` has a total order and a parser that fails closed.
- `AtMost` and `AtLeast` are fail-closed threshold checks that deny when either side is invalid.
- `Finding.Validate` and `Artifact.Validate` reject mistakes they can see: an unset severity, oversize or non-UTF-8 evidence, and metadata that isn't a small set of bounded scalar values.

**Concrete example (future caller code, not part of this story).**

```go
f := finding.Finding{
    ID:         "script-curl-pipe-sh-1",
    Severity:   finding.SeverityHigh,
    Category:   "script",
    Title:      "Remote script piped to shell",
    ArtifactID: a.ID,
    File:       a.RelativePath,
    Line:       12,
    Evidence:   "curl <URL_1> | sh", // already redacted, at most 256 bytes
    Metadata:   map[string]any{"rule": "curl-pipe-sh", "count": 1},
}
if err := f.Validate(); err != nil { /* fail closed: treat as error/block */ }

allowMax, err := finding.ParseSeverity(" low ") // trusted config only
if f.Severity.AtMost(allowMax) { /* allow */ }   // false if either side is invalid
```

**Scope.**

- `internal/artifact`:
  - `Artifact` and `SourceMetadata`, exactly the fields in architecture section 5, with doc comments
  - `(Artifact).Validate() error` and `ErrInvalidArtifact`
  - the exported metadata check `ValidateMetadata` and its limits
- `internal/finding`:
  - `Severity` (an ordered int whose zero value is invalid), with `String`, `Valid`, `Compare` (invalid ranks highest), `AtMost` and `AtLeast`
  - `ParseSeverity` and `ErrInvalidSeverity`
  - `Finding`, exactly as in architecture section 6
  - `MaxEvidenceBytes = 256`, `(Finding).Validate() error` and `ErrInvalidFinding`
- `docs/architecture.md`: one new line in the section 4 package list for `finding/`.

**Non-goals.**

- Any I/O: no hashing, MIME detection, file reading or constructors that touch the filesystem.
- The `Scanner` interface (section 7), the policy engine (section 10), report and JSON output. No `MarshalText`/`UnmarshalText` or JSON tags.
- Typed constants for `SourceMetadata.Type`, and URI reduction. Both belong to the ingest story; this story only documents the rule.
- Validating the content of `ID`, `Category`, `Title`, `Description`, `File`, `Line`, `SHA256` or `URI`. These are covered by documented contracts only.
- Escaping terminal control and bidi characters. That's a follow-up for the report story (section 13).
- Any change to `internal/redactor`, `internal/safefs`, `docs/threat-model.md` or ADRs. REDACT-12 is changing `internal/redactor` and the threat model at the same time.

## 2. Functional requirements and acceptance criteria

| ID | Requirement | Acceptance criteria |
| --- | --- | --- |
| FR1 | `artifact.Artifact` and `artifact.SourceMetadata` match architecture section 5. | Fields, names, order and types are exactly: `ID string`, `Path string`, `RelativePath string`, `Name string`, `Size int64`, `MIMEType string`, `SHA256 string`, `Source SourceMetadata`, `Metadata map[string]any`; `SourceMetadata{Type string; URI string}`. Doc comments per section 3.1. |
| FR2 | `finding.Finding` matches architecture section 6. | Fields exactly: `ID string`, `Severity Severity`, `Category string`, `Title string`, `Description string`, `ArtifactID string`, `File string`, `Line int`, `Evidence string`, `Metadata map[string]any`. Doc comments per section 3.3. |
| FR3 | Severity values and order. | `SeverityInvalid = 0`, `SeverityInfo = 1`, `SeverityLow = 2`, `SeverityMedium = 3`, `SeverityHigh = 4`, `SeverityCritical = 5`. `Finding{}.Severity == SeverityInvalid`. |
| FR4 | `Valid()` | True exactly for 1..5. False for 0, -1, 6, 99, `math.MinInt`, `math.MaxInt`. |
| FR5 | `String()` | `"info"`, `"low"`, `"medium"`, `"high"`, `"critical"` for valid values; `"invalid"` for every other value. Never panics. |
| FR6 | `Compare(other) int` is a total order for sorting. | Returns -1, 0 or +1. Valid values compare by their order. Any invalid value (0, negative, > 5) ranks above `SeverityCritical`. Two invalid values compare equal (0, -1 and 99 all compare 0 to each other). Invalid vs valid gives +1, valid vs invalid gives -1, and `SeverityCritical.Compare(SeverityInvalid) == -1`. **`Compare` is not a threshold check.** With an invalid threshold `t`, `s.Compare(t) <= 0` is true for every valid `s`, so threshold code must use `AtMost`/`AtLeast` (FR7). The doc comment on `Compare` says this. |
| FR7 | `AtMost(limit)` and `AtLeast(limit)` fail closed on either side. | `s.AtMost(limit)` = `s.Valid() && limit.Valid() && s <= limit`. `s.AtLeast(limit)` = `!s.Valid() \|\| !limit.Valid() \|\| s >= limit`. Cases: `SeverityCritical.AtMost(SeverityInvalid) == false`; `SeverityInfo.AtLeast(SeverityInvalid) == true`; for invalid `s` and any `t` (valid or invalid), `s.AtMost(t) == false` and `s.AtLeast(t) == true`. For valid pairs, both match numeric order. |
| FR8 | `ParseSeverity(s string) (Severity, error)` | Steps in order: (1) trim ASCII whitespace only (`" \t\n\r\v\f"`); (2) reject if longer than 64 bytes; (3) reject if any byte is `>= 0x80`; (4) ASCII-lowercase and match one of the five names. `"high"`, `"HIGH"`, `" High\n"`, `" high"` give `SeverityHigh`. Rejects (returning `SeverityInvalid` and an error matching `errors.Is(err, ErrInvalidSeverity)`): `""`, whitespace only, `"invalid"`, `"unknown"`, `"crit"`, `"0"`, `"3"`, `"hi gh"`, `"high\x00"`, `"\xff"`, `"HİGH"` (dotted capital I), `"\u00a0high"` and `"high\u00a0"` (NBSP padding; write these with escapes in tests), full-width `"ｈｉｇｈ"`, and a 65-byte input. |
| FR9 | Parse errors are bounded. | The error text quotes at most the first 32 bytes of the raw input with `strconv.Quote`, and adds `...` when truncated. Format: `finding: invalid severity "<quoted prefix>"` with an optional trailing `...`. The error is bounded by the 32 raw input bytes: printable input gives under 100 bytes, and all-escaped input (up to 4 characters per byte) at most about 160 bytes; an ESC byte appears escaped, never raw. |
| FR10 | `ValidateMetadata(m map[string]any) error` (in `artifact`) | Accepts nil and empty maps. At most `MaxMetadataEntries = 32` entries. Each key is 1..`MaxMetadataKeyBytes = 64` bytes and valid UTF-8. Each value has dynamic type exactly `string`, `bool`, `int`, `int64` or `float64`. String values are at most `MaxMetadataValueBytes = 256` bytes and valid UTF-8. Rejected: `[]byte`, nested `map[string]any`, `[]any`, `[]string`, pointers, structs, named types (for example `type S string`), `error`, and nil values. A map that contains itself is rejected as a nested map with no recursion. Errors wrap `ErrInvalidMetadata`. |
| FR11 | `(Artifact).Validate() error` | Returns `ValidateMetadata(a.Metadata)` wrapped as `artifact: invalid artifact: metadata: ...` (wrapping both `ErrInvalidArtifact` and `ErrInvalidMetadata`). Nothing else is checked in this story. |
| FR12 | `(Finding).Validate()` | Checks in fixed order and returns the first failure, wrapping `ErrInvalidFinding`: (1) invalid severity → `invalid severity`; (2) `len(Evidence) > 256` → `evidence is N bytes, max 256` (256 accepted, byte count not runes); (3) evidence not valid UTF-8 → `evidence is not valid UTF-8`; (4) `artifact.ValidateMetadata(f.Metadata)` fails → `metadata: ...` (also matches `ErrInvalidMetadata`). Empty evidence is valid. Value receiver, never modifies or truncates. |
| FR13 | Validation errors never echo content. | No error from `Validate`, `ValidateMetadata` or `ParseSeverity` (beyond FR9's bounded quote of config input) contains evidence, a metadata key or a metadata value. Errors contain only field names, counts, byte lengths and the value's `reflect.Kind` (never `%T`, because runtime-built types can embed arbitrary strings; `nil` for a nil value). Tested with runtime-built secret-shaped values: no 8-byte substring of any such value appears in the error. |
| FR14 | Contracts are documented. | Package and field doc comments contain the text in sections 3.1 and 3.3. Specifically: the redacted-or-bounded rule for `Evidence`, `Title`, `Description`, `Category`, `ID` and both `Metadata` fields; the untrusted, display-only rule for `RelativePath`, `Name` and `Finding.File`; the `SHA256` format rule; the `URI` reduction rule; `Artifact.Metadata` being read-only after ingest; the no-reflection-formatting rule; and `ParseSeverity` being for trusted config only. |
| FR15 | Architecture doc lists the package. | `docs/architecture.md` section 4 has the line `  finding/                 shared Finding/Severity types` directly after `artifact/`. No other doc changes. |

## 3. Technical design

### 3.1 `internal/artifact`

`artifact.go`: package doc and types.

**Package doc:**

- Describes one item to scan or redact, independent of its source. Ingest produces it; scanners and the redact pipeline consume it. Performs no I/O.
- Every string field is derived from untrusted input.
- Never format an `Artifact` with `%v`, `%+v`, `slog` attributes or JSON into errors or logs. Log `ID` only.

**Field doc comments:**

- `ID`: stable identifier assigned by ingest; `Finding.ArtifactID` refers to it. Constant or generated text, never content from the scanned file.
- `Path`: where the content is on disk. Open it only through `internal/safefs`, never with plain `os.Open`.
- `RelativePath`, `Name`: "Untrusted. Display only. Never join to a directory or pass to a filesystem call. Output code must escape it."
- `Size`, `MIMEType`: filled by ingest; zero or empty when unknown.
- `SHA256`: lowercase hex from ingest. "Not validated here. Check `^[0-9a-f]{64}$` before using it as a path component."
- `Source`: where the artifact came from.
- `Metadata`: optional extra facts, checked by `Validate`. Values are constant text or redactor output, never raw scanned content or secrets. Read-only after ingest: scanners receive `Artifact` by value, but the map is shared, so they must not modify it.
- `SourceMetadata.Type`: one of `file`, `directory`, `archive`, `git`, `download` (typed constants come in the ingest story).
- `SourceMetadata.URI`: "Ingest stores only scheme, host and path. It drops userinfo, query and fragment and never stores the URL the user typed."

`metadata.go`: shared metadata check, used by `Artifact.Validate` and `Finding.Validate`.

```go
const (
    MaxMetadataEntries    = 32
    MaxMetadataKeyBytes   = 64
    MaxMetadataValueBytes = 256
)

var ErrInvalidMetadata = errors.New("invalid metadata")
var ErrInvalidArtifact = errors.New("invalid artifact")

// ValidateMetadata reports whether m is nil or holds at most MaxMetadataEntries
// bounded scalar values. Errors name counts, lengths and types, never keys or values.
func ValidateMetadata(m map[string]any) error

func (a Artifact) Validate() error
```

- Check order: entry count first; then, per entry, the key (length, UTF-8), then the value type, then string length and UTF-8. Map iteration order is random, so when several entries are bad, which one is reported can vary. The error never names the key, so this doesn't matter. Tests assert on `errors.Is` plus a substring of the error message, never on which entry is reported.
- The value check is a plain type switch over `string`, `bool`, `int`, `int64` and `float64`, with `default` rejecting and reporting `value has unsupported kind <reflect.Kind>` (`nil` for a nil value). A type switch doesn't match named types, nil values, `[]byte`, slices, maps or pointers, so they all fall to `default`. There's no recursion, so a self-referencing map is rejected as `map[string]interface {}`.
- Error format: `artifact: metadata: <reason>: %w` around `ErrInvalidMetadata`. `Artifact.Validate` wraps again as `artifact: invalid artifact: %w` (using `fmt.Errorf` with two `%w` verbs, or wrapping in sequence, so `errors.Is` works for both sentinels).
- **Why it's exported from `artifact`.** Both `Artifact` and `Finding` need the same check, and an unexported helper can't be shared across packages. `finding` importing `artifact` follows the natural direction, since findings describe artifacts. It avoids a third package and keeps the architecture doc change to one line. `artifact` stays a leaf with no internal imports.

### 3.2 `internal/finding/severity.go`

```go
type Severity int

const (
    SeverityInvalid Severity = iota // zero value: unset or unknown, never a real severity
    SeverityInfo
    SeverityLow
    SeverityMedium
    SeverityHigh
    SeverityCritical
)

var ErrInvalidSeverity = errors.New("invalid severity")

func (s Severity) Valid() bool { return s >= SeverityInfo && s <= SeverityCritical }

// rank maps every invalid value above SeverityCritical.
func (s Severity) rank() int {
    if !s.Valid() {
        return int(SeverityCritical) + 1
    }
    return int(s)
}

// Compare orders severities for sorting; invalid sorts highest.
// It is not a threshold check: an invalid threshold compares above every valid
// severity. Use AtMost or AtLeast for allow/deny decisions.
func (s Severity) Compare(other Severity) int { return cmp.Compare(s.rank(), other.rank()) }

// AtMost reports s <= limit. False if either side is invalid (use for "allow up to").
func (s Severity) AtMost(limit Severity) bool { return s.Valid() && limit.Valid() && s <= limit }

// AtLeast reports s >= limit. True if either side is invalid (use for "block/review at or above").
func (s Severity) AtLeast(limit Severity) bool { return !s.Valid() || !limit.Valid() || s >= limit }

func (s Severity) String() string // switch; default "invalid"

// ParseSeverity parses a severity name from trusted configuration or CLI flags.
// Never call it on scanned content.
func ParseSeverity(s string) (Severity, error)
```

- **`ParseSeverity` steps:**
  1. `t := strings.Trim(s, " \t\n\r\v\f")`
  2. `len(t) > 64` → error
  3. any byte of `t` `>= 0x80` → error. This runs before lowercasing, so Unicode case folding can't turn `"HİGH"` or Kelvin-sign tricks into a name.
  4. `strings.ToLower(t)` (ASCII only by now), then a switch over the five names

  `"invalid"` is deliberately not accepted.
- The error wraps `ErrInvalidSeverity`: `fmt.Errorf("finding: %w %s", ErrInvalidSeverity, quoteBounded(s))`. `quoteBounded` takes the first 32 bytes of the raw input, applies `strconv.Quote` and appends `...` if truncated. Cutting a UTF-8 sequence is safe because `strconv.Quote` escapes the partial bytes.
- The five names are string constants shared by `String` and `ParseSeverity`. A test checks `ParseSeverity(s.String()) == s` for every valid `s`.
- The parser is named `ParseSeverity`, not `Parse`, because `finding.Parse` would read as "parse a finding".
- `cmp.Compare` has been in the standard library since Go 1.21; the module is on Go 1.27.2.

### 3.3 `internal/finding/finding.go`

```go
// MaxEvidenceBytes is the largest Evidence that Validate accepts.
const MaxEvidenceBytes = 256

var ErrInvalidFinding = errors.New("invalid finding")

type Finding struct { /* architecture section 6, field docs below */ }

func (f Finding) Validate() error
```

**Package doc (contract):**

- **Redacted-or-bounded.** `ID`, `Category`, `Title`, `Description`, `Evidence` and `Metadata` values are constant text chosen by the detector or output of `internal/redactor`, never raw scanned content or secrets. `Evidence` is a short excerpt of at most `MaxEvidenceBytes` bytes and valid UTF-8. Detectors redact and shorten before building the finding, and `Validate` never truncates, because truncating a secret doesn't remove it.
- **Limits of `Validate`.** `Validate` cannot detect secrets. It rejects only mistakes it can see: an invalid severity, oversize or non-UTF-8 evidence, and metadata that breaks `artifact.ValidateMetadata`. The detector is responsible for redaction. `Title`, `Description`, `Category` and `ID` follow the contract but aren't checked in this story.
- **Thresholds.** Use `AtMost` and `AtLeast` for allow and deny decisions, never `Compare` or raw `<`. Callers must call `Validate` on every finding and treat an error as block or error, never allow.
- **No reflection formatting.** Never format a `Finding` with `%v`, `%+v`, `slog` attributes or JSON into errors or logs. Log `ID` and `Severity.String()` only.
- **Output escaping.** Strings may contain terminal control and bidi characters; output code must escape them.

**Field doc comments:**

- `ID`, `Category`, `Title`, `Description`: constant or redactor output, per the package contract.
- `File`: "Untrusted. Display only. Never join to a directory or pass to a filesystem call. Output code must escape it."
- `Evidence`: the redacted-or-bounded rule and `MaxEvidenceBytes`.
- `Metadata`: same rule as `Evidence`; checked by `artifact.ValidateMetadata`.
- `ArtifactID`: `Artifact.ID`.
- `Line`: 1-based, or 0 when unknown.

**`Validate` order and errors** are as in FR12. Message format: `fmt.Errorf("finding: %w: <reason>", ErrInvalidFinding)`. For metadata, the message wraps the `ValidateMetadata` error, so `errors.Is` matches both `ErrInvalidFinding` and `ErrInvalidMetadata`.

### 3.4 Dependencies between packages

```
internal/artifact   (no internal imports)
internal/finding    -> internal/artifact (ValidateMetadata and its limits only)
```

Future `scanner`, `policy`, `report` and `redactor` code imports these, and neither package imports them back.

## 4. Data/API changes and migrations

- **New exported API only.**
  - `artifact`: `Artifact`, `SourceMetadata`, `Artifact.Validate`, `ValidateMetadata`, `MaxMetadataEntries`, `MaxMetadataKeyBytes`, `MaxMetadataValueBytes`, `ErrInvalidArtifact`, `ErrInvalidMetadata`.
  - `finding`: `Finding`, `Severity` and its six constants, `Severity.Valid`, `String`, `Compare`, `AtMost` and `AtLeast`, `ParseSeverity`, `ErrInvalidSeverity`, `MaxEvidenceBytes`, `Finding.Validate`, `ErrInvalidFinding`.
- No persisted data, no wire format, no migrations. The integer values of `Severity` are not a stable external format; any future serialization uses the `String()` names.

## 5. Engineering decisions and rationale

| Decision | Rationale | Alternatives rejected |
| --- | --- | --- |
| `Finding` and `Severity` in a new `internal/finding` package (user decided, Q1). | Used by scanner, redact pipeline, policy and report. A small package with one job keeps policy independent of detection ("detection != policy"). | In `internal/artifact`: mixes findings into file models, and policy imports artifact for severities. In `internal/scanner`: policy and report would depend on scan code. |
| `type Severity int` with zero = `SeverityInvalid` (user decided, Q2). | A forgotten severity is detectable instead of silently becoming `info` and being allowed. | Zero = info: fails open. String type: needs a rank table, and invalid strings can be built directly. |
| `Compare` ranks every invalid value above `Critical` (user decided, Q4). | Sorting puts suspicious unknowns first, and an invalid finding severity can't sort below a valid threshold. | Invalid sorts lowest: fails open. |
| `AtMost`/`AtLeast` as the threshold API (security review F1). | `Compare` fails open when the threshold itself is invalid (a zero-valued config field). Checking both sides closes that. | Relying on `Compare` plus validating config: fails open whenever a caller forgets. |
| `Validate` rejects, never truncates; `MaxEvidenceBytes = 256` (user decided, Q3). | Truncation doesn't remove a secret, and rejecting makes the mistake visible. The bound limits how much scanned content can leak through evidence. | Documentation only: nothing checked. Calling the redactor from `finding`: couples to `internal/redactor` (being changed by REDACT-12), `Redact` can fail, and its labels are only consistent within one call. |
| Metadata limited to bounded scalars for both types (security review F2, user chose option (i)). | `map[string]any` could otherwise carry raw bytes, whole files or nested structures past the evidence bound. | Documentation only: an open side channel. Removing `Metadata`: deviates from the architecture. |
| `artifact.ValidateMetadata` exported and used by `finding`. | One implementation for both types without a third package or a second architecture doc line. | A copy in each package: the two copies drift. A new `internal/metadata` package: one more package and doc line for about 40 lines of code. |
| ASCII-only `ParseSeverity` with a 64-byte cap before lowercasing (security review I1). | Unicode case folding and Unicode whitespace can make different-looking strings parse as the same name. | `strings.TrimSpace` plus `strings.ToLower` on arbitrary input. |
| Errors contain only names, counts, lengths and Go type names. | Evidence and metadata may hold secrets if a detector misbehaves, and errors end up in logs. | Echoing values: leaks exactly what the checks exist to catch. |
| No ADR. | The decisions are local to two new packages, there's no persisted format and no callers yet. This spec and the section 4 line record them. | ADR now: revisit when the policy engine makes severities user configuration. |

## 6. Risks and failure modes

| Risk | Handling |
| --- | --- |
| A detector puts a short secret in `Evidence`, `Title`, `Description` or a metadata string. | Not detectable here. Covered by the documented contract; `security-reviewer` checks each detector. Accepted. |
| A caller skips `Validate`. | Oversize evidence and bad metadata go unnoticed, and nothing in these types prevents it. An invalid finding severity is still denied by `AtMost` and caught by `AtLeast`. The report and policy stories must call `Validate` on every finding (section 13). |
| A threshold is invalid or unset (zero-valued config). | `AtMost` returns false (deny) and `AtLeast` returns true (block or review). `Compare` alone would fail open, which its doc comment says. The policy story must also validate thresholds when config loads. |
| A caller uses `Compare` or raw `<` for thresholds. | Can fail open (an invalid threshold with `Compare`; an invalid value with raw `<`). The doc comments point to `AtMost`/`AtLeast`; policy review checks this. Accepted. |
| A scanner modifies the shared `Artifact.Metadata` map. | Documented as read-only after ingest. Not enforced, since a deep copy on every pass by value would be expensive and outside this story's scope. Accepted. |
| A `Finding` or `Artifact` is formatted with `%+v` into a log. | Covered by the package doc rule. Not enforced. Accepted; reviewers check it. |
| Severity constants are reordered later. | Tests pin the numeric values (FR3) and the full order (FR6, FR7). |
| `RelativePath`, `Name`, `File` or `SHA256` used in filesystem calls. | Covered by doc comments; enforcement belongs to the ingest, scanner and quarantine stories. |
| Merge conflict with REDACT-12. | Only new packages plus one line in `docs/architecture.md`, which REDACT-12 doesn't edit. |

## 7. Security

The `security-reviewer` design review returned CHANGES REQUIRED, and all of its findings are folded in above. After implementation, `security-reviewer` reviews each PR.

- **Fail closed.**
  - The zero severity is invalid.
  - `AtMost` and `AtLeast` deny or flag when either side is invalid.
  - `Compare` ranks invalid values highest.
  - `ParseSeverity` accepts only the five ASCII names.
  - `Validate` rejects bad input and never fixes it up.
  - Metadata accepts only bounded scalars.
- **No disclosure.** Validation errors never contain evidence, metadata keys or metadata values. `ParseSeverity` errors contain at most 32 escaped bytes of trusted config input.
- **Untrusted content.** The doc comments mark `Path`, `RelativePath`, `Name`, `File`, `SHA256` and `URI` with their handling rules, and require output code to escape strings (a follow-up).
- **No panics** on any `Severity` value, any evidence bytes or any metadata shape, including a self-referencing map.
- **CI.** No workflow or credential changes.

## 8. Performance/scalability

Constant-time severity methods. `Finding.Validate` costs O(len(Evidence)) plus O(metadata), and both are capped (256 bytes; at most 32 entries × (64 + 256) bytes). The UTF-8 scans run only after the length checks pass. Nothing here is measurable.

## 9. Implementation steps

Estimated size: about 600 changed lines (code with doc comments about 270, tests about 330, docs 1 line). That is above the 500-line threshold, so the work is split into **two stacked PRs**. PR 2 branches from PR 1.

**PR 1: `internal/finding` severity** (about 260 lines: code about 100, tests about 160)

1. **`internal/finding/severity.go`** with a temporary package doc that states the threshold rule and `ParseSeverity`'s trusted-only rule; `severity_test.go`. No dependencies. Expected result: FR3-FR9 pass. Tests: section 10, severity list.
2. **`docs/architecture.md` section 4 line** (FR15). Run `task verify`.

**PR 2: Artifact, metadata and Finding** (about 340 lines: code about 170, tests about 170). Depends on PR 1.

3. **`internal/artifact/artifact.go` and `metadata.go`**, plus `metadata_test.go` and `artifact_test.go`. Expected result: FR1, FR10, FR11, and the FR13 metadata part pass. Tests: section 10, metadata and artifact lists.
4. **`internal/finding/finding.go`**, the full package doc, and `finding_test.go` (depends on 3). Expected result: FR2, FR12-FR14 pass. Tests: section 10, finding list.
5. Run `task verify`.

If PR 2 comes in over 500 lines, move step 3 into its own PR (artifact plus metadata), leaving `Finding` for a third PR.

## 10. Testing strategy

Table-driven unit tests with `t.Parallel()`, standard library only, following `.agents/skills/test-writing/SKILL.md`. No realistic secrets: secret-shaped values are built at runtime (for example a prefix assembled from parts plus `strings.Repeat("A", 40)`).

**Severity (`severity_test.go`):**

- Constants: numeric values 0..5 (FR3); `Finding{}.Severity == SeverityInvalid` lives in `finding_test.go` (PR 2).
- `Valid`: 1..5 true; 0, -1, 6, 99, `math.MinInt`, `math.MaxInt` false.
- `String`: the five names; `"invalid"` for every invalid value above. Round trip `ParseSeverity(s.String()) == s` for valid `s`.
- `Compare`:
  - All 25 valid pairs follow numeric order.
  - Each invalid value in {0, -1, 99} against each valid value, in both argument orders, gives +1 and -1.
  - Every pair from {0, -1, 99}, including a value with itself, gives 0.
  - `SeverityCritical.Compare(SeverityInvalid) == -1`.
- `AtMost` / `AtLeast`:
  - All 25 valid pairs match numeric `<=` and `>=`.
  - `SeverityCritical.AtMost(SeverityInvalid) == false` and `SeverityInfo.AtLeast(SeverityInvalid) == true`.
  - For each invalid `s` in {0, -1, 99} and each `t` in all valid values plus {0, -1, 99}: `s.AtMost(t) == false` and `s.AtLeast(t) == true`.
  - For each valid `s` and invalid `t`: `s.AtMost(t) == false` and `s.AtLeast(t) == true`.
- `ParseSeverity` accepted: each name in lower, upper and mixed case, and with ASCII spaces, tabs and newlines around it (including `" high"`).
- `ParseSeverity` rejected: the full FR8 list, each returning `SeverityInvalid` and matching `ErrInvalidSeverity`.
- Bounded errors: a 10 KiB input gives an error under 100 bytes ending in `...`; an ESC byte in the input is escaped in the error.

**Metadata (`metadata_test.go`):**

- Accepted: nil, empty, and one value of each allowed type; 32 entries; a 64-byte key; a 256-byte string value.
- Rejected, each matching `ErrInvalidMetadata`:
  - 33 entries; an empty key; a 65-byte key; a non-UTF-8 key
  - a 257-byte string; a non-UTF-8 string
  - values of type `[]byte`, `map[string]any`, `[]any`, `[]string`, `*string`, `struct{}`, named `type S string`, `error`, untyped `nil`, `int32`, `uint`, `float32`
  - a map that contains itself (`m["self"] = m`), rejected with no recursion or hang
- No echo: secret-shaped keys and values (oversize, non-UTF-8, and of an unsupported type) never appear as an 8-byte substring of the error.

**Artifact (`artifact_test.go`):** a zero `Artifact{}` is valid; bad metadata gives an error matching both `ErrInvalidArtifact` and `ErrInvalidMetadata`.

**Finding (`finding_test.go`):**

- A valid baseline with `SeverityLow`, empty evidence and nil metadata returns nil.
- `Finding{}` and `Severity: 99` give `invalid severity`.
- Evidence: 256 bytes passes, 257 bytes gives `evidence is 257 bytes, max 256`, and 256 bytes of multi-byte runes passes. `"ok\xff"` gives `not valid UTF-8`.
- Bad metadata matches both `ErrInvalidFinding` and `ErrInvalidMetadata`.
- Order: an invalid severity plus oversize evidence plus bad metadata reports severity; valid severity plus oversize evidence plus bad metadata reports evidence.
- No echo: covers evidence and metadata, as in FR13.
- No mutation: the finding, including its metadata map, is unchanged after `Validate`.

## 11. Observability, deployment, rollback

No runtime behavior, logs or metrics; nothing calls these types yet. Deployment is the merge, and rollback is reverting the PRs. No data depends on them.

## 12. Definition of done

- FR1-FR15 met. `task test` and `task verify` (fmt, lint, test, cross, security, secrets) succeed on each PR.
- No changes to `internal/redactor`, `internal/safefs`, `docs/threat-model.md` or ADRs.
- `docs/architecture.md` section 4 line added.
- Each PR uses `.github/pull_request_template.md`, links this spec and states "no new dependency".
- `staff-engineering-reviewer` reports PASS or PASS WITH ADVISORIES, and `security-reviewer` reports PASS, on each PR.

## 13. Follow-ups (out of scope; rules from the security design review)

- **Policy story:**
  - Use `AtMost`/`AtLeast` (or `Valid()` on both sides) for every threshold. Never compare raw ints or use `Compare` for allow/deny.
  - Validate every threshold when config loads, and refuse to start if any is missing or invalid.
  - Call `Finding.Validate` on every finding. An invalid finding leads to block or error, never allow.
  - Never load policy from scanned content.
  - Record an ADR when severities become user configuration.
- **Report / MCP stories:**
  - Call `Validate` on every finding and fail closed.
  - Escape C0, C1, ESC and bidi control characters in `Evidence`, `Title`, `Description`, `File`, `RelativePath`, `Name` and `URI`.
  - Output `Metadata` only for allowlisted keys.
  - Never format findings or artifacts with reflection (`%v`, `%+v`, `slog`, JSON) into logs or errors.
- **Ingest story:**
  - Reduce `URI` to scheme, host and path.
  - Add typed `Source.Type` constants.
  - Treat `Metadata` as read-only once set.
  - Set `Path` only from locations that `safefs` has checked.
- **Quarantine story:** never use `RelativePath`, `Name` or `File` for filesystem operations, and check `SHA256` against `^[0-9a-f]{64}$` before using it as a file name.
- **Detector stories:** every `Evidence`, `Title`, `Description` and `Metadata` value is constant text or redactor output; `security-reviewer` checks this for each detector.

## PR 2 requirements from the security re-review

Fold these into PR 2 (all P3, from the second `security-reviewer` pass):

- `ValidateMetadata` reports `reflect.Kind` instead of `%T` (done in FR13 above). Extend the no-echo test with a `reflect.StructOf` value whose field tag is a runtime-built secret-shaped string.
- Metadata keys are covered by the redacted-or-constant contract: "keys and values are constant text or redactor output; keys should be fixed identifiers." Add the same to the detector follow-up.
- `ValidateMetadata` rejects `NaN` and `+/-Inf` for `float64` values (`encoding/json` cannot encode them; one bad value would break a whole JSON report). Add two test cases.
- `artifact` must never import `finding`. If an Artifact ever needs to carry findings, move `ValidateMetadata` into its own package.
- Write tests with escaped non-ASCII (`"\u00a0high"`), never literal look-alike bytes.
