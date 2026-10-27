# Scanner interface, registry and `scan <file>`: spec

Status: approved by the user (design review, interview questions 1-6), with all `security-reviewer` design requirements folded in (FR16-FR27).
Story: [REDACT-36](http://localhost:8080/issue/REDACT-36) "Scanner interface, registry and `scan <file>` for one file".
Branch: `feat/redact-36-scanner-scan-file` (PR 2 stacks on PR 1; see section 9).
Packages: new `internal/scanner` and `internal/scanner/scannertest`, plus changes to `internal/cli`. Go standard library only, no new dependency.
Depends on (merged): REDACT-35 (`internal/artifact`, `internal/finding`), REDACT-10 (`internal/safefs`), REDACT-2 (`internal/cli`).
Followed by: REDACT-39 (directory walking and `scan ./dir`, `internal/ingest`), REDACT-37 (hash and filetype scanners), REDACT-38 (report output), REDACT-50 (exit codes).
Decision record: [ADR 0004](../../adr/0004-scanner-contract-content-and-isolation.md).
Related: `docs/architecture.md` sections 2, 7 and 16, `docs/threat-model.md`, `AGENTS.md` security principles.

> Spec text and tests never contain realistic secret values. Tests build secret-shaped input at runtime.

## 1. Feature overview

**Purpose.** `redactscan scan FILE` runs every registered scanner over one file and prints their findings. The file is only read, never executed. The scan is fail-closed: anything that stops a scanner from running cleanly marks the scan incomplete and exits non-zero, while the findings from the scanners that did work are still shown.

**Concrete example.** With a registry holding two scanners, `script` and `filetype`, where `filetype` panics:

```text
$ redactscan scan ./install.sh
high "script-curl-pipe-sh" "./install.sh":12 "Remote script piped to shell"     (stdout)
redactscan: scan incomplete: filetype: panic                                    (stderr)
redactscan: scan incomplete: 1 findings                                         (stderr)
$ echo $?
1
```

This story ships no production scanners (REDACT-37 adds the first), so the production registry is empty. Until REDACT-37 lands, every real `scan FILE` prints `redactscan: scan incomplete: no scanner ran` and exits 1. That is deliberate: an empty registry must never look like a clean file.

**Scope.**

- `internal/scanner` has no file or network I/O:
  - the `Scanner` interface
  - the `Reason`, `Failure` and `Result` types
  - `MaxContentSize`, `MaxFindings`, `MaxIDBytes`, `MaxTitleBytes` and `MaxFileBytes`
  - `NewRegistry` (explicit and ordered), `Default`, and `(*Registry).Run`, which handles the cap, the context, per-scanner isolation, finding checks and the deterministic sort
  - the written scanner contract (package doc)
  - an import-allowlist test
- `internal/scanner/scannertest` holds `AssertNoMutation`, a shared test helper that future scanners must call in their tests.
- `internal/cli`:
  - the `scan` command
  - an unexported `readArtifact` helper that opens through `safefs.OpenRegular`, reads at most `MaxContentSize+1` bytes and builds the `Artifact`
  - output formatting and exit codes, both provisional
  - usage text
- Docs:
  - ADR 0004
  - `docs/architecture.md` section 7 signature and contract
  - a new Scanner section in `docs/threat-model.md`
  - the README `scan` usage line

**Non-goals.**

- Any real scanner (REDACT-37). Tests use fake scanners only.
- Directory or repository walking, a worker pool, or `scan ./dir` (REDACT-39). `scan` of a directory is refused with `not a regular file (directory)`.
- Anything in `internal/ingest`. REDACT-39 owns it and later moves `readArtifact` there.
- Any change to `internal/redactor`, which REDACT-16 is changing in parallel. This story only imports `redactor.Redact` and `redactor.KindLabelLike`.
- A report format, JSON output or report escaping beyond `strconv.Quote` (REDACT-38).
- A findings-present exit code, or policy and severity thresholds (REDACT-50 and the policy engine).
- Per-scanner timeouts, signal handling and concurrency.
- Stdin input for `scan`.
- Streaming or `io.ReaderAt` content. That is a planned later change (section 5, D1).

## 2. Functional requirements and acceptance criteria

The FR IDs are stable. FR16-FR27 are the security-review requirements (P2 and P3).

| ID | Requirement | Acceptance criteria and verification |
| --- | --- | --- |
| FR1 | `Scanner` interface. | `Name() string`, `Supports(a artifact.Artifact) bool`, `Scan(ctx context.Context, a artifact.Artifact, content []byte) ([]finding.Finding, error)`. The signature deviates from architecture section 7 by adding `content` (D1). Compile-time check in tests with a fake. |
| FR2 | Explicit ordered registry. | `NewRegistry(scanners ...Scanner) (*Registry, error)` keeps argument order. It returns an error wrapping `ErrInvalidRegistry` for: a nil interface value; a name not matching `^[a-z0-9][a-z0-9-]{0,31}$`; the reserved name `registry`; or a duplicate name. Error text names only the argument index (`scanner: invalid registry: scanner 2: duplicate name`), never the name. There is no package-level `Register` function and no `init` registration. Tested as a table. |
| FR3 | `Default()` | `Default() (*Registry, error)` returns the production registry, which is empty in this story. A test asserts `Default()` returns no error. |
| FR4 | Registry order and `Supports`. | `Run` visits scanners in registry order. A scanner whose `Supports(a)` returns false is skipped: no `Scan` call, no failure, and it does not count as ran. A test records call order with three fakes, the middle one unsupported. |
| FR5 | Size cap (decision Q2). | `MaxContentSize = 10 << 20` (10 MiB, an Assumed default, D3). If `len(content) > MaxContentSize`, `Run` calls no scanner and returns `Failures == [{registry, too large}]` with no findings. Tested at exactly `MaxContentSize` (scanners run) and at `MaxContentSize+1` (none run). |
| FR6 | Context. | `Run` checks `ctx.Err()` before each scanner. If it is set, that scanner and every later one gets `{name, canceled}` and none runs. A scanner that returns an error while `ctx.Err() != nil` gets `canceled` instead of `error`. Tested by canceling before `Run` and by canceling from inside the first of three scanners. |
| FR7 | Returned error isolated. | When `Scan` returns a non-nil error, all findings it returned in that call are discarded and `{name, error}` is recorded. Later scanners still run and their findings are kept. The error value is never stored, formatted or printed. A test uses an error whose text is a runtime-built canary and asserts the canary is absent from `Result` (via a field walk) and from CLI stdout and stderr. |
| FR8 | Invalid findings dropped one by one. | Each returned finding is first checked against the FR27 cap (once reached, the rest of that scanner's findings are skipped without further checks). Otherwise it is checked in this order: `Finding.Validate()`; `ArtifactID == a.ID`; the FR18 bounds; the FR17 redactor check. A failing finding is dropped and `{name, invalid finding}` is recorded at most once per scanner. The scanner's other valid findings are kept. Tested per rule. |
| FR9 | Deterministic sort. | `Result.Findings` is stable-sorted by: severity descending (`b.Severity.Compare(a.Severity)`), then `ArtifactID`, `File`, `Line`, `ID`, `Category`, `Title`, `Evidence`, each ascending by byte order. A test registers the same fakes in two different orders and gets identical output, then repeats 50 times to catch any map-order dependence. |
| FR10 | `Result` | `Result{Findings []finding.Finding; Failures []Failure; Ran int}`. `Incomplete()` is `len(Failures) > 0`. `Failure{Scanner string; Reason Reason}`. Failures appear in the order they were recorded. There is at most one failure per (scanner, reason) pair. |
| FR11 | Fixed reasons. | `Reason` is a string type with exactly these constants: `error`, `panic`, `invalid finding`, `canceled`, `too large`, `invalid artifact`, `no scanner`, `too many findings`. No other value is ever produced. |
| FR12 | `scan FILE` CLI. | `redactscan scan FILE` takes exactly one argument. These are usage errors, exiting 2: zero or two or more arguments, `-`, or an unknown flag. `-h` prints usage and exits 0. FILE is opened only through `safefs.OpenRegular` and never executed; there is no `os/exec` anywhere in `internal/cli` or `internal/scanner` (FR21). |
| FR13 | `readArtifact` helper. | It reads at most `scanner.MaxContentSize+1` bytes through `io.LimitReader` and builds `Artifact{ID: "file-1", Path: path, RelativePath: path, Name: filepath.Base(path), Size: int64(len(content)), Source: SourceMetadata{Type: "file"}}`. Open errors use the existing `openReason`: `cannot open "<path>": <reason>`, exit 3. A read error prints `cannot read "<path>": read failed`, exit 3. Tested for symlink, FIFO, directory and missing file (exit 3 with a fixed reason, and FIFO must not hang), and for the cap (a `MaxContentSize+1` file gives `too large` and exit 1). |
| FR14 | Output (decision Q5, provisional). | Stdout gets one line per finding in sorted order: `<severity> <id> <file>[:<line>] <title>`. Severity is `Severity.String()`. `id`, `file` and `title` are `strconv.Quote`d. `:<line>` appears only when `Line > 0`. All lines are built in a buffer and written with a single `Write`. Stderr gets one line per failure, then a summary line (FR16, FR26). A test uses a title, file and id containing ESC, CR, a bidi override and invalid UTF-8, and checks that only escaped forms appear. |
| FR15 | Exit codes (provisional until REDACT-50). | 0 when complete (any number of findings); 1 when incomplete; 2 for a usage error; 3 for an open or read error, or a stdout write error (FR26). Help text marks the output format and the codes as provisional. |
| FR16 | No scanner ran means incomplete (security, P2). | `Ran` counts scanners whose `Scan` returned without an error or panic. If `Ran == 0` after the loop, `Run` appends `{registry, no scanner}`. The CLI prints `redactscan: scan incomplete: no scanner ran` and exits 1. Tested with an empty registry, an all-unsupported registry and an all-failing registry, plus a CLI test with the real `Default()` exiting 1. |
| FR17 | Redactor check on printed fields (security, P2). | For each finding, `ID`, `Title`, `File` and `Evidence` are each passed to `redactor.Redact`. The finding is dropped as `invalid finding` if `Redact` returns an error, or if its `Counts` holds any kind other than `redactor.KindLabelLike`. Label-like text such as `[GITHUB_TOKEN_1]` from already-redacted evidence is accepted, because neutralising it is not a detection. Tested with runtime-built secret-shaped evidence (dropped), a runtime-built secret-shaped title (dropped), a runtime-built secret-shaped file name (dropped, also through the CLI), redactor-labelled evidence and file text (kept) and evidence with a NUL byte (dropped). See D6. |
| FR18 | Bounds on printed fields (security, P2). | A finding is invalid when: `len(ID)` is 0 or over `MaxIDBytes = 128`; `len(Title)` is over `MaxTitleBytes = 128`; `ID` or `Title` is not valid UTF-8; `len(File)` is over `MaxFileBytes = 4096`; or `Line < 0`. These bounds sit on top of `Finding.Validate()`, which already bounds evidence and metadata. Tested at each boundary and one past it. |
| FR19 | Printed fields allowlist (security, P2). | `scan` prints only severity, ID, File, Line and Title. Evidence, Description, Category, Metadata and ArtifactID are never printed. A CLI canary test has a fake scanner put a distinct runtime-built canary string into Evidence, Description, Category and each Metadata key and value, and asserts that no canary appears in stdout or stderr. |
| FR20 | Panic and Goexit isolation (security, P2). | Each `Supports` and `Scan` call runs in its own goroutine. `Run` waits for it before moving on, so execution stays sequential. A `completed` flag set after the call returns, plus `recover()` in a deferred function, turns any abnormal exit into `{name, panic}`: `panic(value)`, `panic(nil)` and `runtime.Goexit()`. A panic in `Supports` means `Scan` is not called. The panic value is discarded and never formatted. Tested with each of `panic("canary")`, `panic(nil)`, `runtime.Goexit()` (in both `Supports` and `Scan`), and with an error value as the panic argument. A following scanner still runs, and no canary appears in output. |
| FR21 | Import allowlist (security, P2). | A test in `internal/scanner` parses every non-test `.go` file in `internal/scanner` and its subdirectories (excluding `scannertest`) with `go/parser` (`ImportsOnly`). It fails on any import outside the allowlist: `cmp`, `context`, `errors`, `fmt`, `slices`, `sort`, `strings`, `unicode/utf8`, and the module paths `internal/artifact`, `internal/finding`, `internal/redactor`. The test also names the explicitly forbidden imports in its failure message: `os`, `os/exec`, `syscall`, `net` and `net/...`, `plugin`, `unsafe`, `log` and `log/...`, `internal/safefs`. Widening the allowlist takes a reviewed edit to this test. |
| FR22 | Written scanner contract (security, P2). | The package doc of `internal/scanner` states that scanners must: not call `os.Exit`, `log.Fatal` or `runtime.Goexit`; not start goroutines that outlive `Scan` or that can panic unrecovered; not modify `content` or `a.Metadata`; use only constant text in panics and errors (never scanned content); return only redacted-or-bounded findings per the `finding` package contract; check `ctx` in long loops; and never execute, load or open anything named by the content. It also states that `Run`'s isolation does not cover goroutines a scanner starts. |
| FR23 | Registry failures use a fixed name (security, P3). | Failures not tied to a scanner (`too large`, `invalid artifact`, `no scanner`) use `Failure.Scanner == RegistryName` (`"registry"`). `NewRegistry` reserves the name (FR2). The CLI prints them as `scan incomplete: file exceeds 10 MiB limit`, `scan incomplete: invalid artifact` and `scan incomplete: no scanner ran`. |
| FR24 | Artifact validated first (security, P3). | `Run` calls `a.Validate()` before anything else. On error it returns `[{registry, invalid artifact}]` and runs no scanner. Tested with invalid metadata. |
| FR25 | Name captured once (security, P3). | `NewRegistry` calls `Name()` exactly once per scanner, validates it and stores it. `Run` never calls `Name()`. Tested with a fake whose `Name()` returns a different (invalid) value on its second call and counts its calls. |
| FR26 | Stdout errors and precedence (security, P3). | Failure lines and the summary always print to stderr, whatever the stdout result. A failed or short stdout write prints `redactscan: cannot write output: write failed` and exits 3. Otherwise an incomplete scan exits 1, whether or not findings were printed. Summary: `redactscan: scan complete: N findings` (exit 0) or `redactscan: scan incomplete: N findings` (exit 1). Tested with a failing stdout writer, for both complete and incomplete scans. |
| FR27 | Findings cap (security, P3). | `MaxFindings = 1000` accepted findings per `Run` (per artifact). The cap is checked before any per-finding check: once it is reached, `{name, too many findings}` is recorded once for that scanner and the rest of its findings are skipped unexamined, so a flood costs no `Validate` or `Redact` work. Scanners still run in order. Tested at exactly 1000 (complete) and 1001 (incomplete, 1000 kept, the first 1000 in registry order). |
| FR28 | Shared no-mutation helper (security, P3). | `scannertest.AssertNoMutation(t testing.TB, s scanner.Scanner, a artifact.Artifact, content []byte)` copies `content` and `a.Metadata`, calls `s.Scan(context.Background(), a, content)`, and fails the test if either changed. Its package doc says every scanner's tests must call it. It is tested against a mutating fake (expected to fail, via a recording `testing.TB`) and a clean fake (passes). |
| FR29 | Docs. | ADR 0004 is added. `docs/architecture.md` section 7 shows the FR1 signature with a link to ADR 0004. `docs/threat-model.md` gains a "Scanner (`internal/scanner`, `scan` command)" section (section 7 below). The README gets a `scan` usage line that does not call any result "safe". |

## 3. Technical design

### 3.1 Layout

```text
internal/scanner/
  scanner.go              package doc (contract FR22), Scanner, Reason, Failure, Result, limits
  registry.go             NewRegistry, Default, ErrInvalidRegistry, RegistryName
  run.go                  Run, call (goroutine + completed flag), checkFinding, sortFindings
  scanner_test.go         registry, run, isolation, cap, sort, bounds, redactor check
  imports_test.go         FR21 allowlist
internal/scanner/scannertest/
  scannertest.go          AssertNoMutation
  scannertest_test.go
internal/cli/
  cli.go                  dispatch "scan", usage text
  scan.go                 runScan, readArtifact, formatting, exit codes, registry seam
  scan_test.go            CLI behavior with fake registries
  scan_unix_test.go       symlink, FIFO, directory (build tag like cli_unix_test.go)
docs/adr/0004-scanner-contract-content-and-isolation.md
docs/architecture.md, docs/threat-model.md, README.md
```

### 3.2 `internal/scanner` API

```go
const (
    MaxContentSize = 10 << 20 // Assumed default; see ADR 0004
    MaxFindings    = 1000
    MaxIDBytes     = 128
    MaxTitleBytes  = 128
    MaxFileBytes   = 4096
    RegistryName   = "registry"
)

type Scanner interface {
    Name() string
    Supports(a artifact.Artifact) bool
    Scan(ctx context.Context, a artifact.Artifact, content []byte) ([]finding.Finding, error)
}

type Reason string // constants per FR11

type Failure struct {
    Scanner string // registered name or RegistryName
    Reason  Reason
}

type Result struct {
    Findings []finding.Finding // validated, checked, sorted (FR9)
    Failures []Failure         // recorded order, one per (scanner, reason)
    Ran      int               // scanners whose Scan returned without error or panic
}

func (r Result) Incomplete() bool

var ErrInvalidRegistry = errors.New("scanner: invalid registry")

func NewRegistry(scanners ...Scanner) (*Registry, error)
func Default() (*Registry, error)
func (r *Registry) Run(ctx context.Context, a artifact.Artifact, content []byte) Result
```

`Registry` holds `[]entry{name string; s Scanner}` and is immutable after `NewRegistry`, so it is safe to share read-only across goroutines for REDACT-39. `Run` itself runs scanners sequentially.

### 3.3 `Run` algorithm

1. If `a.Validate()` fails, return `{Failures: [{registry, invalid artifact}]}`.
2. If `len(content) > MaxContentSize`, return `{Failures: [{registry, too large}]}`.
3. For each entry, in order:
   1. If `ctx.Err() != nil`, record `{name, canceled}` for this entry and all remaining entries, then stop the loop.
   2. Call `Supports(a)` through `call`. A panic or Goexit records `{name, panic}`; continue to the next entry. If it returns false, continue.
   3. Call `Scan(ctx, a, content)` through `call`. A panic or Goexit records `{name, panic}`; continue.
   4. If `err != nil`, discard the returned findings and record `canceled` if `ctx.Err() != nil`, else `error`; continue.
   5. Increment `Ran`. For each returned finding: if `len(accepted) == MaxFindings`, record `{name, too many findings}` and stop examining this scanner's findings; else if `checkFinding` fails, record `{name, invalid finding}` once; else append it.
4. If `Ran == 0`, append `{registry, no scanner}`.
5. `sortFindings(accepted)` (FR9). Return.

`call` (FR20):

```go
// call runs f on its own goroutine and waits. It reports false if f panicked
// (including panic(nil)) or called runtime.Goexit. The panic value is dropped.
func call(f func()) bool {
    done := make(chan bool, 1)
    go func() {
        completed := false
        defer func() {
            if !completed {
                _ = recover() // stop a panic; Goexit cannot be stopped but still runs this defer
            }
            done <- completed
        }()
        f()
        completed = true
    }()
    return <-done
}
```

The `completed` flag, rather than `recover() != nil`, is what makes this correct for `panic(nil)` under any `GODEBUG=panicnil` setting, and for `runtime.Goexit()`, where `recover()` returns nil. **Assumed** from the Go 1.21 release notes and the `runtime.Goexit` docs (Goexit runs deferred calls, and `recover` returns nil during it). FR20's tests verify this on the repo toolchain (Go 1.27.2).

`checkFinding(f, a) bool` (FR8, FR17, FR18) runs, in order:
- `f.Validate() == nil`
- `f.ArtifactID == a.ID`
- `1 <= len(f.ID) <= MaxIDBytes` and `len(f.Title) <= MaxTitleBytes`
- `utf8.ValidString(f.ID)` and `utf8.ValidString(f.Title)`
- `len(f.File) <= MaxFileBytes` and `f.Line >= 0`
- `redactorClean(f.ID)`, then `redactorClean(f.Title)`, then `redactorClean(f.File)`, then `redactorClean(f.Evidence)`

`redactorClean(s)` is true only when `redactor.Redact([]byte(s))` returns no error and every key in `Counts` is `KindLabelLike`. New kinds added by REDACT-16 are covered automatically, because the rule is "any kind but label-like".

### 3.4 CLI (`internal/cli/scan.go`)

- Seam: `var defaultRegistry = scanner.Default`. Tests replace it, following the same pattern as `writeSibling`.
- `runScan(args, stdout, stderr)`:
  1. Parse with a `flag.FlagSet`. Only `-h` and `-help` are accepted, and the only argument check is FR12.
  2. Call `readArtifact(path)` (FR13).
  3. Call `defaultRegistry()`. If it returns an error, print `redactscan: internal error: invalid scanner registry` and exit 1. This is unreachable in production because a unit test covers `Default()`.
  4. Call `reg.Run(context.Background(), a, content)`.
  5. Format stdout into a buffer (FR14), write it once, and remember any failure.
  6. Print failure lines and the summary to stderr (FR23, FR26).
  7. Exit: 3 if the stdout write failed, else 1 if incomplete, else 0.
- Failure line text: `redactscan: scan incomplete: <name>: <reason>` for scanner failures. Registry failures use the FR23 texts. Names are validated constants and reasons are constants, so no escaping is needed. They are still built only from `Failure` fields, never from error values.
- `readArtifact` is a small near-duplicate of the file branch of `readInput`. The cap differs and no `Stat` is needed. `readInput` is deliberately left as is, so `redact` behavior can't change. REDACT-39 replaces `readArtifact` with an ingest call.
- Usage text: a `redactscan scan FILE` line and a short paragraph. The paragraph says: files are read, not executed; 10 MiB limit; output format and exit codes are provisional; "no scanners are registered yet, so scans report incomplete until scanners are added". It never says "safe" or "clean".

## 4. Data/API changes and migrations

- New internal Go APIs only (section 3.2). No persisted data, wire format or config.
- CLI: a new `scan` subcommand. `redact` is unchanged. The stdout format and exit codes are explicitly provisional (REDACT-38 and REDACT-50 may change them).
- No migrations.

## 5. Engineering decisions and rationale

| ID | Decision | Why | Alternatives rejected | ADR |
| --- | --- | --- | --- | --- |
| D1 | **Content is passed as `[]byte`, read once by the caller** (user decision Q1). This deviates from architecture section 7, which has no content parameter. | One open, one cap check and one consistent snapshot for every scanner, so a file swapped between scanners can't be seen. File I/O stays out of scanners. It matches the redact read pattern. | Each scanner opens `a.Path` itself (N opens, TOCTOU, the safefs rule repeated in N places); a bounded `io.ReaderAt` now (more moving parts before a need exists). | 0004 |
| D1a | **Planned later migration to a bounded `io.ReaderAt`.** When a story needs files larger than a memory-friendly cap (for example archives, or hashing large binaries in REDACT-37 or later), change the parameter to `io.ReaderAt` plus a size: an `*io.SectionReader` over the file opened once by the caller, limited to the cap. | It keeps the one-open rule and removes the full read into memory. `[]byte` callers convert with `bytes.NewReader`. The change is contained to the interface, `Run` and each scanner's first read. | Streaming `io.Reader` (each scanner needs its own pass, so this would mean re-opening or buffering). | 0004 |
| D2 | **An over-cap file means incomplete, with no scanners run** (Q2). | It is as fail-closed as refusing, avoids partial-content correctness bugs (for example a wrong hash), and reuses the single incomplete outcome. | Refuse with a separate error path; scan a truncated prefix. | 0004 |
| D3 | **`MaxContentSize` is 10 MiB.** | It matches `redactor.MaxInputSize` and keeps memory per file in flight bounded. **Assumed** suitable; revisit with REDACT-39's measurements on real repositories. It is a separate constant, so the scanner and redactor caps can change independently. | 64 MiB, or configurable (no requirement yet). | - |
| D4 | **The read helper is unexported in `internal/cli`** (Q3). `internal/scanner` stays I/O-free. | No acquisition logic in the scanner (architecture section 4), no overlap with REDACT-39's `internal/ingest`, and pure unit tests. | `scanner.ScanFile(path)`; waiting for `ingest.File`. | - |
| D5 | **Broad failure isolation, with a goroutine per call plus a `completed` flag** (Q4, FR20). | A scanner bug must not kill a REDACT-39 directory scan or hide other findings. `panic(nil)` and `Goexit` are handled. Sequential waiting means no leaks and no concurrency. | No recovery (crash); `recover() != nil` only (misses `panic(nil)` with `panicnil=1`, and Goexit). | 0004 |
| D6 | **`internal/scanner` imports `internal/redactor` to check printed fields** (FR17). | It is defense in depth against a scanner that forgets to redact: the fields that reach the terminal are checked by the same covered-format detector. The dependency points the right way (`redactor` imports nothing internal). The cost is four `Redact` calls (ID, Title, File and Evidence; File up to 4096 bytes) per accepted finding, for at most 1000 accepted findings. | Contract only (the gap the security review flagged); a separate verifier in `scanner` (duplicated knowledge). Limitation: only covered formats are detected (threat model). | 0004 |
| D7 | **Explicit registry built by `NewRegistry`; no global `Register` and no `init`** (planner recommendation, confirmed). | No hidden init-order state, test registries are trivial, and the production list is visible in one function. | `init()`-time registration into a package map. | 0004 |
| D8 | **`ArtifactID` mismatch is an invalid finding** (confirmed). | A finding about another artifact is a scanner bug, and dropping it keeps reports attributable. | Overwrite `ArtifactID` (hides the bug). | - |
| D9 | **The CLI uses `context.Background()`** (confirmed). | There is no requirement yet for Ctrl-C or deadlines; cancellation is tested at the `Run` level. | `signal.NotifyContext` (REDACT-39 can add it along with the worker pool). | - |
| D10 | **Sort key: severity descending, then ArtifactID, File, Line, ID, Category, Title, Evidence** (confirmed). | Most severe first, then a total order over every printed or identifying field, so the result doesn't depend on registry order. | Registry order (not deterministic once scanners are reordered). | - |
| D11 | **Provisional output and exit codes: 0 complete, 1 incomplete, 2 usage, 3 I/O** (Q5). | It makes "incomplete" observable to scripts now (fail closed) and is consistent with `redact`. REDACT-38 and REDACT-50 own the final form. | Exit 0 when incomplete (fail open); JSON now (front-runs REDACT-38). | - |

ADR 0004 records D1, D1a, D2, D5, D6 and D7, because they shape every future scanner.

## 6. Risks and failure modes

| Risk | Handling |
| --- | --- |
| Scanner returns an error, panics, calls Goexit or emits a bad finding | Isolated per FR7, FR8 and FR20; the scan is incomplete and exits 1. |
| Scanner starts its own goroutine, which panics | Not recoverable by `Run`: the process crashes with Go's exit status 2, the same as a usage error. **Assumed** from the Go runtime's documented behavior. Forbidden by the FR22 contract and recorded in the threat model. |
| Scanner calls `os.Exit` or `log.Fatal` | Forbidden by FR22. `os` and `log` are also blocked by the FR21 import allowlist for code inside `internal/scanner`. |
| Scanner hangs | No per-scanner timeout (accepted risk). `Run` blocks; the user interrupts with Ctrl-C. REDACT-39 may add deadlines with the worker pool. |
| Scanner mutates `content` or `a.Metadata` | Contract (FR22) plus `scannertest.AssertNoMutation` in each scanner's tests (FR28). Not enforced at runtime (accepted risk: copying per scanner costs up to 10 MiB each). |
| File changes after open | One read gives one snapshot. A file modified in place during the read can yield mixed content; that is accepted and matches the `redact` and safefs threat model. |
| Empty production registry | Exit 1 with `no scanner ran` (FR16) until REDACT-37. That is intentional, and documented in the usage text and README. |
| Findings flood | Capped at 1000 (FR27); stdout is bounded by about 1000 × (128 + 128 + 4096 quoted bytes). |
| A legitimate finding dropped by the redactor check | For example, a title that names a token shape. Detectors must use labels or constant text. The drop is visible as `invalid finding` and is fail-closed. |
| Over-cap file | Incomplete, exit 1, no scanner run (FR5). |
| A future scanner needs a forbidden import | The FR21 test fails, and widening the allowlist needs a reviewed edit with a reason. |

## 7. Security

New threat model section: "Scanner (`internal/scanner`, `scan` command)".

- **Trust boundary.** Scanned content is untrusted, and so is scanner output, because it is derived from that content. The terminal and later report consumers are less trusted.
- **Never executed.** The CLI only reads, through `safefs.OpenRegular`, so symlinks in any path component, FIFOs, devices and directories are refused (ADR 0002). No `os/exec` is used anywhere in `internal/scanner` (FR21) or `internal/cli`.
- **Bounded input.** At most `MaxContentSize+1` bytes are read; an over-cap file means incomplete, not truncated (FR5).
- **Fail closed.** Every abnormal scanner outcome, an empty or all-unsupported registry, an invalid artifact or the findings cap means incomplete, exit 1 (FR6-FR8, FR16, FR20, FR24, FR27).
- **No content in messages.** Error and panic values are never stored or printed (FR7, FR20). Failure lines use only validated names and constant reasons (FR23).
- **Output minimisation and checks.** Only severity, ID, File, Line and Title are printed (FR19). ID, Title, File and Evidence must pass the redactor check (FR17), with length and UTF-8 bounds (FR18). ID, File and Title are `strconv.Quote`d (FR14), so control and bidi characters appear escaped. **Assumed**: `strconv.Quote` escapes every non-printable rune and invalid UTF-8 byte, per the Go docs; FR14's test verifies it for ESC, CR, U+202E and `\xff`.
- **Accepted risks.**
  - no per-scanner timeout
  - shared read-only `content` and `a.Metadata`, by contract only
  - no exit code for "findings present" until REDACT-50 (a complete scan with high-severity findings exits 0)
  - an unrecovered crash from a scanner-spawned goroutine exits 2, the same as a usage error
  - the redactor check covers only the redactor's covered formats
  - a mid-read in-place modification can yield mixed content
  - invalid-finding floods are not capped: only accepted findings count toward `MaxFindings`, so a scanner returning many invalid findings costs about 1.7 s per million secret-shaped ones (measured); deferred to REDACT-37 or REDACT-39

## 8. Performance/scalability

- Memory: one copy of content (at most 10 MiB plus 1 byte) per `Run`, plus findings (at most 1000). REDACT-39's worker pool bounds files in flight.
- CPU: two goroutine spawns per scanner (microseconds), plus four `Redact` calls per accepted finding (at most 4000 per file; File up to 4096 bytes). That is negligible next to scanning 10 MiB.
- Sorting: O(n log n) with n ≤ 1000.
- `Registry` is immutable, so REDACT-39 can share one registry across workers without locks, as long as scanners themselves are concurrency-safe (to be added to the contract when REDACT-39 introduces concurrency).

## 9. Implementation steps

The work is two stacked PRs. PR 1 is `internal/scanner` with tests (about 450-500 changed lines). PR 2 stacks on PR 1 and holds the CLI, docs and ADR (about 300 lines including docs). If PR 1 goes over about 500 lines, split the hardening (steps 4-6) into PR 1b, stacked between them.

| Step | PR | Work | Depends on | Expected result | Required tests |
| --- | --- | --- | --- | --- | --- |
| 1 | 1 | `scanner.go`: package doc with the FR22 contract; `Scanner`, `Reason` constants, `Failure`, `Result`, `Incomplete`, limits. | - | Compiles; `go vet` is clean. | Compile-time fake check. |
| 2 | 1 | `registry.go`: `NewRegistry`, `Default`, `ErrInvalidRegistry`, `RegistryName`; name rule; one `Name()` call each. | 1 | FR2, FR3, FR25. | Validation table; order; Name call count; `Default()` returns no error. |
| 3 | 1 | `run.go` core: `call`; validate artifact; cap; loop with ctx, `Supports`, `Scan`, error handling; `Ran` and `no scanner`; sort. Initially `checkFinding` is only `Validate` plus the ArtifactID check. | 2 | FR4-FR11, FR16, FR20, FR23, FR24. | Order and skip; cap boundary; ctx before and during; error canary; panic, `panic(nil)`, Goexit and error-valued panic in `Supports` and `Scan`; empty, all-unsupported and all-failing registries; invalid artifact; sort determinism (two orders, 50 repeats). |
| 4 | 1 | `checkFinding` bounds (FR18) and the redactor check (FR17). | 3 | Bad findings dropped one by one. | Each bound at limit and limit+1; runtime-built secret-shaped ID, Title, File and Evidence dropped; label-like evidence and File kept; NUL dropped; valid siblings kept. |
| 5 | 1 | Findings cap (FR27). | 3 | 1000 kept, failure recorded. | 1000 vs 1001; kept set is the first in registry order; once per scanner. |
| 6 | 1 | `imports_test.go` (FR21) and `scannertest` (FR28). | 1 | The allowlist is enforced; the helper is usable by REDACT-37. | The allowlist passes on the package; a deliberately bad import in a temporary copy fails (unit test of the checker function on an in-memory source); helper against mutating and clean fakes. |
| 7 | 1 | Run `task verify`. | 1-6 | Green. | - |
| 8 | 2 | `internal/cli/scan.go`: `runScan`, `readArtifact`, formatting, exit codes, `defaultRegistry` seam; dispatch in `cli.go`; usage text. | PR 1 | FR12-FR15, FR19, FR23, FR26. | Usage errors; help; missing file; cap+1 gives exit 1 `file exceeds 10 MiB limit`; incomplete exit 1 with findings printed; complete exit 0; real `Default()` gives exit 1 `no scanner ran`; quoted control characters; canary not printed for Evidence, Description, Category, Metadata and error text; failing stdout gives exit 3 with stderr lines still printed. |
| 9 | 2 | `scan_unix_test.go`: symlink (final and parent component), FIFO (no hang), directory, using the build tags of `cli_unix_test.go`. | 8 | Exit 3 with a fixed reason. | As listed. |
| 10 | 2 | Docs: ADR 0004 (finalise the status), architecture section 7, the threat-model Scanner section, the README `scan` line. | 8 | FR29. | Review only. |
| 11 | 2 | Run `task verify`; run the manual checks in section 10. | 8-10 | Green. | - |

## 10. Testing strategy

- **Unit (`internal/scanner`).** Table-driven tests with small fake scanners, configured through fields (name, supports, findings, err, panic mode, a hook for mutating `content` or calling cancel). Secret-shaped values and canaries are built at runtime (for example `"gh" + "p_" + strings.Repeat("A", 36)`), never as literals. Canary absence is checked with `strings.Contains` against every string field of the `Result` and against CLI output.
- **Regression and fail-closed.** Every FR that marks a scan incomplete has a test asserting both the failure entry and that the other scanners' findings survive.
- **Determinism.** Two registration orders give identical findings; 50 repeated runs are compared.
- **Isolation semantics.** `panic(nil)` and `runtime.Goexit` tests confirm the Assumed runtime behavior on the repo toolchain.
- **Imports.** The FR21 test.
- **CLI.** Tests replace `defaultRegistry` and call `cli.Run` with buffers. Unix-only tests cover symlink, FIFO and directory. A test keeps `redact` unchanged (the existing suite passes untouched).
- **Race.** `go test -race ./internal/scanner/...` passes; `call` uses only a channel.
- **Manual (PR 2), for the PR description.**
  - `go run ./cmd/redactscan scan README.md` shows stderr `redactscan: scan incomplete: no scanner ran`, `redactscan: scan incomplete: 0 findings`, exit 1.
  - `scan` of a symlink shows `cannot open "<path>": symlink refused`, exit 3.
  - `scan .` shows `not a regular file (directory)`, exit 3.
  - `scan` of a FIFO (`mkfifo`) returns immediately with exit 3.
  - A sparse file of 10 MiB + 1 shows `scan incomplete: file exceeds 10 MiB limit`, exit 1.
  - `scan` with no argument, or with `-`, shows usage, exit 2.

## 11. Observability, deployment, rollback

- Observability: stderr failure lines and the summary only. No logs, metrics or traces (a local CLI).
- Deployment: ships with the binary. `redact` is unaffected.
- Rollback: revert PR 2 to remove the command; PR 1 alone has no callers.

## 12. Definition of done

- FR1-FR29 implemented, with the tests listed in sections 9 and 10.
- `task test` passes during development, and `task verify` (fmt, lint, test, cross, security, secrets) passes before each PR is marked ready.
- ADR 0004 is accepted; `docs/architecture.md` section 7, `docs/threat-model.md` and the README are updated.
- `staff-engineering-reviewer` and `security-reviewer` both PASS. This story touches scanned-content handling, file opening and output of untrusted data.
- PR descriptions follow `.github/pull_request_template.md`, with manual steps from section 10, the accepted risks from section 7, and no secrets or unredacted data.
