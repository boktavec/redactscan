# Sentinel Architecture Design

## 1. Purpose

Sentinel is a local-first developer security gateway written primarily in Go.

It protects two boundaries:

1. **Inbound trust** — scan untrusted repositories, files, folders, archives, and downloads before they enter the trusted developer workspace.
2. **Outbound data safety** — redact sensitive data from logs/files before sharing them with AI systems or external tools.

Later versions add an MCP interface that exposes only sanitized debugging data to AI agents.

---

## 2. Design Principles

- **Local-first:** core scanning and redaction happen locally.
- **Static analysis first:** unknown content is treated as data, not executed.
- **Untrusted until approved:** downloaded or fetched artifacts remain outside trusted directories until policy allows them.
- **Fail closed:** if scanning/redaction fails at a security boundary, do not release raw/unsafe data.
- **Explainable findings:** return evidence and reasoning, not only a risk score.
- **Detection != policy:** scanners report findings; the policy engine decides allow/review/block.
- **Modular:** acquisition, parsing, scanning, redaction, policy, reporting, and integrations remain separate.
- **Shared core:** CLI, watcher, Git workflows, and MCP all reuse the same engine.

---

## 3. High-Level Architecture

```text
                    +------------------+
                    |   Entry Points   |
                    | CLI / Watch / MCP|
                    +--------+---------+
                             |
                             v
                    +------------------+
                    |      Ingest      |
                    +--------+---------+
                             |
                             v
                    +------------------+
                    | Artifact Model   |
                    +--------+---------+
                             |
              +--------------+--------------+
              |                             |
              v                             v
      +---------------+             +---------------+
      | Scan Pipeline |             |Redact Pipeline|
      +-------+-------+             +-------+-------+
              |                             |
              +--------------+--------------+
                             |
                             v
                    +------------------+
                    | Findings / Meta  |
                    +--------+---------+
                             |
                             v
                    +------------------+
                    |  Policy Engine   |
                    +--------+---------+
                             |
                   +---------+---------+
                   |         |         |
                 Allow     Review     Block
```

---

## 4. Core Packages

Recommended Go layout:

```text
cmd/sentinel/              CLI entrypoint

internal/
  artifact/                shared artifact/file models
  ingest/                  files, directories, archives, URLs, Git
  scanner/                 scan orchestration + detectors
  parser/                  structured file/project parsers
  policy/                  allow/review/block decisions
  report/                  terminal/JSON reports
  quarantine/              store/release/delete artifacts
  watcher/                 incoming download directory watcher
  sandbox/                 isolated scanner workers
  redactor/                sensitive-data detection/transformation
  logs/                    log source adapters/buffering
  mcp/                     MCP server (V3)
  config/                  config loading/validation
```

Avoid placing source-specific logic inside the scanner. Acquisition should produce normalized artifacts first.

---

## 5. Artifact Model

Everything should become a common artifact representation regardless of origin.

```go
type Artifact struct {
    ID           string
    Path         string
    RelativePath string
    Name         string
    Size         int64
    MIMEType     string
    SHA256       string
    Source       SourceMetadata
    Metadata     map[string]any
}

type SourceMetadata struct {
    Type string // file, directory, archive, git, download
    URI  string
}
```

The scanner should not care whether a file came from GitHub, Chrome, a ZIP, or disk.

---

## 6. Findings Model

All detectors emit the same finding type.

```go
type Finding struct {
    ID          string
    Severity    Severity
    Category    string
    Title       string
    Description string
    ArtifactID  string
    File        string
    Line        int
    Evidence    string
    Metadata    map[string]any
}
```

Typical severities:

```text
info
low
medium
high
critical
```

Findings are evidence. They should not directly move/delete files.

---

## 7. Scanner Interface

Scanners should be pluggable.

```go
type Scanner interface {
    Name() string
    Supports(a Artifact) bool
    Scan(ctx context.Context, a Artifact) ([]Finding, error)
}
```

Initial scanners:

```text
HashScanner
FileTypeScanner
ScriptScanner
SourceScanner
ManifestScanner
ArchiveScanner
BinaryMetadataScanner
YaraScanner
```

Use a **bounded worker pool** for directory/repository scans. Do not launch an unbounded goroutine per file.

---

## 8. Ingestion Layer

The ingest layer converts different inputs into artifacts.

Supported inputs evolve as follows:

```text
File
Directory
Archive
Git repository
Incoming download
URL (later)
```

Examples:

```bash
sentinel scan file.sh
sentinel scan ./project
sentinel scan package.zip
sentinel scan https://github.com/org/repo
```

### Git

For `sentinel clone`:

```text
Remote repo
   |
   v
Sentinel temp workspace
   |
   v
Scan
   |
   v
Policy
   |
   +--> allow --> create/move trusted working copy
   |
   +--> review/block --> quarantine/temp only
```

Do not place the working tree in the requested trusted destination before approval.

### Archives

Extract only into Sentinel-owned temporary storage.

Enforce:

```text
max extraction size
max file count
max nesting depth
compression-ratio limits
path traversal protection
symlink escape protection
```

---

## 9. Static Analysis Strategy

V1 should not execute unknown content.

Analyze:

```text
file signatures / magic bytes
hashes
permissions
scripts
source code
package manifests
install hooks
shell execution
subprocess usage
credential access
network destinations
obfuscation
encoded commands
embedded executables
YARA rules
binary metadata
```

Developer-specific files include:

```text
package.json
pyproject.toml
setup.py
requirements.txt
Makefile
Dockerfile
docker-compose.yml
.devcontainer/
.vscode/tasks.json
.github/workflows/
shell scripts
PowerShell scripts
```

Prefer behavior chains over simplistic pattern matching.

Example:

```text
read ~/.aws/credentials
        ->
base64 encode
        ->
POST external domain
```

should become one strong explainable finding where possible.

---

## 10. Policy Engine

Scanning and policy must remain separate.

Example config:

```yaml
policy:
  allow:
    max_severity: low

  review:
    min_severity: medium

  block:
    min_severity: high
```

The policy engine receives:

```text
artifact metadata
findings
source information
configuration
```

and returns:

```go
type Decision string

const (
    Allow  Decision = "allow"
    Review Decision = "review"
    Block  Decision = "block"
)
```

This allows the same findings to behave differently under personal vs enterprise policies.

---

## 11. Download Watcher

Browser/app downloads can target:

```text
~/.sentinel/incoming
```

Watcher flow:

```text
filesystem event
    |
ignore partial extensions
    |
wait until file size is stable
    |
scan
    |
policy
    |
    +--> allow --> ~/Downloads
    |
    +--> review/block --> ~/.sentinel/quarantine
```

Typical ignored partial extensions:

```text
.crdownload
.part
.download
.tmp
```

The watcher should never delete suspicious files automatically.

---

## 12. Quarantine

Recommended storage:

```text
~/.sentinel/
  incoming/
  quarantine/
  scans/
  cache/
  logs/
```

CLI:

```bash
sentinel quarantine list
sentinel quarantine inspect <id>
sentinel quarantine release <id>
sentinel quarantine delete <id>
```

Release requires explicit user action for reviewed/blocked artifacts.

---

## 13. Isolation

Separate **static inspection** from **dynamic execution**.

### V1

Host process orchestrates scans. Deeper parsing may run in isolated Docker/Podman workers.

Worker requirements:

```text
read-only target mount
no network by default
non-root
no host credentials
no SSH agent
no Docker socket
drop capabilities
CPU/memory/PID limits
read-only container filesystem
ephemeral lifecycle
```

Containers reduce blast radius but are **not** considered safe enough for unrestricted malware execution.

### Later

Dynamic malware analysis may use:

```text
gVisor
Firecracker microVMs
disposable VMs
external sandbox providers
```

---

## 14. Redaction Architecture (V2)

Reuse ingestion/parsing infrastructure.

CLI:

```bash
sentinel redact app.log
sentinel redact crash.json
cat app.log | sentinel redact
```

Pipeline:

```text
Input
  |
Sensitive-data detection
  |
Typed replacement
  |
Verification pass
  |
Sanitized output
```

Detect:

```text
API keys
AWS/GitHub/cloud credentials
JWT/Bearer/OAuth tokens
passwords
private keys
connection strings
cookies/session tokens
emails
user IDs
IPs
hostnames
internal domains
filesystem paths
cloud resource identifiers
```

Support profiles:

```yaml
profiles:
  ai:
    redact:
      - credentials
      - tokens
      - emails
      - ips
      - hostnames
      - paths
```

Prefer typed pseudonyms:

```text
[EMAIL_1]
[IP_1]
[HOST_1]
[JWT_1]
```

Repeated raw values should map to the same pseudonym within a session.

Redaction failures must fail closed.

---

## 15. MCP / Live Logs (V3)

The AI must never receive direct access to raw logs.

```text
Raw log source
    |
Sentinel adapter
    |
redaction
    |
verification
    |
local buffer/index
    |
MCP server
    |
AI agent
```

Potential MCP tools:

```text
logs.sources
logs.tail
logs.search
logs.errors
logs.recent
logs.context
```

There should be **no MCP option to disable redaction**.

Raw access, if supported, remains local CLI-only.

### Log adapters

Use explicit adapters rather than arbitrary shell execution:

```go
type LogSource interface {
    Name() string
    Read(ctx context.Context, q Query) (<-chan LogEntry, error)
}
```

Implementations may include:

```text
FileSource
StdoutSource
DockerSource
KubernetesSource
JournaldSource
```

Keep logs local and expose only query results to the model.

---

## 16. Version Build Order

### V1 — Inbound Trust

Build in this order:

```text
1. sentinel scan <file>
2. recursive directory scanning
3. bounded worker pool
4. static rules + explainable findings
5. developer manifest/project parsing
6. archive scanning
7. Git repository scanning
8. sentinel clone
9. watcher + incoming/trusted/quarantine workflow
10. isolated scanner workers
```

### V2 — Outbound Data Safety

Add:

```text
redaction engine
secret/PII/infrastructure detectors
typed pseudonyms
profiles
stream support
verification pass
```

Reuse V1 ingestion, config, parser, CLI, and reporting foundations.

### V3 — AI Gateway

Add:

```text
MCP server
log source adapters
local ring buffer/index
session pseudonyms
sanitized live debugging
optional dynamic sandboxing
```

---

## 17. Important Non-Goals for Early Versions

Do not overbuild V1.

Avoid initially:

```text
full EDR behavior
kernel hooks
browser extensions
automatic malware execution
cloud control plane
complex ML malware classifiers
arbitrary MCP shell execution
cross-platform GUI
enterprise management server
```

The priority is a clean reusable core.

---

## 18. Core Product Model

The system ultimately protects both directions:

```text
UNTRUSTED CONTENT                   SENSITIVE DATA
        |                                |
        v                                v
 Sentinel Scanner                 Sentinel Redactor
        |                                |
        v                                v
Trusted Workspace                AI / External Tools
```

The intended long-term product is:

> A local-first developer security gateway that evaluates untrusted content before it enters the trusted environment and sanitizes sensitive development data before it leaves.
