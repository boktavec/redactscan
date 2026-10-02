# Architecture

RedactScan is organized around independent security capabilities.

```mermaid
flowchart LR

CLI --> Scanner
CLI --> Redactor

Scanner --> Classification
Classification --> Safe
Classification --> Quarantine

Redactor --> Detection
Detection --> Replacement
Replacement --> SanitizedOutput
