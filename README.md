# redactscan
Security-focused CLI for scanning untrusted files and repositories and redacting covered sensitive data from logs.

## Usage

```
redactscan redact [-summary] [FILE|-]
```

Reads FILE (or stdin when FILE is `-` or absent), replaces covered secret formats (AWS access and secret keys, GitHub tokens, PEM private keys) with numbered labels such as `[GITHUB_TOKEN_1]`, and writes the result to stdout. Other secret formats pass through unchanged, so review the output before sharing it. Input is limited to 10 MiB.

- `-summary` writes a one-line count of replaced kinds to stderr.
- If the redactor refuses (input too large, unsupported encoding, output could not be verified), nothing is written to stdout.

Exit codes: 0 success, 1 redaction refused, 2 usage error, 3 I/O error.

```
go run ./cmd/redactscan redact -summary app.log > app.redacted.log
```

Known gap: FILE is opened with a plain `os.Open`, so symlinks are followed and FIFOs or devices are not rejected. Safe file opening is tracked in REDACT-10.
