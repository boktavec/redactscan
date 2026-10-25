# redactscan
Security-focused CLI for scanning untrusted files and repositories and redacting covered sensitive data from logs.

## Usage

```
redactscan redact [-summary] [-stdout] [-force] [FILE|-]
```

Reads FILE (or stdin when FILE is `-` or absent), replaces covered secret formats (AWS access and secret keys, GitHub tokens, PEM private keys) with numbered labels such as `[GITHUB_TOKEN_1]`, and writes the result. With FILE the result goes to a new file next to it, named by adding `_cleaned` before the last extension (`logs/app.log` becomes `logs/app_cleaned.log`, `.env` becomes `.env_cleaned`), with mode 0600; stdin always goes to stdout. Other secret formats pass through unchanged, so review the output before sharing it. Input is limited to 10 MiB.

- `-summary` writes a one-line count of replaced kinds to stderr.
- `-stdout` prints the result to stdout instead of a file (FILE only).
- `-force` replaces an existing output file; without it an existing destination is refused.
- Flags must come before FILE.
- Every file write prints `wrote "<path>"` and a reminder on stderr that the output may still contain uncovered secret formats.
- If the redactor refuses (input too large, unsupported encoding, output could not be verified), nothing is written anywhere: no stdout bytes and no file. The file is created through a temporary file and an atomic link or rename, so a failure never leaves partial output.

**Breaking change:** older versions printed `redact FILE` to stdout. Now `redactscan redact f | cmd` and `redactscan redact f > out` receive empty stdout and exit 0. Use `-stdout` for the old behavior.

Exit codes: 0 success, 1 redaction refused (nothing written), 2 usage error, 3 I/O error (open, read, stdout write, creating the output file, or a refused destination).

```
go run ./cmd/redactscan redact -summary app.log   # writes app_cleaned.log
go run ./cmd/redactscan redact -stdout app.log > app.redacted.log
```

FILE must be a regular file reached without symlinks: a symlink in any part of the path, a FIFO, a device, a socket or a directory is refused with exit 3. On macOS the system links `/tmp`, `/var` and `/etc` are allowed.
