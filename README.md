# redactscan
Security-focused CLI for scanning untrusted files and repositories and redacting covered sensitive data from logs.

## Usage

```
redactscan redact [-quiet | -json] [-stdout] [-force] [FILE|-]
```

Reads FILE (or stdin when FILE is `-` or absent), replaces covered secret formats (AWS access and secret keys, GitHub tokens, PEM private keys) with numbered labels such as `[GITHUB_TOKEN_1]`, and writes the result. With FILE the result goes to a new file next to it, named by adding `_cleaned` before the last extension (`logs/app.log` becomes `logs/app_cleaned.log`, `.env` becomes `.env_cleaned`), with mode 0600; stdin always goes to stdout. Other secret formats pass through unchanged, so review the output before sharing it. Input is limited to 10 MiB.

- After success, a one-line count of replaced kinds (never values) is written to stderr in every mode; stdout is unchanged. Example: `redactscan: redacted AWS_ACCESS_KEY=2 GITHUB_TOKEN=1; neutralised 1 label-like`.
- `-quiet` prints nothing on stderr on success (errors and the temporary-file warning still print).
- `-json` prints only `{"counts":{"KIND":N,...}}` on stderr on success (kind names as keys, zero counts absent, no values or paths). `-quiet` and `-json` together are a usage error (exit 2).
- `-summary` is deprecated and has no effect.
- `-stdout` prints the result to stdout instead of a file (FILE only).
- `-force` replaces an existing output file; without it an existing destination is refused.
- Flags must come before FILE.
- Every file write prints `wrote "<path>"` and a reminder on stderr that the output may still contain uncovered secret formats, unless `-quiet` or `-json` is given.
- If the redactor refuses (input too large, unsupported encoding, output could not be verified), nothing is written anywhere: no stdout bytes and no file. The file is created through a temporary file and an atomic link or rename, so a failure never leaves partial output.

**Breaking change (stderr):** stdin and `-stdout` runs used to leave stderr empty on success; they now print the summary line, so scripts that check for empty stderr or merge streams with `2>&1` see one more line. Use `-quiet` to restore the old behavior.

**Breaking change:** older versions printed `redact FILE` to stdout. Now `redactscan redact f | cmd` and `redactscan redact f > out` receive empty stdout and exit 0. Use `-stdout` for the old behavior.

Exit codes: 0 success, 1 redaction refused (nothing written), 2 usage error, 3 I/O error (open, read, stdout write, creating the output file, or a refused destination).

```
go run ./cmd/redactscan redact app.log           # writes app_cleaned.log, summary on stderr
go run ./cmd/redactscan redact -json app.log   # stderr: {"counts":{...}}
go run ./cmd/redactscan redact -stdout app.log > app.redacted.log
```

FILE must be a regular file reached without symlinks: a symlink in any part of the path, a FIFO, a device, a socket or a directory is refused with exit 3. On macOS the system links `/tmp`, `/var` and `/etc` are allowed.
