package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boktavec/redactscan/internal/redactor"
	"github.com/boktavec/redactscan/internal/safefs"
)

const marker = "MARKER-input-text-7f3a"

// Secret-shaped values are built at runtime so no literal is committed.
func randomFrom(r *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

const (
	upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	alnum       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func awsKey(seed int64) string {
	return "AKIA" + randomFrom(rand.New(rand.NewSource(seed)), upperDigits, 16)
}

func ghToken(seed int64) string {
	return "ghp_" + randomFrom(rand.New(rand.NewSource(seed)), alnum, 36)
}

// truncatedGitHubToken is too short to be detected, so the redactor's
// output verification fails on it.
func truncatedGitHubToken(seed int64) string {
	return "ghp_" + randomFrom(rand.New(rand.NewSource(seed)), alnum, 20)
}

type result struct {
	code           int
	stdout, stderr string
}

func run(args []string, stdin io.Reader) result {
	var out, errb bytes.Buffer
	code := Run(args, stdin, &out, &errb)
	return result{code, out.String(), errb.String()}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func redacted(t *testing.T, input string) string {
	t.Helper()
	res, err := redactor.Redact([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return string(res.Output)
}

// assertFailure checks the common contract of every non-zero exit: empty
// stdout and no input bytes on stderr.
func assertFailure(t *testing.T, got result, code int, stderr string, inputs ...string) {
	t.Helper()
	if got.code != code {
		t.Errorf("exit = %d, want %d (stderr %q)", got.code, code, got.stderr)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
	if stderr != "" && got.stderr != stderr {
		t.Errorf("stderr = %q, want %q", got.stderr, stderr)
	}
	for _, in := range inputs {
		if in != "" && strings.Contains(got.stderr, in) {
			t.Errorf("stderr contains input bytes %q", in)
		}
	}
}

func TestRedactFileAndStdin(t *testing.T) {
	input := "start " + awsKey(1) + " " + marker + " " + ghToken(2) + "\n"
	want := redacted(t, input)
	path := writeTemp(t, input)

	tests := []struct {
		name  string
		args  []string
		stdin io.Reader
	}{
		{"file", []string{"redact", path}, strings.NewReader("")},
		{"file ignores stdin", []string{"redact", path}, strings.NewReader("stdin data " + awsKey(3))},
		{"dash", []string{"redact", "-"}, strings.NewReader(input)},
		{"no argument", []string{"redact"}, strings.NewReader(input)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := run(tt.args, tt.stdin)
			if got.code != 0 || got.stdout != want || got.stderr != "" {
				t.Fatalf("got %+v, want exit 0, stdout %q, empty stderr", got, want)
			}
		})
	}
}

func TestRedactEmptyInput(t *testing.T) {
	got := run([]string{"redact"}, strings.NewReader(""))
	if got != (result{}) {
		t.Fatalf("got %+v, want exit 0 with no output", got)
	}
}

func TestRedactSizeLimit(t *testing.T) {
	filler := strings.Repeat("a", redactor.MaxInputSize)

	t.Run("exactly the limit", func(t *testing.T) {
		got := run([]string{"redact"}, strings.NewReader(filler))
		if got.code != 0 || got.stdout != filler || got.stderr != "" {
			t.Fatalf("exit = %d, stderr = %q", got.code, got.stderr)
		}
	})
	t.Run("one byte over", func(t *testing.T) {
		got := run([]string{"redact"}, strings.NewReader(filler+"a"))
		assertFailure(t, got, 1, "redactscan: redaction refused: input exceeds 10 MiB limit\n")
	})
	t.Run("read is bounded", func(t *testing.T) {
		// An endless reader must not hang or exhaust memory.
		got := run([]string{"redact"}, endless{})
		assertFailure(t, got, 1, "redactscan: redaction refused: input exceeds 10 MiB limit\n")
	})
}

type endless struct{}

func (endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestRedactRefusals(t *testing.T) {
	trunc := truncatedGitHubToken(5)
	tests := []struct {
		name   string
		input  string
		stderr string
	}{
		{"NUL byte", marker + " " + awsKey(6) + "\x00", "redactscan: redaction refused: unsupported encoding (NUL byte or UTF-16/32)\n"},
		{"UTF-16 BOM", "\xff\xfe" + marker, "redactscan: redaction refused: unsupported encoding (NUL byte or UTF-16/32)\n"},
		{"UTF-32 LE BOM", "\xff\xfe\x00\x00" + marker, "redactscan: redaction refused: unsupported encoding (NUL byte or UTF-16/32)\n"},
		{"UTF-32 BE BOM", "\x00\x00\xfe\xff" + marker, "redactscan: redaction refused: unsupported encoding (NUL byte or UTF-16/32)\n"},
		{"UTF-16 BE BOM", "\xfe\xff" + marker, "redactscan: redaction refused: unsupported encoding (NUL byte or UTF-16/32)\n"},
		{"verification failure", marker + " " + trunc + "\n", "redactscan: redaction refused: output could not be verified (kind: GITHUB_TOKEN)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := run([]string{"redact", "-"}, strings.NewReader(tt.input))
			assertFailure(t, got, 1, tt.stderr, marker, trunc, awsKey(6))
		})
	}
}

func TestRefusalReasonMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"typed verification", &redactor.VerificationError{Kind: redactor.KindPrivateKey}, "output could not be verified (kind: PRIVATE_KEY)"},
		{"sentinel only", redactor.ErrVerificationFailed, "output could not be verified (kind: unknown)"},
		{"other error", errors.New("contains " + marker), "internal error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refusalReason(tt.err); got != tt.want {
				t.Errorf("refusalReason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOpenReasonMapping(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("wrapped %s: %w", marker, err) }
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"symlink", wrap(safefs.ErrSymlink), "symlink refused"},
		{"typed not regular", wrap(&safefs.NotRegularError{Type: safefs.TypeSocket}), "not a regular file (socket)"},
		{"sentinel not regular", wrap(safefs.ErrNotRegular), "not a regular file"},
		{"changed", wrap(safefs.ErrChanged), "file changed during open"},
		{"unsupported", wrap(safefs.ErrUnsupportedPlatform), "unsupported platform"},
		{"not exist", wrap(fs.ErrNotExist), "not found"},
		{"permission", wrap(fs.ErrPermission), "permission denied"},
		{"other", errors.New("contains " + marker), "cannot open"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := openReason(tt.err); got != tt.want {
				t.Errorf("openReason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedactIOErrors(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no such\nfile")
	unreadable := writeTemp(t, marker+" "+awsKey(7))
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	canRead := func() bool {
		f, err := os.Open(unreadable)
		if err == nil {
			_ = f.Close()
		}
		return err == nil
	}()

	t.Run("missing file", func(t *testing.T) {
		got := run([]string{"redact", missing}, strings.NewReader(""))
		assertFailure(t, got, 3, `redactscan: cannot open "`+dir+`/no such\nfile": not found`+"\n")
		if strings.Count(got.stderr, "\n") != 1 {
			t.Errorf("control character in path was not quoted: %q", got.stderr)
		}
	})
	t.Run("permission denied", func(t *testing.T) {
		if canRead {
			t.Skip("file is readable (running as root?)")
		}
		got := run([]string{"redact", unreadable}, strings.NewReader(""))
		assertFailure(t, got, 3, `redactscan: cannot open "`+unreadable+`": permission denied`+"\n", marker, awsKey(7))
	})
	t.Run("empty path is not stdin", func(t *testing.T) {
		got := run([]string{"redact", ""}, strings.NewReader(marker+" "+awsKey(10)))
		assertFailure(t, got, 3, "redactscan: cannot open \"\": not found\n", marker, awsKey(10))
	})
	t.Run("other open error", func(t *testing.T) {
		long := filepath.Join(dir, strings.Repeat("a", 5000))
		got := run([]string{"redact", long}, strings.NewReader(""))
		assertFailure(t, got, 3, `redactscan: cannot open "`+long+`": cannot open`+"\n")
	})
	t.Run("directory", func(t *testing.T) {
		got := run([]string{"redact", dir}, strings.NewReader(""))
		assertFailure(t, got, 3, `redactscan: cannot open "`+dir+`": not a regular file (directory)`+"\n")
	})
	t.Run("symlink", func(t *testing.T) {
		target := writeTemp(t, marker+" "+awsKey(11))
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		got := run([]string{"redact", link}, strings.NewReader(""))
		assertFailure(t, got, 3, `redactscan: cannot open "`+link+`": symlink refused`+"\n", marker, awsKey(11))
	})
	t.Run("symlinked parent directory", func(t *testing.T) {
		real := filepath.Join(dir, "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(real, "app.log"), []byte(marker+" "+awsKey(12)), 0o600); err != nil {
			t.Fatal(err)
		}
		logs := filepath.Join(dir, "logs")
		if err := os.Symlink(real, logs); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(logs, "app.log")
		got := run([]string{"redact", path}, strings.NewReader(""))
		assertFailure(t, got, 3, `redactscan: cannot open "`+path+`": symlink refused`+"\n", marker, awsKey(12))
	})
	t.Run("device", func(t *testing.T) {
		got := run([]string{"redact", os.DevNull}, strings.NewReader(""))
		assertFailure(t, got, 3, `redactscan: cannot open "`+os.DevNull+`": not a regular file (device)`+"\n")
	})
	t.Run("stdin read error", func(t *testing.T) {
		// Fake: a reader that fails after some bytes, which the OS will not
		// produce on demand.
		in := io.MultiReader(strings.NewReader(marker+" "+awsKey(8)), errReader{})
		got := run([]string{"redact"}, in)
		assertFailure(t, got, 3, "redactscan: cannot read stdin: read failed\n", marker, awsKey(8))
	})
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom " + marker) }

// Fakes: writers that fail or write short, which a buffer never does.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom " + marker) }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestRedactStdoutWriteFailure(t *testing.T) {
	input := marker + " " + awsKey(9)
	for name, w := range map[string]io.Writer{"error": failWriter{}, "short write": shortWriter{}} {
		t.Run(name, func(t *testing.T) {
			var errb bytes.Buffer
			code := Run([]string{"redact", "-summary"}, strings.NewReader(input), w, &errb)
			if code != 3 {
				t.Errorf("exit = %d, want 3", code)
			}
			if want := "redactscan: cannot write output: write failed\n"; errb.String() != want {
				t.Errorf("stderr = %q, want %q", errb.String(), want)
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		reason string
	}{
		{"no args", nil, "redactscan: missing command\n"},
		{"unknown command", []string{"scan"}, `redactscan: unknown command "scan"` + "\n"},
		{"unknown flag", []string{"redact", "-nope"}, "redactscan: invalid arguments\n"},
		{"two files", []string{"redact", "a", "b"}, "redactscan: expected at most one FILE argument\n"},
		{"flag after file", []string{"redact", "app.log", "-summary"}, "redactscan: expected at most one FILE argument\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := run(tt.args, strings.NewReader(""))
			if got.code != 2 || got.stdout != "" {
				t.Fatalf("got %+v, want exit 2 and empty stdout", got)
			}
			if want := tt.reason + usageText; got.stderr != want {
				t.Errorf("stderr = %q, want reason then usage", got.stderr)
			}
		})
	}
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{
		{"-h"}, {"-help"}, {"--help"},
		{"redact", "-h"}, {"redact", "-help"}, {"redact", "--help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			got := run(args, strings.NewReader(""))
			if got.code != 0 || got.stdout != usageText || got.stderr != "" {
				t.Fatalf("got %+v, want exit 0 with usage on stdout", got)
			}
		})
	}
}

func TestUsageWording(t *testing.T) {
	lower := strings.ToLower(usageText)
	for _, banned := range []string{"safe to share", "safely"} {
		if strings.Contains(lower, banned) {
			t.Errorf("usage text contains %q", banned)
		}
	}
	for _, want := range []string{"AWS", "GitHub", "private keys", "pass through unchanged", "10 MiB", "Exit codes"} {
		if !strings.Contains(usageText, want) {
			t.Errorf("usage text lacks %q", want)
		}
	}
}

func TestSummary(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		input string
		want  string
	}{
		{
			"sorted kinds with distinct counts",
			[]string{"redact", "-summary"},
			ghToken(1) + " " + awsKey(2) + " " + awsKey(3) + " " + awsKey(2),
			"redactscan: redacted AWS_ACCESS_KEY=2 GITHUB_TOKEN=1\n",
		},
		{"double dash", []string{"redact", "--summary"}, awsKey(4), "redactscan: redacted AWS_ACCESS_KEY=1\n"},
		{"no secrets", []string{"redact", "-summary"}, "plain text", "redactscan: no covered secret formats found\n"},
		{"label like only", []string{"redact", "-summary"}, "[GITHUB_TOKEN_1]", "redactscan: no covered secret formats found; neutralised 1 label-like\n"},
		{"secret and label like", []string{"redact", "-summary"}, awsKey(5) + " [AWS_ACCESS_KEY_1]", "redactscan: redacted AWS_ACCESS_KEY=1; neutralised 1 label-like\n"},
		{"flag absent", []string{"redact"}, awsKey(6), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := run(tt.args, strings.NewReader(tt.input))
			if got.code != 0 || got.stderr != tt.want || got.stdout != redacted(t, tt.input) {
				t.Fatalf("got %+v, want exit 0, stderr %q", got, tt.want)
			}
		})
	}
}
