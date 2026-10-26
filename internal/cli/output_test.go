package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/boktavec/redactscan/internal/redactor"
	"github.com/boktavec/redactscan/internal/safefs"
)

const tempLeftLine = "redactscan: temporary file may remain\n"

const noteLine = "redactscan: note: output may still contain uncovered secret formats\n"

func TestCleanedName(t *testing.T) {
	tests := map[string]string{
		"app.log":         "app_cleaned.log",
		"a.2024.log":      "a.2024_cleaned.log",
		"x.tar.gz":        "x.tar_cleaned.gz",
		"Makefile":        "Makefile_cleaned",
		".env":            ".env_cleaned",
		".env.local":      ".env_cleaned.local",
		".config.yml":     ".config_cleaned.yml",
		"x.":              "x_cleaned.",
		"..foo":           "..foo_cleaned",
		"app_cleaned.log": "app_cleaned_cleaned.log",
		"...":             "..._cleaned",
	}
	for in, want := range tests {
		if got := cleanedName(in); got != want {
			t.Errorf("cleanedName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitTyped(t *testing.T) {
	tests := []struct{ path, dir, base string }{
		{"app.log", "", "app.log"},
		{"/app.log", "/", "app.log"},
		{"logs/app.log", "logs/", "app.log"},
		{"logs//app.log", "logs//", "app.log"},
		{"./a/../app.log", "./a/../", "app.log"},
	}
	for _, tt := range tests {
		if dir, base := splitTyped(tt.path); dir != tt.dir || base != tt.base {
			t.Errorf("splitTyped(%q) = %q, %q", tt.path, dir, base)
		}
	}
}

// entries lists a directory, so tests can assert nothing was created.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range list {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func writeIn(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRedactWritesCleanedFile(t *testing.T) {
	input := marker + " " + awsKey(20) + "\n"
	dir := t.TempDir()
	in := writeIn(t, dir, "app.log", input)
	out := filepath.Join(dir, "app_cleaned.log")

	got := run([]string{"redact", in}, strings.NewReader(""))
	wantErr := "redactscan: redacted AWS_ACCESS_KEY=1\n" +
		"redactscan: wrote " + strconv.Quote(out) + "\n" + noteLine
	if got != (result{0, "", wantErr}) {
		t.Fatalf("got %+v, want exit 0, empty stdout, stderr %q", got, wantErr)
	}
	if c := readFile(t, out); c != redacted(t, input) {
		t.Errorf("output = %q", c)
	}
	if readFile(t, in) != input {
		t.Error("input was modified")
	}
	if names := entries(t, dir); len(names) != 2 {
		t.Errorf("directory = %v, want input and output only", names)
	}
}

func TestRedactEmptyFileGivesEmptyOutput(t *testing.T) {
	dir := t.TempDir()
	got := run([]string{"redact", writeIn(t, dir, "e.log", "")}, strings.NewReader(""))
	if got.code != 0 || got.stdout != "" {
		t.Fatalf("got %+v", got)
	}
	if fi, err := os.Stat(filepath.Join(dir, "e_cleaned.log")); err != nil || fi.Size() != 0 {
		t.Fatalf("empty output file missing: %v", err)
	}
}

func TestStdoutAndStdinCreateNoFile(t *testing.T) {
	input := marker + " " + awsKey(21)
	dir := t.TempDir()
	in := writeIn(t, dir, "app.log", input)
	want := redacted(t, input)
	for name, args := range map[string][]string{
		"-stdout":       {"redact", "-stdout", in},
		"-stdout force": {"redact", "-stdout", "-force", in},
		"stdin force":   {"redact", "-force"},
		"dash stdout":   {"redact", "-stdout", "-"},
	} {
		t.Run(name, func(t *testing.T) {
			got := run(args, strings.NewReader(input))
			if got.code != 0 || got.stderr != "redactscan: redacted AWS_ACCESS_KEY=1\n" || got.stdout != want {
				t.Fatalf("got %+v", got)
			}
			if names := entries(t, dir); len(names) != 1 {
				t.Errorf("directory = %v, want input only", names)
			}
		})
	}
}

func TestFlagAfterFileIsUsageError(t *testing.T) {
	dir := t.TempDir()
	in := writeIn(t, dir, "app.log", awsKey(22))
	for _, flagArg := range []string{"-stdout", "-force"} {
		got := run([]string{"redact", in, flagArg}, strings.NewReader(""))
		if got.code != 2 || got.stdout != "" {
			t.Errorf("%s: got %+v", flagArg, got)
		}
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Errorf("directory = %v", names)
	}
}

func TestNoClobberAndForce(t *testing.T) {
	input := marker + " " + awsKey(23)
	dir := t.TempDir()
	in := writeIn(t, dir, "app.log", input)
	out := filepath.Join(dir, "app_cleaned.log")
	exists := "redactscan: cannot write " + strconv.Quote(out) + ": already exists (use -force to replace)\n"

	writeIn(t, dir, "app_cleaned.log", "old")
	assertFailure(t, run([]string{"redact", in}, strings.NewReader("")), 3, exists, marker)
	if readFile(t, out) != "old" {
		t.Error("existing destination was modified")
	}

	got := run([]string{"redact", "-force", in}, strings.NewReader(""))
	if got.code != 0 || readFile(t, out) != redacted(t, input) {
		t.Fatalf("force: got %+v", got)
	}
	if names := entries(t, dir); len(names) != 2 {
		t.Errorf("directory = %v, want no temp file", names)
	}
}

func TestRefusedDestinations(t *testing.T) {
	input := marker + " " + awsKey(24)
	tests := []struct {
		name    string
		force   bool
		make    func(t *testing.T, dir string)
		reason  string
		keepsIt string // file that must keep this content
	}{
		{"symlink without force", false, func(t *testing.T, dir string) {
			mustSymlink(t, filepath.Join(dir, "target"), filepath.Join(dir, "app_cleaned.log"))
		}, "already exists (use -force to replace)", ""},
		{"directory without force", false, func(t *testing.T, dir string) {
			mustMkdir(t, filepath.Join(dir, "app_cleaned.log"))
		}, "already exists (use -force to replace)", ""},
		{"symlink with force", true, func(t *testing.T, dir string) {
			writeIn(t, dir, "target", "keep")
			mustSymlink(t, filepath.Join(dir, "target"), filepath.Join(dir, "app_cleaned.log"))
		}, "symlink refused", "target"},
		{"directory with force", true, func(t *testing.T, dir string) {
			mustMkdir(t, filepath.Join(dir, "app_cleaned.log"))
		}, "not a regular file (directory)", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			in := writeIn(t, dir, "app.log", input)
			tt.make(t, dir)
			before := entries(t, dir)
			args := []string{"redact", in}
			if tt.force {
				args = []string{"redact", "-force", in}
			}
			out := filepath.Join(dir, "app_cleaned.log")
			got := run(args, strings.NewReader(""))
			assertFailure(t, got, 3, "redactscan: cannot write "+strconv.Quote(out)+": "+tt.reason+"\n", marker)
			if after := entries(t, dir); strings.Join(after, ",") != strings.Join(before, ",") {
				t.Errorf("directory changed: %v -> %v", before, after)
			}
			if tt.keepsIt != "" && readFile(t, filepath.Join(dir, tt.keepsIt)) != "keep" {
				t.Error("symlink target was modified")
			}
		})
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestNothingCreatedBeforeRedactSucceeds(t *testing.T) {
	trunc := truncatedGitHubToken(25)
	tests := map[string]string{
		"verifier failure":     marker + " " + trunc + "\n",
		"oversize":             strings.Repeat("a", redactor.MaxInputSize+1),
		"unsupported encoding": marker + "\x00",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			in := writeIn(t, dir, "app.log", content)
			got := run([]string{"redact", in}, strings.NewReader(""))
			assertFailure(t, got, 1, "", marker, trunc)
			if names := entries(t, dir); len(names) != 1 {
				t.Errorf("directory = %v, want input only", names)
			}
		})
	}
	t.Run("open failure", func(t *testing.T) {
		dir := t.TempDir()
		mustSymlink(t, dir, filepath.Join(dir, "link"))
		got := run([]string{"redact", filepath.Join(dir, "link")}, strings.NewReader(""))
		assertFailure(t, got, 3, "")
		if names := entries(t, dir); len(names) != 1 {
			t.Errorf("directory = %v, want link only", names)
		}
	})
}

func TestNameTooLong(t *testing.T) {
	dir := t.TempDir()
	// 250 bytes is a valid name, but "_cleaned" pushes the output past NAME_MAX.
	name := strings.Repeat("a", 246) + ".log"
	in := writeIn(t, dir, name, marker+" "+awsKey(26))
	out := filepath.Join(dir, cleanedName(name))
	got := run([]string{"redact", in}, strings.NewReader(""))
	assertFailure(t, got, 3, "redactscan: cannot write "+strconv.Quote(out)+": name too long\n", marker)
	if names := entries(t, dir); len(names) != 1 {
		t.Errorf("directory = %v, want input only", names)
	}
}

func TestHostileFilenameIsQuoted(t *testing.T) {
	dir := t.TempDir()
	name := "a\x1b[31m\nb\u202ec.log"
	in := writeIn(t, dir, name, awsKey(27))
	got := run([]string{"redact", in}, strings.NewReader(""))
	wantOut := strconv.Quote(filepath.Join(dir, cleanedName(name)))
	if got.code != 0 || got.stderr != "redactscan: redacted AWS_ACCESS_KEY=1\nredactscan: wrote "+wantOut+"\n"+noteLine {
		t.Fatalf("got %+v", got)
	}
	for _, raw := range []string{"\x1b", "\u202e"} {
		if strings.Contains(got.stderr, raw) {
			t.Errorf("stderr contains raw %q", raw)
		}
	}
	if strings.Count(got.stderr, "\n") != 3 {
		t.Errorf("newline in name was not escaped: %q", got.stderr)
	}
}

// TestForceWithRacingDirectory races -force against a directory appearing at
// the destination. Every outcome must be a whole file or a fixed refusal.
func TestForceWithRacingDirectory(t *testing.T) {
	input := marker + " " + awsKey(28)
	want := redacted(t, input)
	dir := t.TempDir()
	in := writeIn(t, dir, "app.log", input)
	out := filepath.Join(dir, "app_cleaned.log")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if os.Mkdir(out, 0o700) == nil {
				_ = os.Remove(out)
			}
		}
	}()
	defer func() { close(stop); wg.Wait() }()

	for range 200 {
		got := run([]string{"redact", "-force", in}, strings.NewReader(""))
		switch got.code {
		case 0:
			if c := readFile(t, out); c != want {
				t.Fatalf("output = %q", c)
			}
			_ = os.Remove(out)
		case 3:
			ok := false
			for _, r := range []string{"file changed during write", "not a regular file (directory)"} {
				ok = ok || strings.HasSuffix(got.stderr, ": "+r+"\n")
			}
			if !ok || got.stdout != "" {
				t.Fatalf("got %+v", got)
			}
		default:
			t.Fatalf("got %+v", got)
		}
	}
	for _, n := range entries(t, dir) {
		if strings.HasPrefix(n, ".redactscan-") {
			t.Errorf("temp file left: %s", n)
		}
	}
}

func TestWriteReasonMapping(t *testing.T) {
	both := errors.Join(safefs.ErrChanged, syscall.EEXIST)
	tests := []struct {
		name    string
		err     error
		replace bool
		want    string
	}{
		{"exists", syscall.EEXIST, false, "already exists (use -force to replace)"},
		{"exists with force is not reported as exists", syscall.EEXIST, true, "write failed"},
		{"changed beats exists", both, false, "file changed during write"},
		{"changed with force", safefs.ErrChanged, true, "file changed during write"},
		{"symlink", safefs.ErrSymlink, true, "symlink refused"},
		{"typed not regular", &safefs.NotRegularError{Type: safefs.TypeFIFO}, true, "not a regular file (fifo)"},
		{"link EPERM", syscall.EPERM, false, "no-clobber write not supported on this filesystem"},
		{"link ENOTSUP", syscall.ENOTSUP, false, "no-clobber write not supported on this filesystem"},
		{"link EOPNOTSUPP", syscall.EOPNOTSUPP, false, "no-clobber write not supported on this filesystem"},
		{"link EMLINK", syscall.EMLINK, false, "no-clobber write not supported on this filesystem"},
		{"EPERM with force", syscall.EPERM, true, "permission denied"},
		{"rename onto directory", syscall.EISDIR, true, "not a regular file (directory)"},
		{"EACCES", syscall.EACCES, false, "permission denied"},
		{"ENOSPC", syscall.ENOSPC, true, "no space left"},
		{"EDQUOT", syscall.EDQUOT, true, "no space left"},
		{"ENAMETOOLONG", syscall.ENAMETOOLONG, false, "name too long"},
		{"EROFS", syscall.EROFS, false, "read-only filesystem"},
		{"unsupported", safefs.ErrUnsupportedPlatform, false, "unsupported platform"},
		{"invalid name", safefs.ErrInvalidName, false, "write failed"},
		{"temp names", safefs.ErrTempNames, false, "write failed"},
		{"other", errors.New("contains " + marker), false, "write failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := writeReason(tt.err, tt.replace); got != tt.want {
				t.Errorf("writeReason = %q, want %q", got, tt.want)
			}
		})
	}
}

// Tests that replace writeSibling must not call t.Parallel: the seam is
// package state.
func stubWriteSibling(t *testing.T, fn func(string, fs.FileInfo, string, []byte, bool) (bool, error)) {
	t.Helper()
	old := writeSibling
	writeSibling = fn
	t.Cleanup(func() { writeSibling = old })
}

func TestTempLeftLine(t *testing.T) {
	dir := t.TempDir()
	in := writeIn(t, dir, "app.log", awsKey(30))
	out := strconv.Quote(filepath.Join(dir, "app_cleaned.log"))
	tests := []struct {
		name       string
		err        error
		code       int
		wantStderr string
	}{
		{"success", nil, 0, "redactscan: redacted AWS_ACCESS_KEY=1\nredactscan: wrote " + out + "\n" + noteLine + tempLeftLine},
		{"failure", syscall.ENOSPC, 3, "redactscan: cannot write " + out + ": no space left\n" + tempLeftLine},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubWriteSibling(t, func(string, fs.FileInfo, string, []byte, bool) (bool, error) { return true, tt.err })
			got := run([]string{"redact", in}, strings.NewReader(""))
			if got != (result{tt.code, "", tt.wantStderr}) {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

// The FileInfo handed to WriteSibling must come from the open descriptor: if
// the input entry is replaced after open, the write is refused.
func TestInputInfoComesFromOpenDescriptor(t *testing.T) {
	dir := t.TempDir()
	in := writeIn(t, dir, "app.log", awsKey(31))
	stubWriteSibling(t, func(path string, fi fs.FileInfo, name string, data []byte, replace bool) (bool, error) {
		if err := os.Rename(in, filepath.Join(dir, "moved.log")); err != nil {
			t.Fatal(err)
		}
		writeIn(t, dir, "app.log", "replacement")
		return safefs.WriteSibling(path, fi, name, data, replace)
	})
	got := run([]string{"redact", in}, strings.NewReader(""))
	want := "redactscan: cannot write " + strconv.Quote(filepath.Join(dir, "app_cleaned.log")) + ": file changed during write\n"
	assertFailure(t, got, 3, want)
	if names := entries(t, dir); strings.Join(names, ",") != "app.log,moved.log" {
		t.Errorf("directory = %v, want no output or temp file", names)
	}
}

func TestFileSummaryModes(t *testing.T) {
	input := marker + " " + awsKey(60) + " " + awsKey(61) + " [AWS_ACCESS_KEY_1]\n"
	wantOutput := redacted(t, input)
	tests := []struct {
		name  string
		flags []string
		want  func(out string) string
	}{
		{"default", nil, func(out string) string {
			return "redactscan: redacted AWS_ACCESS_KEY=2; neutralised 1 label-like\nredactscan: wrote " + out + "\n" + noteLine
		}},
		{"summary no-op", []string{"-summary"}, func(out string) string {
			return "redactscan: redacted AWS_ACCESS_KEY=2; neutralised 1 label-like\nredactscan: wrote " + out + "\n" + noteLine
		}},
		{"json", []string{"-json"}, func(string) string {
			return `{"counts":{"AWS_ACCESS_KEY":2,"LABEL_LIKE":1}}` + "\n"
		}},
		{"quiet", []string{"--quiet"}, func(string) string { return "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			in := writeIn(t, dir, "app.log", input)
			out := filepath.Join(dir, "app_cleaned.log")
			got := run(append(append([]string{"redact"}, tt.flags...), in), strings.NewReader(""))
			if want := (result{0, "", tt.want(strconv.Quote(out))}); got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
			if c := readFile(t, out); c != wantOutput {
				t.Errorf("output file = %q", c)
			}
		})
	}
}

func TestFileFailuresPrintNoSummary(t *testing.T) {
	for _, fl := range [][]string{nil, {"-json"}, {"-quiet"}, {"-summary"}} {
		name := strings.Join(fl, "")
		run3 := func(in string) result {
			return run(append(append([]string{"redact"}, fl...), in), strings.NewReader(""))
		}
		t.Run("refused"+name, func(t *testing.T) {
			dir := t.TempDir()
			in := writeIn(t, dir, "app.log", "a\x00")
			assertFailure(t, run3(in), 1, "redactscan: redaction refused: unsupported encoding (NUL byte or UTF-16/32)\n")
			if names := entries(t, dir); len(names) != 1 {
				t.Errorf("directory = %v", names)
			}
		})
		t.Run("existing destination"+name, func(t *testing.T) {
			dir := t.TempDir()
			in := writeIn(t, dir, "app.log", awsKey(62))
			writeIn(t, dir, "app_cleaned.log", "keep")
			out := strconv.Quote(filepath.Join(dir, "app_cleaned.log"))
			assertFailure(t, run3(in), 3, "redactscan: cannot write "+out+": already exists (use -force to replace)\n")
		})
		t.Run("injected write error"+name, func(t *testing.T) {
			dir := t.TempDir()
			in := writeIn(t, dir, "app.log", awsKey(63))
			stubWriteSibling(t, func(string, fs.FileInfo, string, []byte, bool) (bool, error) { return false, syscall.ENOSPC })
			out := strconv.Quote(filepath.Join(dir, "app_cleaned.log"))
			assertFailure(t, run3(in), 3, "redactscan: cannot write "+out+": no space left\n")
		})
	}
}

func TestTempLeftWithSummaryModes(t *testing.T) {
	dir := t.TempDir()
	in := writeIn(t, dir, "app.log", awsKey(64))
	stubWriteSibling(t, func(string, fs.FileInfo, string, []byte, bool) (bool, error) { return true, nil })
	t.Run("json first, warning last", func(t *testing.T) {
		got := run([]string{"redact", "-json", in}, strings.NewReader(""))
		want := result{0, "", `{"counts":{"AWS_ACCESS_KEY":1}}` + "\n" + tempLeftLine}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
	t.Run("quiet keeps only the warning", func(t *testing.T) {
		got := run([]string{"redact", "-quiet", in}, strings.NewReader(""))
		if want := (result{0, "", tempLeftLine}); got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
}

func TestStdoutIdenticalAcrossFlags(t *testing.T) {
	input := marker + " " + awsKey(65) + "\n"
	want := redacted(t, input)
	for _, fl := range [][]string{nil, {"-summary"}, {"-quiet"}, {"-json"}} {
		got := run(append(append([]string{"redact"}, fl...), "-"), strings.NewReader(input))
		if got.code != 0 || got.stdout != want {
			t.Errorf("%v: got %+v", fl, got)
		}
	}
}
