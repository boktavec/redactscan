//go:build darwin || linux

package safefs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const outName = "app_cleaned.log"

// fixture is an input file whose descriptor was opened the way the CLI does.
type fixture struct {
	dir  string
	path string // typed input path
	fi   fs.FileInfo
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := tempDir(t)
	path := filepath.Join(dir, "app.log")
	writeFile(t, path, []byte("input"))
	f, err := OpenRegular(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return fixture{dir: dir, path: path, fi: fi}
}

func (fx fixture) write(data string, replace bool) (bool, error) {
	return WriteSibling(fx.path, fx.fi, outName, []byte(data), replace)
}

func (fx fixture) out() string { return filepath.Join(fx.dir, outName) }

func (fx fixture) mustWrite(t *testing.T, data string, replace bool) {
	t.Helper()
	if left, err := fx.write(data, replace); err != nil || left {
		t.Fatalf("WriteSibling = (%v, %v)", left, err)
	}
}

func readString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// assertOnly fails unless dir holds exactly the wanted entries (no temp files).
func assertOnly(t *testing.T, dir string, want ...string) {
	t.Helper()
	got := names(t, dir)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("entries in dir = %v, want %v", got, want)
	}
}

// setSeam replaces a test seam for one test. Seam tests and umask tests change
// process-wide state and must not call t.Parallel.
func setSeam[T any](t *testing.T, seam *T, v T) {
	t.Helper()
	old := *seam
	*seam = v
	t.Cleanup(func() { *seam = old })
}

func TestWriteSiblingWritesContentMode0600(t *testing.T) {
	for _, umask := range []int{0o000, 0o077, 0o277} {
		for _, replace := range []bool{false, true} {
			t.Run(fmt.Sprintf("umask %03o replace %v", umask, replace), func(t *testing.T) {
				fx := newFixture(t) // before umask: 0277 would make the temp dir unusable
				old := syscall.Umask(umask)
				t.Cleanup(func() { syscall.Umask(old) })
				if replace {
					writeFile(t, fx.out(), []byte("old"))
				}
				fx.mustWrite(t, marker, replace)

				fi, err := os.Lstat(fx.out())
				if err != nil {
					t.Fatal(err)
				}
				if fi.Mode().Perm() != 0o600 {
					t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
				}
				if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != os.Getuid() {
					t.Errorf("uid = %d, want %d", st.Uid, os.Getuid())
				}
				if got := readString(t, fx.out()); got != marker {
					t.Errorf("content = %q", got)
				}
				assertOnly(t, fx.dir, "app.log", outName)
			})
		}
	}
}

func TestWriteSiblingEmptyData(t *testing.T) {
	fx := newFixture(t)
	fx.mustWrite(t, "", false)
	if got := readString(t, fx.out()); got != "" {
		t.Errorf("content = %q, want empty", got)
	}
}

func TestWriteSiblingRelativeInputPath(t *testing.T) {
	fx := newFixture(t)
	t.Chdir(fx.dir)
	if _, err := WriteSibling("app.log", fx.fi, outName, []byte("x"), false); err != nil {
		t.Fatalf("relative path: %v", err)
	}
	assertOnly(t, fx.dir, "app.log", outName)
}

// destinations builds each kind of existing destination.
var destinations = []struct {
	name  string
	setup func(t *testing.T, path, target string)
	typ   FileType // non-empty when replace must refuse as not regular
	link  bool
}{
	{"regular", func(t *testing.T, p, _ string) { writeFile(t, p, []byte("old")) }, "", false},
	{"symlink", func(t *testing.T, p, target string) {
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}, "", true},
	{"directory", func(t *testing.T, p, _ string) {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}, TypeDirectory, false},
	{"fifo", func(t *testing.T, p, _ string) { mkfifo(t, p) }, TypeFIFO, false},
}

func TestWriteSiblingNoClobber(t *testing.T) {
	for _, d := range destinations {
		t.Run(d.name, func(t *testing.T) {
			fx := newFixture(t)
			target := filepath.Join(fx.dir, "target")
			writeFile(t, target, []byte("target"))
			d.setup(t, fx.out(), target)

			left, err := fx.write(marker, false)
			if !errors.Is(err, fs.ErrExist) || left {
				t.Fatalf("= (%v, %v), want EEXIST", left, err)
			}
			if got := readString(t, target); got != "target" {
				t.Errorf("target changed to %q", got)
			}
			if d.name == "regular" && readString(t, fx.out()) != "old" {
				t.Error("destination changed")
			}
			for _, n := range names(t, fx.dir) {
				if strings.HasPrefix(n, ".redactscan-") {
					t.Errorf("temp file left: %s", n)
				}
			}
		})
	}
}

func TestWriteSiblingReplace(t *testing.T) {
	for _, d := range destinations {
		t.Run(d.name, func(t *testing.T) {
			fx := newFixture(t)
			target := filepath.Join(fx.dir, "target")
			writeFile(t, target, []byte("target"))
			d.setup(t, fx.out(), target)

			left, err := fx.write(marker, true)
			if left {
				t.Error("tempLeft = true")
			}
			var nr *NotRegularError
			switch {
			case d.link:
				if !errors.Is(err, ErrSymlink) {
					t.Errorf("err = %v, want ErrSymlink", err)
				}
			case d.typ != "":
				if !errors.As(err, &nr) || nr.Type != d.typ {
					t.Errorf("err = %v, want NotRegularError(%s)", err, d.typ)
				}
			case err != nil:
				t.Errorf("err = %v", err)
			case readString(t, fx.out()) != marker:
				t.Error("destination not replaced")
			}
			if got := readString(t, target); got != "target" {
				t.Errorf("target changed to %q", got)
			}
		})
	}
}

// S2 (both OSes): O_EXCL on a planted symlink fails with EEXIST, and a rename
// over a symlink replaces the link without touching its target.
func TestRootSymlinkSemantics(t *testing.T) {
	dir := tempDir(t)
	target := filepath.Join(dir, "target")
	writeFile(t, target, []byte("target"))
	if err := os.Symlink(target, filepath.Join(dir, "planted")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	if _, err := root.OpenFile("planted", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); !errors.Is(err, syscall.EEXIST) {
		t.Errorf("O_EXCL over symlink: %v, want EEXIST", err)
	}
	writeFile(t, filepath.Join(dir, "src"), []byte("new"))
	if err := root.Rename("src", "planted"); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(filepath.Join(dir, "planted")); fi.Mode()&fs.ModeSymlink != 0 {
		t.Error("rename did not replace the symlink")
	}
	if got := readString(t, target); got != "target" {
		t.Errorf("target changed to %q", got)
	}
}

// S3: the errno from link on a filesystem without hard links (FAT, exFAT). It
// needs such a volume, so it runs only when REDACTSCAN_NOLINK_DIR names one;
// otherwise the errno stays Assumed (see ADR 0003).
func TestLinkErrnoWithoutHardLinks(t *testing.T) {
	dir := os.Getenv("REDACTSCAN_NOLINK_DIR")
	if dir == "" {
		t.Skip("set REDACTSCAN_NOLINK_DIR to a directory on a filesystem without hard links")
	}
	writeFile(t, filepath.Join(dir, "a"), []byte("x"))
	defer func() { _ = os.Remove(filepath.Join(dir, "a")) }()
	t.Logf("link errno: %v", os.Link(filepath.Join(dir, "a"), filepath.Join(dir, "b")))
}

func TestOpenNoFollowStartDirectories(t *testing.T) {
	for _, p := range []string{".", "/"} {
		f, err := openDir(p)
		if err != nil {
			t.Errorf("openDir(%q): %v", p, err)
			continue
		}
		if fi, err := f.Stat(); err != nil || !fi.IsDir() {
			t.Errorf("openDir(%q) is not a directory: %v", p, err)
		}
		_ = f.Close()
	}
}

func TestSplitTyped(t *testing.T) {
	tests := []struct {
		in, dir, base string
		ok            bool
	}{
		{"app.log", ".", "app.log", true},
		{"/app.log", "/", "app.log", true},
		{"logs/app.log", "logs", "app.log", true},
		{"logs//app.log", "logs/", "app.log", true},
		{"logs/", "logs", "", false},
		{"", ".", "", false},
	}
	for _, tt := range tests {
		dir, base, ok := splitTyped(tt.in)
		if dir != tt.dir || base != tt.base || ok != tt.ok {
			t.Errorf("splitTyped(%q) = %q, %q, %v", tt.in, dir, base, ok)
		}
	}
}

func TestWriteSiblingInvalidNames(t *testing.T) {
	fx := newFixture(t)
	for _, name := range []string{"", ".", "..", "a/b", "a\x00b"} {
		if _, err := WriteSibling(fx.path, fx.fi, name, nil, false); !errors.Is(err, ErrInvalidName) {
			t.Errorf("name %q: err = %v, want ErrInvalidName", name, err)
		}
	}
	if _, err := WriteSibling(fx.path, fx.fi, "app.log", nil, true); !errors.Is(err, ErrInvalidName) {
		t.Errorf("outName == input base: err = %v, want ErrInvalidName", err)
	}
	if _, err := WriteSibling(fx.dir+"/", fx.fi, outName, nil, false); !errors.Is(err, ErrInvalidName) {
		t.Errorf("empty base: err = %v, want ErrInvalidName", err)
	}
}

func TestWriteSiblingSymlinkInDirectoryPath(t *testing.T) {
	fx := newFixture(t)
	link := filepath.Join(tempDir(t), "link")
	if err := os.Symlink(fx.dir, link); err != nil {
		t.Fatal(err)
	}
	_, err := WriteSibling(filepath.Join(link, "app.log"), fx.fi, outName, nil, false)
	if !errors.Is(err, ErrSymlink) {
		t.Errorf("err = %v, want ErrSymlink", err)
	}
	assertOnly(t, fx.dir, "app.log")
}

func TestWriteSiblingInputReplacedAfterRead(t *testing.T) {
	fx := newFixture(t)
	if err := os.Remove(fx.path); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.write(marker, false); !errors.Is(err, ErrChanged) {
		t.Errorf("input removed: err = %v, want ErrChanged", err)
	}
	writeFile(t, fx.path, []byte("other"))
	if _, err := fx.write(marker, false); !errors.Is(err, ErrChanged) {
		t.Errorf("input replaced: err = %v, want ErrChanged", err)
	}
	assertOnly(t, fx.dir, "app.log")
}

func TestWriteSiblingSwapAtDestination(t *testing.T) {
	for _, replace := range []bool{false, true} {
		fx := newFixture(t)
		target := filepath.Join(fx.dir, "target")
		writeFile(t, target, []byte("target"))
		setSeam(t, &beforeCommit, func() {
			if err := os.Symlink(target, fx.out()); err != nil {
				t.Error(err)
			}
		})
		_, err := fx.write(marker, replace)
		if got := readString(t, target); got != "target" {
			t.Errorf("replace=%v: target changed to %q", replace, got)
		}
		if replace {
			if err != nil {
				t.Errorf("replace: %v", err)
			}
			if fi, _ := os.Lstat(fx.out()); fi.Mode()&fs.ModeSymlink != 0 {
				t.Error("replace: symlink was not replaced")
			}
		} else if !errors.Is(err, fs.ErrExist) {
			t.Errorf("no replace: err = %v, want EEXIST", err)
		}
	}
}

// The directory is renamed away and a lookalike put at the typed path (a
// symlink to another directory, or a real directory with same-named entries).
func TestWriteSiblingDirectorySwap(t *testing.T) {
	swaps := map[string]func(t *testing.T, dir, other string){
		"symlink": func(t *testing.T, dir, other string) {
			if err := os.Symlink(other, dir); err != nil {
				t.Fatal(err)
			}
		},
		"real directory": func(t *testing.T, dir, _ string) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(dir, "app.log"), []byte("lookalike"))
			writeFile(t, filepath.Join(dir, outName), []byte("lookalike"))
		},
	}
	for name, swap := range swaps {
		for _, replace := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s replace %v", name, replace), func(t *testing.T) {
				base := tempDir(t)
				sub := filepath.Join(base, "sub")
				moved := filepath.Join(base, "moved")
				other := filepath.Join(base, "other")
				for _, d := range []string{sub, other} {
					if err := os.Mkdir(d, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				in := filepath.Join(sub, "app.log")
				writeFile(t, in, []byte("input"))
				f, err := OpenRegular(in)
				if err != nil {
					t.Fatal(err)
				}
				fi, _ := f.Stat()
				_ = f.Close()

				var temp string
				setSeam(t, &tempName, func() string { temp = randomTempName(); return temp })
				setSeam(t, &beforeCommit, func() {
					if err := os.Rename(sub, moved); err != nil {
						t.Fatal(err)
					}
					swap(t, sub, other)
				})
				if replace {
					writeFile(t, filepath.Join(sub, outName), []byte("old"))
				}
				_, err = WriteSibling(in, fi, outName, []byte(marker), replace)
				if !errors.Is(err, ErrChanged) {
					t.Fatalf("err = %v, want ErrChanged", err)
				}
				assertOnly(t, other)
				if name == "real directory" {
					assertOnly(t, sub, "app.log", outName)
					if readString(t, filepath.Join(sub, outName)) != "lookalike" {
						t.Error("lookalike destination changed")
					}
				}
				for _, n := range names(t, moved) {
					if n == temp {
						t.Error("temp file left in the original directory")
					}
				}
			})
		}
	}
}

// The root is opened through the verified descriptor, so a directory swapped
// in before the root open is never written to: the output stays in the
// original directory and the re-verify then refuses.
func TestWriteSiblingDirectorySwappedBeforeRootOpen(t *testing.T) {
	base := tempDir(t)
	sub, other := filepath.Join(base, "sub"), filepath.Join(base, "other")
	for _, d := range []string{sub, other} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	in := filepath.Join(sub, "app.log")
	writeFile(t, in, []byte("input"))
	// A hard link makes the input binding pass in the lookalike directory.
	if err := os.Link(in, filepath.Join(other, "app.log")); err != nil {
		t.Fatal(err)
	}
	f, err := OpenRegular(in)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := f.Stat()
	_ = f.Close()

	setSeam(t, &beforeOpenRoot, func() {
		if err := os.Rename(sub, filepath.Join(base, "moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(other, sub); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := WriteSibling(in, fi, outName, nil, false); !errors.Is(err, ErrChanged) {
		t.Errorf("err = %v, want ErrChanged", err)
	}
	assertOnly(t, sub, "app.log")
	assertOnly(t, filepath.Join(base, "moved"), "app.log")
}

// Opening the root by path would block forever on a FIFO swapped in for the
// directory.
func TestWriteSiblingFIFOSwappedForDirectoryDoesNotHang(t *testing.T) {
	base := tempDir(t)
	sub := filepath.Join(base, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(sub, "app.log")
	writeFile(t, in, []byte("input"))
	f, err := OpenRegular(in)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := f.Stat()
	_ = f.Close()
	setSeam(t, &beforeOpenRoot, func() {
		if err := os.Rename(sub, filepath.Join(base, "moved")); err != nil {
			t.Fatal(err)
		}
		mkfifo(t, sub)
	})

	done := make(chan error, 1)
	go func() {
		_, err := WriteSibling(in, fi, outName, nil, false)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrChanged) {
			t.Errorf("err = %v, want ErrChanged", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WriteSibling blocked")
	}
	assertOnly(t, filepath.Join(base, "moved"), "app.log")
}

// sameAsRoot is defense in depth now that the root comes from the descriptor,
// so a swap cannot reach it; this checks the comparison itself.
func TestSameAsRootDetectsDifferentDirectories(t *testing.T) {
	a, b := tempDir(t), tempDir(t)
	fa, err := openDir(a)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fa.Close() }()
	ra, _ := os.OpenRoot(a)
	rb, _ := os.OpenRoot(b)
	defer func() { _ = ra.Close(); _ = rb.Close() }()
	if !sameAsRoot(fa, ra) {
		t.Error("same directory reported different")
	}
	if sameAsRoot(fa, rb) {
		t.Error("different directories reported same")
	}
}

func TestWriteSiblingCreateTempFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	fx := newFixture(t)
	if err := os.Chmod(fx.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fx.dir, 0o700) })
	left, err := fx.write(marker, false)
	if left || !errors.Is(err, syscall.EACCES) || err.Error() != "safefs: create temp failed" {
		t.Errorf("= (%v, %v)", left, err)
	}
	assertOnly(t, fx.dir, "app.log")
}

func TestWriteSiblingRetriesPlantedTempName(t *testing.T) {
	fx := newFixture(t)
	target := filepath.Join(fx.dir, "target")
	writeFile(t, target, []byte("target"))
	planted := ".redactscan-planted.tmp"
	if err := os.Symlink(target, filepath.Join(fx.dir, planted)); err != nil {
		t.Fatal(err)
	}
	names := []string{planted, planted, randomTempName()}
	setSeam(t, &tempName, func() string { n := names[0]; names = names[1:]; return n })

	fx.mustWrite(t, marker, false)
	if got := readString(t, target); got != "target" {
		t.Errorf("target written through planted symlink: %q", got)
	}
}

func TestWriteSiblingTempNamesExhausted(t *testing.T) {
	fx := newFixture(t)
	writeFile(t, filepath.Join(fx.dir, ".redactscan-fixed.tmp"), []byte("x"))
	setSeam(t, &tempName, func() string { return ".redactscan-fixed.tmp" })
	if _, err := fx.write(marker, false); !errors.Is(err, ErrTempNames) {
		t.Errorf("err = %v, want ErrTempNames", err)
	}
	assertOnly(t, fx.dir, ".redactscan-fixed.tmp", "app.log")
}

// failingFile injects a failure at one step of the temp-file lifecycle.
type failingFile struct {
	*os.File
	step  string
	short bool
}

func (f failingFile) Write(p []byte) (int, error) {
	if f.short {
		return f.File.Write(p[:len(p)/2])
	}
	if f.step == "write" {
		return 0, syscall.ENOSPC
	}
	return f.File.Write(p)
}

func (f failingFile) Sync() error {
	if f.step == "sync" {
		return syscall.EIO
	}
	return f.File.Sync()
}

func (f failingFile) Close() error {
	_ = f.File.Close()
	if f.step == "close" {
		return syscall.EIO
	}
	return nil
}

func TestWriteSiblingInjectedFailuresLeaveNothing(t *testing.T) {
	cases := []struct {
		step  string
		short bool
		want  error
		text  string
	}{
		{"write", false, syscall.ENOSPC, "safefs: write failed"},
		{"short write", true, io.ErrShortWrite, "safefs: write failed"},
		{"sync", false, syscall.EIO, "safefs: sync failed"},
		{"close", false, syscall.EIO, "safefs: close failed"},
	}
	for _, tc := range cases {
		for _, replace := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s replace %v", tc.step, replace), func(t *testing.T) {
				fx := newFixture(t)
				setSeam(t, &wrapTemp, func(f *os.File) tempFile { return failingFile{f, tc.step, tc.short} })
				left, err := fx.write(marker, replace)
				if left || !errors.Is(err, tc.want) || err.Error() != tc.text {
					t.Errorf("= (%v, %v), want %v with text %q", left, err, tc.want, tc.text)
				}
				assertOnly(t, fx.dir, "app.log")
			})
		}
	}
}

func TestWriteSiblingCommitFailuresLeaveNoTemp(t *testing.T) {
	t.Run("link", func(t *testing.T) {
		fx := newFixture(t)
		setSeam(t, &beforeCommit, func() { writeFile(t, fx.out(), []byte("racer")) })
		left, err := fx.write(marker, false)
		if left || !errors.Is(err, syscall.EEXIST) || err.Error() != "safefs: link failed" {
			t.Errorf("= (%v, %v)", left, err)
		}
		assertOnly(t, fx.dir, "app.log", outName)
		if readString(t, fx.out()) != "racer" {
			t.Error("racing destination was changed")
		}
	})
	t.Run("rename over a directory", func(t *testing.T) {
		fx := newFixture(t)
		setSeam(t, &beforeCommit, func() {
			if err := os.MkdirAll(filepath.Join(fx.out(), "sub"), 0o700); err != nil {
				t.Error(err)
			}
		})
		left, err := fx.write(marker, true)
		if left || !errors.Is(err, ErrChanged) {
			t.Errorf("= (%v, %v), want ErrChanged", left, err)
		}
		assertOnly(t, fx.dir, "app.log", outName)
	})
}

func TestWriteSiblingRemoveFailureSetsTempLeft(t *testing.T) {
	removeFails := func(*os.Root, string) error { return syscall.EIO }
	t.Run("after successful link", func(t *testing.T) {
		fx := newFixture(t)
		setSeam(t, &removeEntry, removeFails)
		left, err := fx.write(marker, false)
		if !left || err != nil {
			t.Errorf("= (%v, %v), want (true, nil)", left, err)
		}
		if readString(t, fx.out()) != marker {
			t.Error("destination missing or wrong")
		}
	})
	t.Run("after failed write", func(t *testing.T) {
		fx := newFixture(t)
		setSeam(t, &removeEntry, removeFails)
		setSeam(t, &wrapTemp, func(f *os.File) tempFile { return failingFile{f, "sync", false} })
		left, err := fx.write(marker, false)
		if !left || err == nil {
			t.Errorf("= (%v, %v), want (true, error)", left, err)
		}
	})
}

func TestWriteSiblingErrorsLeakNoPath(t *testing.T) {
	fx := newFixture(t)
	secret := fx.dir
	var errs []error
	_, err := WriteSibling(filepath.Join(fx.dir, "missing-dir", "app.log"), fx.fi, outName, nil, false)
	errs = append(errs, err)
	fx.mustWrite(t, "x", false)
	_, err = fx.write("x", false)
	errs = append(errs, err)
	setSeam(t, &beforeCommit, func() { writeFile(t, filepath.Join(fx.dir, "d"), nil) })
	_, err = WriteSibling(fx.path, fx.fi, "d", nil, false) // link fails
	errs = append(errs, err)

	for _, err := range errs {
		if err == nil {
			t.Fatal("expected an error")
		}
		var errno syscall.Errno
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "missing-dir") {
			t.Errorf("error text leaks the path: %q", err)
		}
		if !errors.As(err, &errno) {
			t.Errorf("error does not unwrap to syscall.Errno: %v", err)
		}
		var pe *fs.PathError
		var le *os.LinkError
		if errors.As(err, &pe) || errors.As(err, &le) {
			t.Errorf("error still wraps a path-bearing type: %v", err)
		}
	}
}

func TestWriteSiblingConcurrentRuns(t *testing.T) {
	const runs = 16
	for _, replace := range []bool{false, true} {
		fx := newFixture(t)
		var wg sync.WaitGroup
		errs := make([]error, runs)
		for i := range runs {
			wg.Go(func() {
				data := strings.Repeat(string(rune('a'+i)), 64<<10)
				_, errs[i] = fx.write(data, replace)
			})
		}
		wg.Wait()

		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case replace || !errors.Is(err, fs.ErrExist):
				t.Errorf("replace=%v: unexpected error %v", replace, err)
			}
		}
		if replace && ok != runs || !replace && ok != 1 {
			t.Errorf("replace=%v: %d runs succeeded", replace, ok)
		}
		got := readString(t, fx.out())
		if len(got) != 64<<10 || strings.Trim(got, got[:1]) != "" {
			t.Errorf("replace=%v: destination is not exactly one run's output", replace)
		}
		assertOnly(t, fx.dir, "app.log", outName)
	}
}

func TestWriteSiblingLeaksNoDescriptors(t *testing.T) {
	fx := newFixture(t)
	attempts := map[string]func(){
		"success":  func() { _, _ = fx.write("x", true) },
		"exists":   func() { _, _ = fx.write("x", false) },
		"bad name": func() { _, _ = WriteSibling(fx.path, fx.fi, "", nil, false) },
		"changed": func() {
			other, _ := os.Stat(fx.dir)
			_, _ = WriteSibling(fx.path, other, outName, nil, true)
		},
	}
	for name, attempt := range attempts {
		t.Run(name, func(t *testing.T) {
			attempt()
			before := fdCount(t)
			for range 20 {
				attempt()
			}
			if after := fdCount(t); after != before {
				t.Errorf("descriptors before = %d, after = %d", before, after)
			}
		})
	}
}
