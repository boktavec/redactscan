//go:build darwin || linux

package cli

import (
	"os"
	"strings"
	"testing"
	"time"
)

const changedLine = "- file changed during the scan\n"

// scanWithChange runs `scan path` and calls modify between Run and the change
// checks, through the afterRun seam.
func scanWithChange(t *testing.T, path string, modify func()) result {
	t.Helper()
	useScanners(t, fakeScanner{name: "a"})
	afterRun = modify
	t.Cleanup(func() { afterRun = func() {} })
	return run([]string{"scan", path}, strings.NewReader(""))
}

// TestScanRealRegistryDetectsChange checks that the change check wraps the
// production registry, not only injected fake scanners.
func TestScanRealRegistryDetectsChange(t *testing.T) {
	path := writeTemp(t, "content")
	afterRun = func() {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = f.Close() }()
		if _, err := f.WriteString("more"); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { afterRun = func() {} })
	got := run([]string{"scan", path}, strings.NewReader(""))
	if got.code != exitIncomplete || got.stderr != "" || !strings.Contains(got.stdout, changedLine) ||
		!strings.Contains(got.stdout, "hash.sha256") {
		t.Errorf("got %+v", got)
	}
}

func TestScanUntouchedFileIsComplete(t *testing.T) {
	got := scanWithChange(t, writeTemp(t, "content"), func() {})
	if got.code != 0 || strings.Contains(got.stdout, "changed") {
		t.Errorf("got %+v", got)
	}
}

func TestScanDetectsChangeDuringScan(t *testing.T) {
	later := time.Now().Add(-time.Hour)
	tests := []struct {
		name   string
		modify func(t *testing.T, path string)
	}{
		{"append", func(t *testing.T, path string) {
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if _, err := f.WriteString("more"); err != nil {
				t.Fatal(err)
			}
		}},
		{"truncate", func(t *testing.T, path string) {
			if err := os.Truncate(path, 2); err != nil {
				t.Fatal(err)
			}
		}},
		{"same-size rewrite with a new mtime", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("CONTENT"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, later, later); err != nil {
				t.Fatal(err)
			}
		}},
		{"mtime only", func(t *testing.T, path string) {
			if err := os.Chtimes(path, later, later); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each format gets a fresh file: a second run on an already
			// modified file would make some modifications no-ops.
			path := writeTemp(t, "content")
			got := scanWithChange(t, path, func() { tt.modify(t, path) })
			if got.code != exitIncomplete || got.stderr != "" || !strings.Contains(got.stdout, changedLine) {
				t.Errorf("text: got %+v", got)
			}

			path = writeTemp(t, "content")
			useScanners(t, fakeScanner{name: "a"})
			afterRun = func() { tt.modify(t, path) }
			got = run([]string{"scan", "-json", path}, strings.NewReader(""))
			if got.code != exitIncomplete || !strings.Contains(got.stdout, `{"scanner":"registry","reason":"changed"}`) {
				t.Errorf("json: got %+v", got)
			}
		})
	}
}

// TestCheckUnchanged tests each check alone. The probe test passes a fresh
// FileInfo, so only the byte at offset size can give it away.
func TestCheckUnchanged(t *testing.T) {
	open := func(t *testing.T) (*os.File, os.FileInfo, string) {
		t.Helper()
		path := writeTemp(t, "12345")
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		return f, fi, path
	}

	t.Run("untouched", func(t *testing.T) {
		f, fi, _ := open(t)
		if !checkUnchanged(f, fi, fi.Size()) {
			t.Error("reported a change")
		}
	})
	t.Run("probe sees appended data", func(t *testing.T) {
		f, _, path := open(t)
		if err := os.WriteFile(path, []byte("12345678"), 0o600); err != nil {
			t.Fatal(err)
		}
		fresh, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if checkUnchanged(f, fresh, 5) {
			t.Error("data at offset size was not detected")
		}
	})
	t.Run("probe error other than EOF", func(t *testing.T) {
		f, fi, _ := open(t)
		// A negative offset makes ReadAt fail with a non-EOF error.
		if checkUnchanged(f, fi, -1) {
			t.Error("a failing probe counted as unchanged")
		}
	})
	t.Run("failing fstat", func(t *testing.T) {
		f, fi, _ := open(t)
		_ = f.Close()
		if checkUnchanged(f, fi, fi.Size()) {
			t.Error("a failing fstat counted as unchanged")
		}
	})
	t.Run("ctime change alone", func(t *testing.T) {
		f, fi, path := open(t)
		// chmod changes ctime but neither size nor mtime.
		time.Sleep(20 * time.Millisecond)
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if checkUnchanged(f, fi, fi.Size()) {
			t.Error("a ctime change was not detected")
		}
	})
}

// fakeInfo overrides parts of a real FileInfo.
type fakeInfo struct {
	os.FileInfo
	size    *int64
	modTime *time.Time
	noSys   bool
}

func (f fakeInfo) Size() int64 {
	if f.size != nil {
		return *f.size
	}
	return f.FileInfo.Size()
}

func (f fakeInfo) ModTime() time.Time {
	if f.modTime != nil {
		return *f.modTime
	}
	return f.FileInfo.ModTime()
}

func (f fakeInfo) Sys() any {
	if f.noSys {
		return nil
	}
	return f.FileInfo.Sys()
}

// TestCheckUnchangedComparesEachField pins each comparison on its own: the
// recorded FileInfo differs from the real file in exactly one field.
func TestCheckUnchangedComparesEachField(t *testing.T) {
	path := writeTemp(t, "12345")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	otherSize := fi.Size() + 1
	otherTime := fi.ModTime().Add(time.Nanosecond)

	tests := []struct {
		name string
		prev fakeInfo
		want bool
	}{
		{"identical", fakeInfo{FileInfo: fi}, true},
		{"size differs", fakeInfo{FileInfo: fi, size: &otherSize}, false},
		{"mtime differs by 1 ns", fakeInfo{FileInfo: fi, modTime: &otherTime}, false},
		{"no ctime available", fakeInfo{FileInfo: fi, noSys: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkUnchanged(f, tt.prev, fi.Size()); got != tt.want {
				t.Errorf("checkUnchanged = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCtimeNS(t *testing.T) {
	fi, err := os.Stat(writeTemp(t, "x"))
	if err != nil {
		t.Fatal(err)
	}
	ns, ok := ctimeNS(fi)
	if !ok || time.Since(time.Unix(0, ns)) > time.Minute || time.Since(time.Unix(0, ns)) < -time.Minute {
		t.Errorf("ctimeNS = %d, %v", ns, ok)
	}
}
