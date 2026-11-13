package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// A procfs file reports size 0 but has content, so the probe past size must
// make the scan incomplete.
func TestScanProcFileIsIncomplete(t *testing.T) {
	// /proc/self is a symlink, which safefs refuses, so use the pid.
	path := fmt.Sprintf("/proc/%d/status", os.Getpid())
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no procfs: %v", err)
	}
	useScanners(t, fakeScanner{name: "a"})
	got := run([]string{"scan", path}, strings.NewReader(""))
	if got.code != exitIncomplete || got.stderr != "" || !strings.Contains(got.stdout, changedLine) {
		t.Errorf("got %+v", got)
	}
}
