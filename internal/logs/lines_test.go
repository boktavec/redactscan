package logs

import (
	"math"
	"reflect"
	"testing"
)

// feed writes the chunks in order and returns every emitted entry.
func feed(a *lineAssembler, chunks ...string) []LogEntry {
	var out []LogEntry
	collect := func(e LogEntry) bool { out = append(out, e); return true }
	for _, c := range chunks {
		a.write([]byte(c), collect)
	}
	return out
}

func cutAll(a *lineAssembler) []LogEntry {
	var out []LogEntry
	a.cut(func(e LogEntry) bool { out = append(out, e); return true })
	return out
}

func line(s string) LogEntry { return LogEntry{Source: "t", Line: []byte(s)} }

func marker(dropped int64) LogEntry {
	return LogEntry{Source: "t", Truncated: true, Dropped: dropped}
}

func TestLineAssemblerSplitsLinesAcrossChunks(t *testing.T) {
	a := newLineAssembler("t", 100)
	got := feed(a, "al", "pha\nbe", "ta\n\ngam", "ma\n")
	want := []LogEntry{line("alpha"), line("beta"), line(""), line("gamma")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got[2].Line == nil {
		t.Error("empty line has nil Line, want empty non-nil")
	}
}

func TestLineAssemblerKeepsCarriageReturn(t *testing.T) {
	got := feed(newLineAssembler("t", 100), "one\r\ntwo\r\n")
	want := []LogEntry{line("one\r"), line("two\r")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestLineAssemblerCapBoundary(t *testing.T) {
	const max = 8
	exact := feed(newLineAssembler("t", max), "12345678\n")
	if !reflect.DeepEqual(exact, []LogEntry{line("12345678")}) {
		t.Errorf("exactly max: got %v", exact)
	}

	over := feed(newLineAssembler("t", max), "123456789\nnext\n")
	want := []LogEntry{marker(9), line("next")}
	if !reflect.DeepEqual(over, want) {
		t.Errorf("max+1: got %v, want %v", over, want)
	}
}

func TestLineAssemblerOverCapGivesOneMarkerAcrossManyChunks(t *testing.T) {
	a := newLineAssembler("t", 8)
	got := feed(a, "1234", "5678", "9", "abcdefgh", "ijkl", "\nok\n")
	if len(got) != 2 {
		t.Fatalf("got %d entries %v, want a marker then one line", len(got), got)
	}
	if !got[0].Truncated || got[0].Line != nil || got[0].Dropped < 9 {
		t.Errorf("marker = %+v, want Truncated, nil Line, Dropped >= 9", got[0])
	}
	if string(got[1].Line) != "ok" {
		t.Errorf("line after marker = %q, want ok", got[1].Line)
	}
}

func TestLineAssemblerNeverEmitsOverCapBytes(t *testing.T) {
	a := newLineAssembler("t", 4)
	for _, e := range feed(a, "abcdefghij", "klmn\n", "xy\n") {
		if len(e.Line) > 4 {
			t.Errorf("emitted %d byte line, over the cap", len(e.Line))
		}
	}
}

func TestLineAssemblerPendingCapacityStaysWithinCap(t *testing.T) {
	a := newLineAssembler("t", 10)
	feed(a, "123456789")
	if cap(a.pending) > 10 {
		t.Errorf("cap(pending) = %d, want <= 10", cap(a.pending))
	}
}

func TestLineAssemblerLinesDoNotAlias(t *testing.T) {
	a := newLineAssembler("t", 100)
	first := feed(a, "aaaa\n")[0]
	feed(a, "bbbb\n")
	if string(first.Line) != "aaaa" {
		t.Errorf("earlier line changed to %q", first.Line)
	}
}

func TestLineAssemblerCut(t *testing.T) {
	t.Run("pending bytes give one marker", func(t *testing.T) {
		a := newLineAssembler("t", 100)
		feed(a, "abc")
		if got := cutAll(a); !reflect.DeepEqual(got, []LogEntry{marker(3)}) {
			t.Errorf("got %v", got)
		}
		if got := feed(a, "x\n"); !reflect.DeepEqual(got, []LogEntry{line("x")}) {
			t.Errorf("after cut: got %v, want the new line only", got)
		}
	})
	t.Run("nothing pending gives nothing", func(t *testing.T) {
		a := newLineAssembler("t", 100)
		feed(a, "abc\n")
		if got := cutAll(a); len(got) != 0 {
			t.Errorf("got %v, want none", got)
		}
	})
	t.Run("after a marker gives nothing more", func(t *testing.T) {
		a := newLineAssembler("t", 4)
		feed(a, "123456")
		if got := cutAll(a); len(got) != 0 {
			t.Errorf("got %v, want none", got)
		}
		if got := feed(a, "ok\n"); !reflect.DeepEqual(got, []LogEntry{line("ok")}) {
			t.Errorf("after cut: got %v", got)
		}
	})
	t.Run("skipping fragment gives its count", func(t *testing.T) {
		a := newLineAssembler("t", 100)
		a.skipFragment()
		feed(a, "abcd")
		if got := cutAll(a); !reflect.DeepEqual(got, []LogEntry{marker(4)}) {
			t.Errorf("got %v", got)
		}
	})
	t.Run("skipping with nothing seen gives nothing", func(t *testing.T) {
		a := newLineAssembler("t", 100)
		a.skipFragment()
		if got := cutAll(a); len(got) != 0 {
			t.Errorf("got %v", got)
		}
	})
}

func TestLineAssemblerFragmentSkip(t *testing.T) {
	t.Run("ends at newline", func(t *testing.T) {
		a := newLineAssembler("t", 100)
		a.skipFragment()
		got := feed(a, "rest", "of\nnext\n")
		want := []LogEntry{marker(7), line("next")}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
	t.Run("ends at the cap", func(t *testing.T) {
		a := newLineAssembler("t", 4)
		a.skipFragment()
		got := feed(a, "abc", "de", "fgh\nnext\n")
		want := []LogEntry{marker(5), line("next")}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestLineAssemblerStopsWhenEmitDeclines(t *testing.T) {
	a := newLineAssembler("t", 100)
	calls := 0
	ok := a.write([]byte("a\nb\nc\n"), func(LogEntry) bool { calls++; return false })
	if ok || calls != 1 {
		t.Errorf("ok = %v, calls = %d, want false and 1", ok, calls)
	}
}

func TestSaturatingAdd(t *testing.T) {
	if got := saturatingAdd(math.MaxInt64-1, 5); got != math.MaxInt64 {
		t.Errorf("got %d, want MaxInt64", got)
	}
	if got := saturatingAdd(math.MaxInt64, 1); got != math.MaxInt64 {
		t.Errorf("got %d, want MaxInt64", got)
	}
	if got := saturatingAdd(3, 4); got != 7 {
		t.Errorf("got %d, want 7", got)
	}
}

func TestLineAssemblerDroppedSaturates(t *testing.T) {
	a := newLineAssembler("t", 4)
	a.skipFragment()
	a.dropped = math.MaxInt64 - 1
	a.markerSent = true // already reported; the counter must still not overflow
	feed(a, "abcdefgh")
	if a.dropped != math.MaxInt64 {
		t.Errorf("dropped = %d, want MaxInt64", a.dropped)
	}
}
