package logs

import (
	"bytes"
	"math"
)

// lineAssembler turns byte chunks into complete lines and drop markers. It does
// no I/O and holds at most max bytes of a pending line.
//
// A line over max, and a fragment being skipped, are never emitted: each gives
// one marker. Dropped is a lower bound on the line's length (see LogEntry).
type lineAssembler struct {
	source string
	max    int

	pending    []byte // the unfinished line, len <= max
	skipping   bool   // discard bytes until the next "\n"
	markerSent bool   // the line being skipped already has its marker
	dropped    int64  // bytes discarded while skipping
}

func newLineAssembler(source string, maxLineBytes int) *lineAssembler {
	return &lineAssembler{source: source, max: maxLineBytes}
}

// skipFragment discards everything up to and including the next "\n". It is
// used when reading starts in the middle of a line.
func (a *lineAssembler) skipFragment() {
	a.skipping = true
	a.markerSent = false
	a.dropped = 0
}

// write feeds chunk and calls emit for each resulting entry in order. It stops
// and returns false as soon as emit returns false.
func (a *lineAssembler) write(chunk []byte, emit func(LogEntry) bool) bool {
	for len(chunk) > 0 {
		nl := bytes.IndexByte(chunk, '\n')
		segment := len(chunk) // bytes of this line within chunk, excluding "\n"
		if nl >= 0 {
			segment = nl
		}
		var ok bool
		if a.skipping {
			ok = a.skip(segment, nl >= 0, emit)
		} else {
			ok = a.collect(chunk[:segment], nl >= 0, emit)
		}
		if !ok {
			return false
		}
		if nl < 0 {
			return true
		}
		chunk = chunk[nl+1:]
	}
	return true
}

// skip discards segment bytes (plus the "\n" when terminated).
func (a *lineAssembler) skip(segment int, terminated bool, emit func(LogEntry) bool) bool {
	n := segment
	if terminated {
		n++
	}
	a.dropped = saturatingAdd(a.dropped, n)
	if !a.markerSent && (terminated || a.dropped > int64(a.max)) {
		a.markerSent = true
		if !emit(a.marker(a.dropped)) {
			return false
		}
	}
	if terminated {
		a.reset()
	}
	return true
}

// collect adds a line segment to pending, emitting the line when terminated.
func (a *lineAssembler) collect(segment []byte, terminated bool, emit func(LogEntry) bool) bool {
	if len(a.pending)+len(segment) > a.max {
		dropped := saturatingAdd(int64(len(a.pending)), len(segment))
		a.pending = a.pending[:0]
		if !terminated {
			a.skipping, a.markerSent, a.dropped = true, true, dropped
		}
		return emit(a.marker(dropped))
	}
	a.grow(len(segment))
	a.pending = append(a.pending, segment...)
	if !terminated {
		return true
	}
	line := make([]byte, len(a.pending))
	copy(line, a.pending)
	a.pending = a.pending[:0]
	return emit(LogEntry{Source: a.source, Line: line})
}

// grow makes room for n more bytes without letting capacity pass max.
func (a *lineAssembler) grow(n int) {
	need := len(a.pending) + n
	if need <= cap(a.pending) {
		return
	}
	newCap := min(max(2*cap(a.pending), need), a.max)
	pending := make([]byte, len(a.pending), newCap)
	copy(pending, a.pending)
	a.pending = pending
}

// cut ends the current line without a "\n" (truncation or rotation): unfinished
// bytes give one marker unless the line already has one.
func (a *lineAssembler) cut(emit func(LogEntry) bool) bool {
	var dropped int64
	switch {
	case a.markerSent:
	case len(a.pending) > 0:
		dropped = int64(len(a.pending))
	case a.skipping:
		dropped = a.dropped
	}
	a.reset()
	if dropped == 0 {
		return true
	}
	return emit(a.marker(dropped))
}

func (a *lineAssembler) reset() {
	a.pending = a.pending[:0]
	a.skipping, a.markerSent, a.dropped = false, false, 0
}

func (a *lineAssembler) marker(dropped int64) LogEntry {
	return LogEntry{Source: a.source, Truncated: true, Dropped: dropped}
}

func saturatingAdd(total int64, n int) int64 {
	if total > math.MaxInt64-int64(n) {
		return math.MaxInt64
	}
	return total + int64(n)
}
