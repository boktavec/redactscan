//go:build darwin || linux

package quarantine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/boktavec/redactscan/internal/safefs"
)

const (
	filePerm        fs.FileMode = 0o600
	tempPrefix                  = ".tmp-"
	metaTempPrefix              = ".meta-"
	metaTempSuffix              = ".tmp"
	contentName                 = "content"
	metadataName                = "metadata.json"
	maxNameTries                = 10
	readdirBatch                = 256
	idPlaceholder               = "0000000000000000000000000000000000000000000000000000000000000000-0000000000000000"
	hashPlaceholder             = "0000000000000000000000000000000000000000000000000000000000000000"
)

// Test seams, as in safefs: production never changes them.
var (
	// randSuffix returns 16 lowercase hex characters.
	randSuffix = func() string {
		var b [idSuffixLen / 2]byte
		_, _ = rand.Read(b[:]) // never fails since Go 1.24
		return hex.EncodeToString(b[:])
	}
	now = time.Now
	// sourceReader wraps the source so tests can grow or shrink it after fstat.
	sourceReader = func(r io.Reader) io.Reader { return r }
	// afterStep runs after each completed Put step; a non-nil error simulates
	// an OS failure at that point (it is wrapped like one).
	afterStep = func(string) error { return nil }
)

// Put copies src into a new quarantine entry and returns its ID. src must be
// a regular file (callers open it with safefs.OpenRegular); it is read from
// offset 0 with ReadAt, so a source the caller already read is stored whole.
// The caller keeps ownership and closes it. The entry is
// complete only once metadata.json exists; on failure Put removes what it
// created and returns a fixed-text error. Findings in in must come from
// scanner.Registry.Run: Put does not re-run the redactor over finding strings.
//
// The budget check is not serialized: concurrent Puts can exceed it.
func (s *Store) Put(src *os.File, in Input) (id string, err error) {
	if err := validateInput(in); err != nil {
		return "", err
	}
	if src == nil {
		return "", ErrInvalidInput
	}
	fi, err := src.Stat()
	if err != nil {
		return "", newOpError("fstat source", err)
	}
	if !fi.Mode().IsRegular() {
		return "", ErrInvalidInput
	}
	size := fi.Size()
	if size > s.opts.MaxEntrySize {
		return "", ErrTooLarge
	}
	meta := Metadata{
		SchemaVersion: SchemaVersion, ID: idPlaceholder, SHA256: hashPlaceholder, Size: size,
		CreatedAt: now().UTC().Truncate(time.Second),
		Source:    in.Source, Name: in.Name, Decision: in.Decision, Findings: in.Findings,
	}
	// ID, hash and time are fixed width, so this is the final length.
	pre, err := encodeMetadata(meta)
	if err != nil {
		return "", err
	}
	if err := s.checkBudget(size + int64(len(pre))); err != nil {
		return "", err
	}

	tmp, sum, err := s.copyToTemp(src, size)
	if err != nil {
		return "", err
	}
	e := &pendingEntry{s: s, tmp: tmp}
	defer func() {
		if err != nil {
			e.abort()
		}
		e.close()
	}()
	if id, err = e.reserve(hex.EncodeToString(sum)); err != nil {
		return "", err
	}
	meta.ID, meta.SHA256 = id, id[:idHashLen]
	if err = e.publish(meta); err != nil {
		return "", err
	}
	return id, nil
}

// checkBudget refuses the Put when the entry count or byte budget would be
// exceeded. Each entry counts its content and metadata.json, and orphan .tmp-*
// files count; unknown names are ignored. incoming is the content plus
// metadata size about to be written. Nothing has been created yet.
func (s *Store) checkBudget(incoming int64) error {
	d, err := s.qroot.Open(".")
	if err != nil {
		return newOpError("list", err)
	}
	defer func() { _ = d.Close() }()
	var entries int
	var used int64
	for {
		names, err := d.Readdirnames(readdirBatch)
		for _, name := range names {
			var paths []string
			switch {
			case ValidID(name):
				entries++
				paths = []string{name + "/" + contentName, name + "/" + metadataName}
			case strings.HasPrefix(name, tempPrefix):
				paths = []string{name}
			default:
				continue
			}
			if entries >= s.opts.MaxEntries {
				return ErrStoreFull
			}
			for _, path := range paths {
				n, err := s.lstatSize(path)
				if err != nil {
					return err
				}
				used += n
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return newOpError("list", err)
		}
	}
	if used > s.opts.MaxStoreBytes || incoming > s.opts.MaxStoreBytes-used {
		return ErrStoreFull
	}
	return nil
}

// lstatSize returns the size of path in the quarantine root, 0 if missing.
func (s *Store) lstatSize(path string) (int64, error) {
	fi, err := s.qroot.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return 0, nil
	case err != nil:
		return 0, newOpError("lstat", err)
	}
	return fi.Size(), nil
}

// createTemp exclusively creates a 0600 file named prefix+rand+suffix in
// root, retrying a colliding name.
func createTemp(root *os.Root, prefix, suffix string) (*os.File, string, error) {
	for range maxNameTries {
		name := prefix + randSuffix() + suffix
		f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", newOpError("create temp", err)
		}
		if err := f.Chmod(filePerm); err != nil { // never rely on the umask
			_ = f.Close()
			_ = root.Remove(name)
			return nil, "", newOpError("chmod", err)
		}
		return f, name, nil
	}
	return nil, "", ErrIDExhausted
}

// copyToTemp streams src into a fresh .tmp- file in the quarantine root and
// returns its name and SHA-256. The temp file is removed on any error.
func (s *Store) copyToTemp(src *os.File, size int64) (name string, sum []byte, err error) {
	f, tmp, err := createTemp(s.qroot, tempPrefix, "")
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if err != nil {
			_ = s.qroot.Remove(tmp)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), sourceReader(io.NewSectionReader(src, 0, size+1)))
	if err != nil {
		_ = f.Close()
		return "", nil, newOpError("copy", err)
	}
	if n != size {
		_ = f.Close()
		return "", nil, ErrSourceChanged
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", nil, newOpError("fsync", err)
	}
	if err := f.Close(); err != nil {
		return "", nil, newOpError("close", err)
	}
	if err := afterStep("copied"); err != nil {
		return "", nil, newOpError("copied", err)
	}
	return tmp, h.Sum(nil), nil
}

// pendingEntry tracks only what this Put created so a failure removes exactly
// that: a pre-existing content or metadata.json is never touched.
type pendingEntry struct {
	s        *Store
	tmp      string // content temp name in the quarantine root; "" once removed
	id       string
	dir      *os.File
	root     *os.Root
	content  bool // we linked content
	metaTmp  string
	metadata bool // we linked metadata.json
}

// reserve creates the entry directory <hash>-<rand16> exclusively at 0700.
func (e *pendingEntry) reserve(hash string) (string, error) {
	for range maxNameTries {
		id := hash + "-" + randSuffix()
		err := e.s.qroot.Mkdir(id, dirMode)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", newOpError("mkdir", err)
		}
		e.id = id
		return id, e.open()
	}
	return "", ErrIDExhausted
}

func (e *pendingEntry) open() error {
	fi, err := e.s.qroot.Lstat(e.id)
	if err != nil {
		return newOpError("lstat", err)
	}
	if e.dir, e.root, err = safefs.OpenChildDir(e.s.qroot, e.id, fi); err != nil {
		return err
	}
	if err := e.dir.Chmod(dirMode); err != nil { // never rely on the umask
		return newOpError("chmod", err)
	}
	if err := e.s.qdir.Sync(); err != nil {
		return newOpError("fsync", err)
	}
	return hook("reserved")
}

// publish places content, then metadata.json: the entry is complete only when
// the second link succeeds.
func (e *pendingEntry) publish(meta Metadata) error {
	if err := link(e.s.qroot, e.tmp, e.id+"/"+contentName); err != nil {
		return err
	}
	e.content = true
	if err := e.s.qroot.Remove(e.tmp); err != nil {
		return newOpError("remove temp", err)
	}
	e.tmp = ""
	if err := e.dir.Sync(); err != nil { // content durable before metadata
		return newOpError("fsync", err)
	}
	if err := hook("content-placed"); err != nil {
		return err
	}
	data, err := encodeMetadata(meta)
	if err != nil {
		return err
	}
	if err := e.writeMetaTemp(data); err != nil {
		return err
	}
	if err := link(e.root, e.metaTmp, metadataName); err != nil {
		return err
	}
	e.metadata = true
	if err := e.root.Remove(e.metaTmp); err != nil {
		return newOpError("remove temp", err)
	}
	e.metaTmp = ""
	if err := e.dir.Sync(); err != nil {
		return newOpError("fsync", err)
	}
	if err := e.s.qdir.Sync(); err != nil {
		return newOpError("fsync", err)
	}
	return hook("published")
}

func (e *pendingEntry) writeMetaTemp(data []byte) error {
	f, name, err := createTemp(e.root, metaTempPrefix, metaTempSuffix)
	if err != nil {
		return err
	}
	e.metaTmp = name
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return newOpError("write", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return newOpError("fsync", err)
	}
	if err := f.Close(); err != nil {
		return newOpError("close", err)
	}
	return hook("metadata-written")
}

// abort removes what this Put created, best effort. A failure leaves an
// incomplete entry (no metadata.json) that Read reports as ErrIncomplete.
func (e *pendingEntry) abort() {
	if e.tmp != "" {
		_ = e.s.qroot.Remove(e.tmp)
	}
	if e.id != "" {
		if e.root != nil {
			if e.metadata {
				_ = e.root.Remove(metadataName)
			}
			if e.metaTmp != "" {
				_ = e.root.Remove(e.metaTmp)
			}
		}
		if e.content {
			_ = e.s.qroot.Remove(e.id + "/" + contentName)
		}
		_ = e.s.qroot.Remove(e.id) // fails, harmlessly, if anything else is inside
	}
}

func (e *pendingEntry) close() {
	if e.root != nil {
		_ = e.root.Close()
	}
	if e.dir != nil {
		_ = e.dir.Close()
	}
}

func hook(step string) error {
	if err := afterStep(step); err != nil {
		return newOpError(step, err)
	}
	return nil
}

// link is a no-replace hard link: an existing target is ErrEntryExists and is
// left unchanged.
func link(root *os.Root, oldname, newname string) error {
	err := root.Link(oldname, newname)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.EEXIST):
		return ErrEntryExists
	}
	return newOpError("link", err)
}
