package builtin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
)

const hashChunkSize = 64 << 10

// Constant finding text for Hash (checked by tests).
const (
	hashCategory    = "hash"
	hashTitle       = "SHA-256 of file content"
	hashDescription = "SHA-256 digest of the bytes read during this scan."
)

// Hash reports the SHA-256 of the content as one info finding. The digest
// describes the bytes read during this scan, not the identity of the file.
type Hash struct{}

func (Hash) Name() string                    { return "hash" }
func (Hash) Supports(artifact.Artifact) bool { return true }

// Scan hashes exactly size bytes with a single reusable buffer, so memory use
// does not depend on size. It loops by hand instead of calling io.Copy, which
// could bypass the bounded reader through WriterTo or ReaderFrom.
func (Hash) Scan(ctx context.Context, a artifact.Artifact, r io.ReaderAt, size int64) ([]finding.Finding, error) {
	h := sha256.New()
	buf := make([]byte, hashChunkSize)
	for off := int64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chunk := buf[:min(int64(len(buf)), size-off)]
		if err := readFull(r, chunk, off); err != nil {
			return nil, err
		}
		h.Write(chunk)
		off += int64(len(chunk))
	}

	return []finding.Finding{{
		ID:          "hash.sha256",
		Severity:    finding.SeverityInfo,
		Category:    hashCategory,
		Title:       hashTitle,
		Description: hashDescription,
		ArtifactID:  a.ID,
		File:        a.RelativePath,
		Metadata:    map[string]any{"sha256": hex.EncodeToString(h.Sum(nil)), "size": size},
	}}, nil
}
