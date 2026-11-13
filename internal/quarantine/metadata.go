package quarantine

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"
	"strings"
	"time"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
)

// createdAtLayout is the only accepted created_at format (UTC, seconds).
const createdAtLayout = "2006-01-02T15:04:05Z"

// Finding metadata value types (spec D12). Typing each value keeps integers
// above 2^53 exact, which a float64 detour would not.
const (
	typeString  = "string"
	typeBool    = "bool"
	typeInt     = "int"
	typeInt64   = "int64"
	typeFloat64 = "float64"
)

type recordDTO struct {
	SchemaVersion int          `json:"schema_version"`
	ID            string       `json:"id"`
	SHA256        string       `json:"sha256"`
	Size          *int64       `json:"size"` // pointer: absent must be corrupt, not 0
	CreatedAt     string       `json:"created_at"`
	Source        sourceDTO    `json:"source"`
	Name          string       `json:"name"`
	Decision      string       `json:"decision"`
	Findings      []findingDTO `json:"findings"`
}

type sourceDTO struct {
	Type string `json:"type"`
	URI  string `json:"uri"`
}

type findingDTO struct {
	ID          string        `json:"id"`
	Severity    string        `json:"severity"`
	Category    string        `json:"category"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	ArtifactID  string        `json:"artifact_id"`
	File        string        `json:"file"`
	Line        int           `json:"line"`
	Evidence    string        `json:"evidence"`
	Metadata    []metaItemDTO `json:"metadata"`
}

type metaItemDTO struct {
	Key   string         `json:"key"`
	Type  string         `json:"type"`
	Value jsontext.Value `json:"value"`
}

// encodeMetadata validates m and returns metadata.json bytes. Over
// MaxMetadataBytes is ErrMetadataTooLarge: Put and Read share the cap, so
// Put never writes an entry that Read would refuse. Findings is always an
// array and finding metadata is sorted by key, so output is deterministic.
func encodeMetadata(m Metadata) ([]byte, error) {
	if validateFields(m) != nil {
		return nil, ErrInvalidInput
	}
	created := m.CreatedAt.UTC().Format(createdAtLayout)
	if !validCreatedAt(created) {
		return nil, ErrInvalidInput // e.g. year above 9999: decode would refuse it
	}
	dto := recordDTO{
		SchemaVersion: m.SchemaVersion,
		ID:            m.ID,
		SHA256:        m.SHA256,
		Size:          &m.Size,
		CreatedAt:     created,
		Source:        sourceDTO{Type: m.Source.Type, URI: m.Source.URI},
		Name:          m.Name,
		Decision:      string(m.Decision),
		Findings:      make([]findingDTO, 0, len(m.Findings)),
	}
	for _, f := range m.Findings {
		items, err := encodeItems(f.Metadata)
		if err != nil {
			return nil, ErrInvalidInput
		}
		dto.Findings = append(dto.Findings, findingDTO{
			ID: f.ID, Severity: f.Severity.String(), Category: f.Category, Title: f.Title,
			Description: f.Description, ArtifactID: f.ArtifactID, File: f.File, Line: f.Line,
			Evidence: f.Evidence, Metadata: items,
		})
	}
	data, err := json.Marshal(dto)
	if err != nil {
		return nil, ErrInvalidInput
	}
	if len(data) > MaxMetadataBytes {
		return nil, ErrMetadataTooLarge
	}
	return data, nil
}

func encodeItems(m map[string]any) ([]metaItemDTO, error) {
	items := make([]metaItemDTO, 0, len(m))
	for k, v := range m {
		var typ string
		switch v.(type) {
		case string:
			typ = typeString
		case bool:
			typ = typeBool
		case int:
			typ = typeInt
		case int64:
			typ = typeInt64
		case float64:
			typ = typeFloat64
		default:
			return nil, errInvalidRecord // unreachable after Validate
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, errInvalidRecord
		}
		items = append(items, metaItemDTO{Key: k, Type: typ, Value: raw})
	}
	slices.SortFunc(items, func(a, b metaItemDTO) int { return strings.Compare(a.Key, b.Key) })
	return items, nil
}

// decodeMetadata strictly decodes and validates metadata.json for the entry
// directory dirID. Every failure is ErrCorruptMetadata with no detail, and the
// returned Metadata is zero. json/v2 rejects duplicate members, case-variant
// names and trailing data; v1 encoding/json accepts all three, so it must
// not be used here.
func decodeMetadata(data []byte, dirID string) (Metadata, error) {
	if len(data) > MaxMetadataBytes {
		return Metadata{}, ErrCorruptMetadata
	}
	var dto recordDTO
	if err := json.Unmarshal(data, &dto, json.RejectUnknownMembers(true)); err != nil {
		return Metadata{}, ErrCorruptMetadata
	}
	m, err := dto.toMetadata()
	if err != nil || validateStored(m, dirID) != nil {
		return Metadata{}, ErrCorruptMetadata
	}
	return m, nil
}

// parseCreatedAt time.Parse also accepts fractions and offsets the layout
// lacks, so the exact stored format is required by formatting back.
func parseCreatedAt(s string) (time.Time, bool) {
	t, err := time.Parse(createdAtLayout, s)
	return t, err == nil && t.Format(createdAtLayout) == s
}

func validCreatedAt(s string) bool {
	_, ok := parseCreatedAt(s)
	return ok
}

func (d recordDTO) toMetadata() (Metadata, error) {
	created, ok := parseCreatedAt(d.CreatedAt)
	if !ok || d.Findings == nil || d.Size == nil {
		return Metadata{}, errInvalidRecord // null or absent findings or size is corrupt
	}
	m := Metadata{
		SchemaVersion: d.SchemaVersion,
		ID:            d.ID,
		SHA256:        d.SHA256,
		Size:          *d.Size,
		CreatedAt:     created,
		Source:        artifact.SourceMetadata{Type: d.Source.Type, URI: d.Source.URI},
		Name:          d.Name,
		Decision:      Decision(d.Decision),
		Findings:      make([]finding.Finding, 0, len(d.Findings)),
	}
	for _, fd := range d.Findings {
		f, err := fd.toFinding()
		if err != nil {
			return Metadata{}, err
		}
		m.Findings = append(m.Findings, f)
	}
	return m, nil
}

func (d findingDTO) toFinding() (finding.Finding, error) {
	sev, ok := parseSeverity(d.Severity)
	if !ok || len(d.Metadata) > artifact.MaxMetadataEntries {
		return finding.Finding{}, errInvalidRecord
	}
	f := finding.Finding{
		ID: d.ID, Severity: sev, Category: d.Category, Title: d.Title, Description: d.Description,
		ArtifactID: d.ArtifactID, File: d.File, Line: d.Line, Evidence: d.Evidence,
	}
	if len(d.Metadata) == 0 {
		return f, nil
	}
	f.Metadata = make(map[string]any, len(d.Metadata))
	for _, it := range d.Metadata {
		v, err := it.decodeValue()
		if _, dup := f.Metadata[it.Key]; dup || err != nil {
			return finding.Finding{}, errInvalidRecord
		}
		f.Metadata[it.Key] = v
	}
	return f, nil
}

// decodeValue decodes the value into exactly the declared Go type.
func (it metaItemDTO) decodeValue() (any, error) {
	if it.Value.Kind() == 'n' { // json/v2 would turn null into a zero value
		return nil, errInvalidRecord
	}
	switch it.Type {
	case typeString:
		return unmarshalAs[string](it.Value)
	case typeBool:
		return unmarshalAs[bool](it.Value)
	case typeInt:
		return unmarshalAs[int](it.Value)
	case typeInt64:
		return unmarshalAs[int64](it.Value)
	case typeFloat64:
		return unmarshalAs[float64](it.Value)
	}
	return nil, errInvalidRecord
}

func unmarshalAs[T any](raw jsontext.Value) (any, error) {
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, errInvalidRecord
	}
	return v, nil
}

// parseSeverity matches the five stored names exactly. finding.ParseSeverity
// is for trusted configuration and trims and folds case, which stored data
// must not get.
func parseSeverity(s string) (finding.Severity, bool) {
	for sev := finding.SeverityInfo; sev <= finding.SeverityCritical; sev++ {
		if sev.String() == s {
			return sev, true
		}
	}
	return finding.SeverityInvalid, false
}
