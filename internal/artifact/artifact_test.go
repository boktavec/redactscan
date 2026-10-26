package artifact

import (
	"errors"
	"testing"
)

func TestArtifactValidate(t *testing.T) {
	t.Parallel()
	if err := (Artifact{}).Validate(); err != nil {
		t.Errorf("zero Artifact: Validate() = %v", err)
	}
	if err := (Artifact{Metadata: map[string]any{"k": "v"}}).Validate(); err != nil {
		t.Errorf("valid metadata: Validate() = %v", err)
	}
}

func TestArtifactValidateBadMetadata(t *testing.T) {
	t.Parallel()
	err := Artifact{Metadata: map[string]any{"k": []byte("x")}}.Validate()
	if !errors.Is(err, ErrInvalidArtifact) || !errors.Is(err, ErrInvalidMetadata) {
		t.Errorf("err = %v, want both ErrInvalidArtifact and ErrInvalidMetadata", err)
	}
}
