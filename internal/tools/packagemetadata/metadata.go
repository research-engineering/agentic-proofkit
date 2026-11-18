package packagemetadata

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
)

const MaximumBytes = 16 << 20

type Record struct {
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description"`
	License     string     `json:"license"`
	Repository  Repository `json:"repository"`
}

type Repository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Raw messages distinguish absence from null without normalizing string values.
type rawRecord struct {
	Name        json.RawMessage `json:"name"`
	Version     json.RawMessage `json:"version"`
	Description json.RawMessage `json:"description"`
	License     json.RawMessage `json:"license"`
	Repository  json.RawMessage `json:"repository"`
}

type rawRepository struct {
	Type json.RawMessage `json:"type"`
	URL  json.RawMessage `json:"url"`
}

func Read(root string) (Record, error) {
	content, err := artifactfile.ReadBounded(root, "package.json", MaximumBytes)
	if err != nil {
		return Record{}, fmt.Errorf("read package metadata failed: %w", err)
	}
	return Admit(content)
}

func Admit(content []byte) (Record, error) {
	raw, err := admission.DecodeTypedJSON[*rawRecord](bytes.NewReader(content), MaximumBytes)
	if err != nil {
		return Record{}, fmt.Errorf("package metadata JSON admission failed")
	}
	if raw == nil {
		return Record{}, fmt.Errorf("package metadata must be an object")
	}
	var repository rawRepository
	if len(raw.Repository) != 0 {
		if raw.Repository[0] != '{' {
			return Record{}, fmt.Errorf("package metadata repository must be an object")
		}
		repository, err = admission.DecodeTypedJSON[rawRepository](bytes.NewReader(raw.Repository), MaximumBytes)
		if err != nil {
			return Record{}, fmt.Errorf("package metadata repository JSON admission failed")
		}
	}
	var record Record
	for _, field := range []struct {
		label string
		raw   json.RawMessage
		value *string
	}{
		{"name", raw.Name, &record.Name},
		{"version", raw.Version, &record.Version},
		{"description", raw.Description, &record.Description},
		{"license", raw.License, &record.License},
		{"repository.type", repository.Type, &record.Repository.Type},
		{"repository.url", repository.URL, &record.Repository.URL},
	} {
		if len(field.raw) == 0 {
			continue
		}
		if field.raw[0] != '"' {
			return Record{}, fmt.Errorf("package metadata %s must be a string", field.label)
		}
		if err := json.Unmarshal(field.raw, field.value); err != nil {
			return Record{}, fmt.Errorf("package metadata %s must be a string", field.label)
		}
		if admit.ContainsSecretLikeValue(*field.value) {
			return Record{}, fmt.Errorf("package metadata %s contains a secret-like value", field.label)
		}
	}
	return record, nil
}
