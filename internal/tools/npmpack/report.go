package npmpack

import (
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

type Record struct {
	Filename  string `json:"filename"`
	ID        string `json:"id,omitempty"`
	Integrity string `json:"integrity"`
	Name      string `json:"name"`
	Shasum    string `json:"shasum"`
	Version   string `json:"version"`
}

func DecodeNPM12Report(reader io.Reader, maxBytes int64) (Record, error) {
	keyed, err := admission.DecodeTypedJSON[map[string]Record](reader, maxBytes)
	if err != nil {
		return Record{}, err
	}
	if len(keyed) != 1 {
		return Record{}, fmt.Errorf("npm pack report must contain exactly one keyed record")
	}
	for key, record := range keyed {
		if key != record.Name {
			return Record{}, fmt.Errorf("npm pack report key must equal the record package name")
		}
		for _, field := range []struct {
			name  string
			value string
		}{
			{name: "filename", value: record.Filename},
			{name: "integrity", value: record.Integrity},
			{name: "name", value: record.Name},
			{name: "shasum", value: record.Shasum},
			{name: "version", value: record.Version},
		} {
			if _, err := admit.NonEmptyText(field.value, "npm pack report "+field.name); err != nil {
				return Record{}, err
			}
		}
		return record, nil
	}
	return Record{}, fmt.Errorf("npm pack report must contain exactly one keyed record")
}
