package npmpack

import (
	"strings"
	"testing"
)

func TestDecodeNPM12ReportRequiresOneIdentityBoundRecord(t *testing.T) {
	valid := `{"@research-engineering/agentic-proofkit":{"filename":"package.tgz","integrity":"sha512-value","name":"@research-engineering/agentic-proofkit","shasum":"abc","version":"1.2.3"}}`
	record, err := DecodeNPM12Report(strings.NewReader(valid), int64(len(valid)))
	if err != nil {
		t.Fatalf("DecodeNPM12Report(valid) error = %v", err)
	}
	if record.Name != "@research-engineering/agentic-proofkit" {
		t.Fatalf("DecodeNPM12Report(valid) = %#v", record)
	}

	for _, test := range []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "legacy array root",
			value: `[{"filename":"package.tgz","integrity":"sha512-value","name":"@research-engineering/agentic-proofkit","shasum":"abc","version":"1.2.3"}]`,
			want:  "cannot unmarshal array",
		},
		{
			name:  "mismatched key",
			value: `{"other":{"filename":"package.tgz","integrity":"sha512-value","name":"@research-engineering/agentic-proofkit","shasum":"abc","version":"1.2.3"}}`,
			want:  "key must equal",
		},
		{
			name:  "multiple records",
			value: `{"first":{"filename":"first.tgz","integrity":"sha512-first","name":"first","shasum":"first","version":"1.0.0"},"second":{"filename":"second.tgz","integrity":"sha512-second","name":"second","shasum":"second","version":"1.0.0"}}`,
			want:  "exactly one",
		},
		{
			name:  "duplicate key",
			value: `{"first":{"name":"first"},"first":{"name":"first"}}`,
			want:  "duplicate object key",
		},
		{
			name:  "missing required identity",
			value: `{"first":{"filename":"first.tgz","integrity":"sha512-first","name":"first","shasum":"first"}}`,
			want:  "version must be non-empty text",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeNPM12Report(strings.NewReader(test.value), int64(len(test.value)))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("DecodeNPM12Report() error = %v, want %q", err, test.want)
			}
		})
	}
}
