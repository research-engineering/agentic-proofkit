package npmpack

import (
	"strings"
	"testing"
)

func TestDecodeNPM12ReportRequiresOneIdentityBoundRecord(t *testing.T) {
	valid := `{"@research-engineering/agentic-proofkit":{"filename":"package.tgz","id":"@research-engineering/agentic-proofkit@1.2.3","integrity":"sha512-value","name":"@research-engineering/agentic-proofkit","shasum":"abc","version":"1.2.3"}}`
	record, err := DecodeNPM12Report(strings.NewReader(valid), int64(len(valid)))
	if err != nil {
		t.Fatalf("DecodeNPM12Report(valid) error = %v", err)
	}
	if record.Name != "@research-engineering/agentic-proofkit" || record.ID != "@research-engineering/agentic-proofkit@1.2.3" {
		t.Fatalf("DecodeNPM12Report(valid) = %#v", record)
	}
	const sentinel = "sk-proj-abcdefghijklmnop"
	invalidID := strings.Replace(valid, record.ID, sentinel, 1)
	_, err = DecodeNPM12Report(strings.NewReader(invalidID), int64(len(invalidID)))
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("expected an ID admission refusal without disclosure, got %v", err)
	}

	for _, test := range []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "legacy array root",
			value: `[{"filename":"package.tgz","integrity":"sha512-value","name":"@research-engineering/agentic-proofkit","shasum":"abc","version":"1.2.3"}]`,
			want:  "invalid JSON value type",
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

func TestDecodeNPM12ReportDoesNotExposeUnadmittedKeysInTypeErrors(t *testing.T) {
	const key = "UNADMITTED_KEY_MARKER"
	const input = `{"` + key + `":{"version":7}}`
	_, err := DecodeNPM12Report(strings.NewReader(input), int64(len(input)))
	if err == nil || !strings.Contains(err.Error(), "invalid JSON value type") || strings.Contains(err.Error(), key) {
		t.Fatalf("expected a bounded JSON type diagnostic without the caller key, got %v", err)
	}
}
