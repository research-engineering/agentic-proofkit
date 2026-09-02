package main

import (
	"strings"
	"testing"
)

func TestDecodeNPM12PackOutputRequiresOneIdentityBoundRecord(t *testing.T) {
	valid := []byte("{\"@research-engineering/agentic-proofkit\":{\"filename\":\"package.tgz\",\"integrity\":\"sha512-value\",\"name\":\"@research-engineering/agentic-proofkit\",\"shasum\":\"abc\",\"version\":\"1.2.3\"}}")
	records, err := decodeNPM12PackOutput(valid)
	if err != nil {
		t.Fatalf("decodeNPM12PackOutput(valid) error = %v", err)
	}
	if len(records) != 1 || records[0].Name != "@research-engineering/agentic-proofkit" {
		t.Fatalf("decodeNPM12PackOutput(valid) = %#v", records)
	}

	for _, test := range []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "legacy array root",
			value: "[{\"filename\":\"package.tgz\",\"integrity\":\"sha512-value\",\"name\":\"@research-engineering/agentic-proofkit\",\"shasum\":\"abc\",\"version\":\"1.2.3\"}]",
			want:  "cannot unmarshal array",
		},
		{
			name:  "mismatched key",
			value: "{\"other\":{\"filename\":\"package.tgz\",\"integrity\":\"sha512-value\",\"name\":\"@research-engineering/agentic-proofkit\",\"shasum\":\"abc\",\"version\":\"1.2.3\"}}",
			want:  "key must equal",
		},
		{
			name:  "multiple records",
			value: "{\"first\":{\"name\":\"first\"},\"second\":{\"name\":\"second\"}}",
			want:  "exactly one",
		},
		{
			name:  "duplicate key",
			value: "{\"first\":{\"name\":\"first\"},\"first\":{\"name\":\"first\"}}",
			want:  "duplicate object key",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeNPM12PackOutput([]byte(test.value))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decodeNPM12PackOutput() error = %v, want %q", err, test.want)
			}
		})
	}
}
