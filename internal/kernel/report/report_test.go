package report

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestBuildSelfCheckReportStableShape(t *testing.T) {
	report := BuildSelfCheckReport(map[string]any{"input": "value"}).JSONValue()
	serialized, err := stablejson.Marshal(report)
	if err != nil {
		t.Fatalf("stable marshal report: %v", err)
	}
	expected := `{
  "diagnostics": [
    {
      "key": "inputKind",
      "value": "object"
    }
  ],
  "nonClaims": [
    "Go self-check does not replace the full package gate.",
    "Go self-check does not execute native witnesses, read repository state, approve merge, or publish artifacts."
  ],
  "reportId": "proofkit.go-runtime.self-check",
  "reportKind": "proofkit.go-runtime.self-check",
  "ruleResults": [
    {
      "diagnostics": [],
      "message": "Go bootstrap runtime parsed explicit JSON input and emitted a deterministic report.",
      "ruleId": "proofkit.go-runtime.self-check.explicit-input",
      "status": "passed"
    }
  ],
  "schemaVersion": 1,
  "state": "passed",
  "summary": {
    "inputKind": "object"
  }
}
`
	if string(serialized) != expected {
		t.Fatalf("self-check report drift:\n%s", serialized)
	}
}

func TestBuildSelfCheckReportClassifiesInputKinds(t *testing.T) {
	cases := []struct {
		name  string
		input any
		want  string
	}{
		{name: "null", input: nil, want: `"inputKind": "null"`},
		{name: "boolean", input: true, want: `"inputKind": "boolean"`},
		{name: "string", input: "value", want: `"inputKind": "string"`},
		{name: "array", input: []any{}, want: `"inputKind": "array"`},
		{name: "object", input: map[string]any{}, want: `"inputKind": "object"`},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			serialized, err := stablejson.Marshal(BuildSelfCheckReport(item.input).JSONValue())
			if err != nil {
				t.Fatalf("stable marshal report: %v", err)
			}
			if !strings.Contains(string(serialized), item.want) {
				t.Fatalf("report=%s, want %s", serialized, item.want)
			}
		})
	}
}
