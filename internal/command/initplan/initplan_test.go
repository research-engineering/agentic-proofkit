package initplan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildEmitsDryRunDecisionRoutes(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.029604058402699797876482176530432798172890455890181537273269246789159546473190")
	record, err := Build("fresh")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if record.ReportKind != reportKind || record.State != "passed" {
		t.Fatalf("unexpected record: %#v", record)
	}
	if record.Summary["selectedPreset"] != "fresh" || record.Summary["dryRunOnly"] != true {
		t.Fatalf("summary does not describe dry-run fresh route: %#v", record.Summary)
	}
	encoded, err := json.Marshal(record.JSONValue())
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	for _, unexpected := range []string{"repoRoot", "merge_ready"} {
		if strings.Contains(string(encoded), unexpected) {
			t.Fatalf("init report overclaims or implies repository access: %s", encoded)
		}
	}
}

func TestBuildRejectsUnknownPreset(t *testing.T) {
	_, err := Build("unknown")
	if err == nil || !strings.Contains(err.Error(), "init --preset must be") {
		t.Fatalf("Build() error=%v, want preset rejection", err)
	}
}
