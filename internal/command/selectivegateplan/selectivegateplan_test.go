package selectivegateplan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildRejectsUnknownRootPolicyFields(t *testing.T) {
	input := validPlanInput()
	input["skipSecretScan"] = true

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("Build() error = %v, want unsupported field rejection", err)
	}
}

func TestBuildRejectsUnknownNestedPolicyFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "secret scan",
			mutate: func(input map[string]any) {
				input["secretScan"].(map[string]any)["skipOnFork"] = true
			},
		},
		{
			name: "generated artifact rule",
			mutate: func(input map[string]any) {
				input["generatedArtifactRules"] = []any{map[string]any{
					"command":               "agentic-proofkit generated-artifact-freshness",
					"generator":             "scripts/generate.go",
					"path":                  "docs/generated.md",
					"sourceOfTruthPatterns": []any{"docs/specs/**/*.json"},
					"skipFreshness":         true,
				}}
			},
		},
		{
			name: "unknown edge",
			mutate: func(input map[string]any) {
				edge := unknownEdgeInput("edge.dynamic", "dynamic_or_unknown")
				edge["silentFallback"] = true
				input["unknownEdges"] = []any{edge}
			},
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validPlanInput()
			item.mutate(input)
			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), "unsupported field") {
				t.Fatalf("Build() error=%v, want unsupported field rejection", err)
			}
		})
	}
}

func TestBuildAcceptsMinimalExplicitPlanInput(t *testing.T) {
	output, _, err := Build(validPlanInput())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !stringArrayContains(output["nonClaims"], "Selective gate plans do not execute commands, authenticate receipts, approve merge, or prove proof freshness.") {
		t.Fatalf("nonClaims missing command-owned boundary denial: %#v", output["nonClaims"])
	}
}

func TestBuildRejectsDisplayOnlyCommandShellControlTokens(t *testing.T) {
	input := validPlanInput()
	input["baseCommands"] = []any{planCommand("proofkit.base", "npm run check && curl example.test", "base")}
	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "display-only command text") {
		t.Fatalf("Build() error = %v, want display-only command rejection", err)
	}
}

func TestBuildFailsClosedForUncoveredUnknownEdge(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.114223091652506300873298948515061679816313892419980290837569919004743321148207")
	input := validPlanInput()
	input["unknownEdges"] = []any{unknownEdgeInput("edge.dynamic", "dynamic_or_unknown")}

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 1 || output["planState"] != "fail_closed" {
		t.Fatalf("Build() exitCode=%d planState=%v, want fail_closed", exitCode, output["planState"])
	}
	if !stringArrayContains(output["failures"], "unknown selective planner edge lacks declared fallback coverage: edge.dynamic (dynamic_or_unknown)") {
		t.Fatalf("failures do not include unknown-edge coverage failure: %#v", output["failures"])
	}
	edges := output["unknownEdges"].([]any)
	edge := edges[0].(map[string]any)
	if edge["coverageState"] != "uncovered" {
		t.Fatalf("coverageState=%v want uncovered", edge["coverageState"])
	}
}

func TestBuildUsesDeclaredFallbackForCoveredUnknownEdge(t *testing.T) {
	input := validPlanInput()
	input["unknownEdges"] = []any{unknownEdgeInput("edge.dynamic", "dynamic_or_unknown")}
	input["fallbackCoverage"] = []any{
		map[string]any{
			"command":     planCommand("full.workspace", "npm run check", "full_workspace"),
			"edgeClasses": []any{"dynamic_or_unknown"},
			"reason":      "Full workspace gate covers dynamic edges.",
		},
	}

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || output["planState"] != "ok" {
		t.Fatalf("Build() exitCode=%d planState=%v, want ok", exitCode, output["planState"])
	}
	if !commandIDExists(output["requiredCommands"], "full.workspace") {
		t.Fatalf("requiredCommands missing fallback command: %#v", output["requiredCommands"])
	}
	edges := output["unknownEdges"].([]any)
	edge := edges[0].(map[string]any)
	if edge["coverageState"] != "covered_by_declared_fallback" {
		t.Fatalf("coverageState=%v want covered_by_declared_fallback", edge["coverageState"])
	}
	if !stringArrayContains(edge["fallbackCommandIds"], "full.workspace") {
		t.Fatalf("fallbackCommandIds missing full.workspace: %#v", edge["fallbackCommandIds"])
	}
}

func TestBuildRejectsInvalidFallbackCoverage(t *testing.T) {
	cases := []struct {
		name     string
		coverage []any
		want     string
	}{
		{
			name: "empty edge classes",
			coverage: []any{map[string]any{
				"command":     planCommand("full.workspace", "npm run check", "full_workspace"),
				"edgeClasses": []any{},
				"reason":      "Full workspace gate covers dynamic edges.",
			}},
			want: "fallbackCoverage edgeClasses must not be empty",
		},
		{
			name: "unknown edge class",
			coverage: []any{map[string]any{
				"command":     planCommand("full.workspace", "npm run check", "full_workspace"),
				"edgeClasses": []any{"unknown_edge_class"},
				"reason":      "Full workspace gate covers dynamic edges.",
			}},
			want: "full.workspace fallbackCoverage edgeClasses must be one of",
		},
		{
			name: "duplicate command id",
			coverage: []any{
				map[string]any{"command": planCommand("full.workspace", "npm run check", "full_workspace"), "edgeClasses": []any{"dynamic_or_unknown"}, "reason": "First."},
				map[string]any{"command": planCommand("full.workspace", "npm run test", "full_workspace"), "edgeClasses": []any{"generated_source"}, "reason": "Second."},
			},
			want: "fallbackCoverage command id must be unique",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validPlanInput()
			input["fallbackCoverage"] = item.coverage
			_, exitCode, err := Build(input)
			if exitCode != 1 || err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Build() exitCode=%d error=%v, want %q", exitCode, err, item.want)
			}
		})
	}
}

func TestBuildRejectsUnknownEdgeClass(t *testing.T) {
	input := validPlanInput()
	input["unknownEdges"] = []any{unknownEdgeInput("edge.unknown", "unknown_edge_class")}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "selective gate unknown edge edge.unknown edgeClass must be one of") {
		t.Fatalf("Build() error=%v, want unknown edge-class rejection", err)
	}
}

func TestBuildAdmitsEveryProofVocabularySelectiveEdgeClass(t *testing.T) {
	for _, class := range proofvocab.SelectiveEdgeClasses() {
		t.Run(class, func(t *testing.T) {
			input := validPlanInput()
			input["unknownEdges"] = []any{unknownEdgeInput("edge."+class, class)}
			input["fallbackCoverage"] = []any{
				map[string]any{
					"command":     planCommand("full.workspace", "npm run check", "full_workspace"),
					"edgeClasses": []any{class},
					"reason":      "Full workspace gate covers this unknown edge class.",
				},
			}

			_, _, err := Build(input)
			if err != nil {
				t.Fatalf("Build() rejected owner selective edge class %q: %v", class, err)
			}
		})
	}
}

func validPlanInput() map[string]any {
	return map[string]any{
		"schemaVersion":               json.Number("1"),
		"archiveOrBinaryPathPatterns": []any{},
		"artifactIntegrityPolicies":   []any{},
		"baseCommands":                []any{planCommand("proofkit.base", "npm run check", "base")},
		"changedPaths":                []any{},
		"dependencyFreshness":         map[string]any{"command": "npm install --package-lock-only", "paths": []any{}},
		"fallbackCoverage":            []any{},
		"generatedArtifactRules":      []any{},
		"ignoredProofLikePaths":       []any{},
		"nonClaims":                   []any{"Selective gate plan test input does not claim command execution."},
		"packageCommands":             []any{},
		"pathTriggeredCommands":       []any{},
		"preexistingFailures":         []any{},
		"privatePathPrefixes":         []any{},
		"proofLikePathPatterns":       []any{},
		"publicApi":                   map[string]any{"command": "agentic-proofkit public-api", "touched": false},
		"requirementImpact":           map[string]any{"command": "agentic-proofkit requirement-bindings", "touched": false},
		"secretScan":                  map[string]any{"command": "agentic-proofkit secret-scan", "mode": "diff-scoped", "required": true},
		"touchedRequirementWitnesses": []any{},
		"unknownEdges":                []any{},
	}
}

func planCommand(id string, command string, reason string) map[string]any {
	return map[string]any{"id": id, "command": command, "reason": reason}
}

func unknownEdgeInput(id string, class string) map[string]any {
	return map[string]any{"edgeClass": class, "edgeId": id, "path": "src/app.ts", "reason": "Caller reports unresolved planner edge."}
}

func commandIDExists(raw any, id string) bool {
	values, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, value := range values {
		record, ok := value.(map[string]any)
		if ok && record["id"] == id {
			return true
		}
	}
	return false
}

func stringArrayContains(raw any, needle string) bool {
	values, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
