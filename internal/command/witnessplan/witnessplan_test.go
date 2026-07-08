package witnessplan

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestBuildAdmitsSafeCommandAndRejectsShellCommand(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.061163857848999249192334582247265083240613726562619453864656308921156645063184")
	plan, err := Build(validWitnessPlanInput())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	commands := plan["commands"].([]any)
	groups := plan["parallelGroups"].([]any)
	if len(commands) != 1 || len(groups) != 1 {
		t.Fatalf("Build() plan=%#v, want one command in one group", plan)
	}

	input := validWitnessPlanInput()
	command := input["commands"].([]any)[0].(map[string]any)
	command["argv"] = []any{"sh", "-c", "go test ./..."}
	_, err = Build(input)
	if err == nil || !strings.Contains(err.Error(), "shell") {
		t.Fatalf("Build() accepted shell command: %v", err)
	}
}

func TestBuildProjectsRequirementBindingsToWitnessPlan(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.033949758224172503973560419980040060865660836625689337975156681518110461106337")
	input := map[string]any{
		"schemaVersion":           json.Number("1"),
		"projection":              "requirement-bindings",
		"vocabulary":              validWitnessPlanInput()["vocabulary"],
		"requirementProofBinding": validRequirementProofBindingInput("go test ./internal/command/witnessplan"),
	}
	plan, err := Build(input)
	if err != nil {
		t.Fatalf("Build() projection error = %v", err)
	}
	commands := plan["commands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("projected commands=%#v, want one", commands)
	}
	command := commands[0].(map[string]any)
	argv := command["argv"].([]any)
	if strings.Join([]string{argv[0].(string), argv[1].(string), argv[2].(string)}, " ") != "go test ./internal/command/witnessplan" {
		t.Fatalf("projected argv=%#v", argv)
	}
	if command["networkPolicy"] != "none" || command["credentialClass"] != "none" || command["cachePolicy"] != "disabled" {
		t.Fatalf("projected command did not use conservative policy: %#v", command)
	}
}

func TestBuildRejectsRequirementBindingProjectionThatNeedsShellQuoting(t *testing.T) {
	input := map[string]any{
		"schemaVersion":           json.Number("1"),
		"projection":              "requirement-bindings",
		"vocabulary":              validWitnessPlanInput()["vocabulary"],
		"requirementProofBinding": validRequirementProofBindingInput(`go test "./path with space"`),
	}
	_, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "provide an explicit witness-plan command catalog") {
		t.Fatalf("Build() error=%v, want explicit catalog rejection", err)
	}
}

func TestBuildRejectsRequirementBindingProjectionWithAmbiguousParallelGroups(t *testing.T) {
	input := map[string]any{
		"schemaVersion":           json.Number("1"),
		"projection":              "requirement-bindings",
		"vocabulary":              validWitnessPlanInput()["vocabulary"],
		"requirementProofBinding": validRequirementProofBindingInput("go test ./internal/command/witnessplan"),
	}
	vocabulary := input["vocabulary"].(map[string]any)
	vocabulary["parallelGroups"] = []any{"destructive", "safe"}

	_, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "exactly one parallelGroup") {
		t.Fatalf("Build() error=%v, want ambiguous parallel group rejection", err)
	}
}

func TestBuildRejectsRequirementBindingProjectionWithShellControl(t *testing.T) {
	input := map[string]any{
		"schemaVersion":           json.Number("1"),
		"projection":              "requirement-bindings",
		"vocabulary":              validWitnessPlanInput()["vocabulary"],
		"requirementProofBinding": validRequirementProofBindingInput(`go test ./internal/command/witnessplan && echo ok`),
	}
	_, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "shell control tokens") {
		t.Fatalf("Build() error=%v, want shell-control rejection", err)
	}
}

func TestBuildRejectsRequirementBindingProjectionWithoutVocabulary(t *testing.T) {
	input := map[string]any{
		"schemaVersion":           json.Number("1"),
		"projection":              "requirement-bindings",
		"requirementProofBinding": validRequirementProofBindingInput("go test ./internal/command/witnessplan"),
	}
	_, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "witness vocabulary") {
		t.Fatalf("Build() error=%v, want vocabulary admission rejection", err)
	}
}

func TestBuildRejectsProjectionNonClaimsUntilPlanOwnsRetainedMetadata(t *testing.T) {
	input := map[string]any{
		"schemaVersion":           json.Number("1"),
		"projection":              "requirement-bindings",
		"vocabulary":              validWitnessPlanInput()["vocabulary"],
		"requirementProofBinding": validRequirementProofBindingInput("go test ./internal/command/witnessplan"),
		"nonClaims":               []any{"Projection fixture does not execute witnesses."},
	}

	_, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("Build() error=%v, want unsupported nonClaims rejection", err)
	}
}

func validWitnessPlanInput() map[string]any {
	return map[string]any{
		"vocabulary": map[string]any{
			"artifactKinds":                 []any{"report"},
			"credentialClasses":             []any{"github-token", "none"},
			"environmentClasses":            []any{"local-go"},
			"nonCacheableCredentialClasses": []any{"github-token"},
			"parallelGroups":                []any{"local"},
			"maxTimeoutMs":                  json.Number("10000"),
			"environmentClassPolicies": []any{
				map[string]any{
					"environmentClass":  "local-go",
					"networkPolicies":   []any{"none"},
					"credentialClasses": []any{"github-token", "none"},
					"cachePolicies":     []any{"disabled", "read-only"},
				},
			},
		},
		"commands": []any{
			map[string]any{
				"schemaVersion":   json.Number("1"),
				"id":              "proofkit.test-command",
				"cwd":             ".",
				"argv":            []any{"go", "test", "./..."},
				"timeoutMs":       json.Number("1000"),
				"networkPolicy":   "none",
				"credentialClass": "none",
				"cachePolicy":     "disabled",
				"parallelGroup":   "local",
				"environment": map[string]any{
					"inherit":   "none",
					"allowlist": []any{},
					"classes":   []any{"local-go"},
				},
				"expectedArtifacts": []any{
					map[string]any{"kind": "report", "path": "artifacts/proofkit/report.json", "required": true},
				},
				"exitCodePolicy": map[string]any{
					"kind":         "zero",
					"successCodes": []any{json.Number("0")},
				},
			},
		},
	}
}

func validRequirementProofBindingInput(command string) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"bindingId":     "proofkit.witnessplan.binding",
		"requirements": []any{
			map[string]any{
				"claimLevel":    "blocking",
				"nonClaims":     []any{"Witness-plan projection requirement fixture does not execute commands."},
				"ownerId":       "proofkit.witnessplan",
				"proofState":    "witness_backed",
				"requirementId": "REQ-PROOFKIT-WITNESSPLAN-001",
				"specPath":      "docs/specs/proofkit-witnessplan/requirements.v1.json",
			},
		},
		"bindings": []any{
			map[string]any{
				"commandIds":         []any{"proofkit.test-command"},
				"environmentClasses": []any{"local-go"},
				"requirementId":      "REQ-PROOFKIT-WITNESSPLAN-001",
				"scenarioId":         "proofkit.witnessplan.scenario",
				"witnessId":          "proofkit.witnessplan.witness",
				"witnessKind":        "contract",
				"witnessPath":        "internal/command/witnessplan/witnessplan_test.go",
			},
		},
		"witnessCommands": []any{
			map[string]any{
				"command":          command,
				"commandId":        "proofkit.test-command",
				"environmentClass": "local-go",
			},
		},
		"selection": map[string]any{
			"changedPaths":   []any{},
			"ownerIds":       []any{},
			"requirementIds": []any{},
		},
		"nonClaims": []any{"Witness-plan projection binding fixture does not prove command pass evidence."},
	}
}
