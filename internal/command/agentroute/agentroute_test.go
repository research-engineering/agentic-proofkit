package agentroute

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestBuildRoutesRequirementSourceAndBlocksUnknownGoal(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.requirement_source",
		"goal":          "validate_requirement_source",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "requirement_source",
				"ref":  "docs/specs/module/requirements.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if state := report["state"]; state != "routed" {
		t.Fatalf("state = %v, want routed", state)
	}
	if family := report["selectedFamily"]; family != "requirement_source" {
		t.Fatalf("selectedFamily = %v, want requirement_source", family)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("nextCommands length = %d, want 1", len(commands))
	}
	firstCommand := commands[0].(map[string]any)
	if command := firstCommand["command"]; command != "requirement-source-admission" {
		t.Fatalf("first command = %v, want requirement-source-admission", command)
	}
	argv := firstCommand["argv"].([]any)
	if got, want := argv[3], "docs/specs/module/requirements.v1.json"; got != want {
		t.Fatalf("first argv input = %v, want %s", got, want)
	}
	assertNoInvalidSpecialCommandArgv(t, commands)
	if commandExists(commands, "requirement-source-transition") {
		t.Fatalf("requirement-source-transition must require a separate transition input: %#v", commands)
	}

	blocked, blockedExitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.unknown",
		"goal":          "unknown",
		"mode":          "observe",
	})
	if err != nil {
		t.Fatalf("Build unknown returned error: %v", err)
	}
	if blockedExitCode != 1 {
		t.Fatalf("unknown exitCode = %d, want 1", blockedExitCode)
	}
	if state := blocked["state"]; state != "blocked_unknown_goal" {
		t.Fatalf("unknown state = %v, want blocked_unknown_goal", state)
	}
	if commands := blocked["nextCommands"].([]any); len(commands) != 0 {
		t.Fatalf("unknown nextCommands length = %d, want 0", len(commands))
	}
}

func TestBuildRejectsUnknownAdoptionMode(t *testing.T) {
	t.Parallel()

	_, _, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.invalid_mode",
		"goal":          "validate_requirement_source",
		"mode":          "audit",
	})
	if err == nil || !strings.Contains(err.Error(), "agent route mode must be one of") {
		t.Fatalf("Build error=%v, want adoption mode admission failure", err)
	}
}

func TestBuildRoutesSelectiveEvidenceThroughObligationProjectionInput(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.admit_receipts",
		"goal":          "admit_receipts",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "selective_evidence",
				"ref":  "artifacts/proofkit/selective-evidence-input.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 1 || commands[0].(map[string]any)["command"] != "selective-gate-evidence" {
		t.Fatalf("nextCommands=%#v, want only selective-gate-evidence until projection input exists", commands)
	}
	omitted := report["omitted"].([]any)
	if !omittedCommandMissingInput(omitted, "selective-gate-obligation-decision-input", "obligation_decision_input") {
		t.Fatalf("omitted=%#v, want missing obligation_decision_input projector command", omitted)
	}
	if reason := omittedCommandReason(omitted, "selective-gate-obligation-decision-input"); !strings.Contains(reason, "composed from the selective-gate-evidence output") {
		t.Fatalf("omitted projector reason=%q, want composed evidence handoff guidance", reason)
	}
}

func TestBuildRoutesMaterializedObligationDecisionInput(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.admit_receipts.phase2",
		"goal":          "admit_receipts",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "obligation_decision_input",
				"ref":  "artifacts/proofkit/obligation-decision-input.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if state := report["state"]; state != "routed" {
		t.Fatalf("state=%v, want routed", state)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 1 || commands[0].(map[string]any)["command"] != "selective-gate-obligation-decision-input" {
		t.Fatalf("nextCommands=%#v, want selective-gate-obligation-decision-input", commands)
	}
	argv := toStringSlice(t, commands[0].(map[string]any)["argv"].([]any))
	assertArgvContainsPair(t, argv, "--input", "artifacts/proofkit/obligation-decision-input.json")
	if len(report["requiredInputs"].([]any)) != 0 {
		t.Fatalf("requiredInputs=%#v, want none", report["requiredInputs"])
	}
}

func TestBuildRoutesAuthoringPlanWithoutFalseTransitionInput(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.authoring",
		"goal":          "author_requirements",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "authoring_plan",
				"ref":  "docs/proofkit/requirement-authoring-plan.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("nextCommands length = %d, want 1: %#v", len(commands), commands)
	}
	command := commands[0].(map[string]any)
	if command["command"] != "requirement-authoring-plan" {
		t.Fatalf("command=%v, want requirement-authoring-plan", command["command"])
	}
	argv := toStringSlice(t, command["argv"].([]any))
	if got := argValue(argv, "--input"); got != "docs/proofkit/requirement-authoring-plan.v1.json" {
		t.Fatalf("authoring argv input=%q, want authoring_plan ref", got)
	}
	for _, item := range commands {
		if item.(map[string]any)["command"] == "requirement-source-transition" {
			t.Fatalf("author_requirements must not emit transition with authoring_plan input: %#v", commands)
		}
	}
}

func TestBuildRoutesBindingDerivedWitnessPlanInput(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.binding_witness_plan",
		"goal":          "bind_requirement_proofs",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "binding_witness_plan_input",
				"ref":  "proofkit/witness-plan-input.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("nextCommands length = %d, want 1: %#v", len(commands), commands)
	}
	command := commands[0].(map[string]any)
	if command["command"] != "witness-plan" {
		t.Fatalf("command=%v, want witness-plan", command["command"])
	}
	argv := toStringSlice(t, command["argv"].([]any))
	if got := argValue(argv, "--input"); got != "proofkit/witness-plan-input.v1.json" {
		t.Fatalf("witness-plan argv input=%q, want binding_witness_plan_input ref", got)
	}
}

func TestBuildRoutesExplicitWitnessCommandCatalog(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.witness_command_catalog",
		"goal":          "bind_requirement_proofs",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "witness_command_catalog",
				"ref":  "proofkit/witness-command-catalog.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("nextCommands length = %d, want 1: %#v", len(commands), commands)
	}
	command := commands[0].(map[string]any)
	if command["command"] != "witness-plan" {
		t.Fatalf("command=%v, want witness-plan", command["command"])
	}
	argv := toStringSlice(t, command["argv"].([]any))
	if got := argValue(argv, "--input"); got != "proofkit/witness-command-catalog.v1.json" {
		t.Fatalf("witness-plan argv input=%q, want witness_command_catalog ref", got)
	}
}

func TestBuildRoutesCapabilityMapForAuthoringWithoutChangingAdoptionMode(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.capability_map",
		"goal":          "author_requirements",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "capability_map",
				"ref":  "docs/proofkit/capability-map.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("nextCommands length = %d, want 1: %#v", len(commands), commands)
	}
	argv := findCommandArgv(t, commands, "capability-map-admission")
	if got := argValue(argv, "--input"); got != "docs/proofkit/capability-map.v1.json" {
		t.Fatalf("capability-map-admission input=%q, want capability_map ref", got)
	}
	if commandExists(commands, "requirement-authoring-plan") {
		t.Fatalf("authoring plan must require an authoring_plan input: %#v", commands)
	}
	if report["summary"].(map[string]any)["mode"] != "observe" {
		t.Fatalf("agent-route adoption mode drifted: %#v", report["summary"])
	}
}

func TestBuildRoutesCapabilityMapForRepositoryAdoption(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.adopt.capability_map",
		"goal":          "adopt_repository",
		"mode":          "warn",
		"availableInputs": []any{
			map[string]any{
				"kind": "capability_map",
				"ref":  "docs/proofkit/capability-map.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	argv := findCommandArgv(t, commands, "capability-map-admission")
	if got := argValue(argv, "--input"); got != "docs/proofkit/capability-map.v1.json" {
		t.Fatalf("capability-map-admission input=%q, want capability_map ref", got)
	}
	if commandExists(commands, "adoption-workflow-plan") || commandExists(commands, "scaffold-project-structure") {
		t.Fatalf("adoption route must not invent missing adoption workflow or scaffold input: %#v", commands)
	}
}

func TestBuildRoutesTestDiscoveryToDraftInventoryProjection(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.test_discovery",
		"goal":          "inventory_tests",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "test_discovery",
				"ref":  "proofkit/test-discovery.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("nextCommands length = %d, want 1: %#v", len(commands), commands)
	}
	argv := findCommandArgv(t, commands, "test-evidence-inventory")
	if got := argValue(argv, "--projection"); got != "discovery-draft" {
		t.Fatalf("test-evidence-inventory projection=%q, want discovery-draft", got)
	}
	if got := argValue(argv, "--input"); got != "proofkit/test-discovery.v1.json" {
		t.Fatalf("test-evidence-inventory input=%q, want test_discovery ref", got)
	}
	if commandExists(commands, "requirement-coverage-view") {
		t.Fatalf("test discovery must not close coverage directly: %#v", commands)
	}
}

func TestBuildRoutesCoverageComposeInputBeforeCoverageView(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.coverage_compose",
		"goal":          "inspect_coverage",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "coverage_compose_input",
				"ref":  "proofkit/coverage-compose-input.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("nextCommands length = %d, want 1: %#v", len(commands), commands)
	}
	argv := findCommandArgv(t, commands, "requirement-coverage-input-compose")
	if got := argValue(argv, "--input"); got != "proofkit/coverage-compose-input.v1.json" {
		t.Fatalf("requirement-coverage-input-compose input=%q, want coverage_compose_input ref", got)
	}
	if commandExists(commands, "requirement-coverage-view") {
		t.Fatalf("coverage compose route must not require prebuilt coverage_view_input: %#v", commands)
	}
}

func TestBuildRoutesRequirementSourceTransitionOnlyWithTransitionInput(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.requirement_source_transition",
		"goal":          "validate_requirement_source",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "requirement_source_transition",
				"ref":  "docs/proofkit/requirement-source-transition.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("nextCommands length = %d, want 1: %#v", len(commands), commands)
	}
	argv := findCommandArgv(t, commands, "requirement-source-transition")
	if got := argValue(argv, "--input"); got != "docs/proofkit/requirement-source-transition.v1.json" {
		t.Fatalf("transition argv input=%q, want transition ref", got)
	}
	if commandExists(commands, "requirement-source-admission") {
		t.Fatalf("requirement-source-admission must not consume transition input: %#v", commands)
	}
}

func TestBuildReleaseRouteUsesSchemaSpecificInputs(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.release_inputs",
		"goal":          "release_or_deploy_evidence",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "release_authority_input",
				"ref":  "proofkit/release-authority.v1.json",
			},
			map[string]any{
				"kind": "readiness_closeout_input",
				"ref":  "proofkit/readiness-closeout.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 2 {
		t.Fatalf("nextCommands length = %d, want 2: %#v", len(commands), commands)
	}
	if got := argValue(findCommandArgv(t, commands, "release-authority"), "--input"); got != "proofkit/release-authority.v1.json" {
		t.Fatalf("release-authority input=%q", got)
	}
	if got := argValue(findCommandArgv(t, commands, "readiness-closeout"), "--input"); got != "proofkit/readiness-closeout.v1.json" {
		t.Fatalf("readiness-closeout input=%q", got)
	}
	for _, forbidden := range []string{"registry-consumer", "deployment-evidence-admission"} {
		if commandExists(commands, forbidden) {
			t.Fatalf("%s must not consume release_authority_input or readiness_closeout_input: %#v", forbidden, commands)
		}
	}
}

func TestBuildMigrationRouteUsesPlanSpecificInput(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.migration_plan",
		"goal":          "retire_local_infrastructure",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "migration_parity",
				"ref":  "proofkit/migration-parity.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("nextCommands length = %d, want 1: %#v", len(commands), commands)
	}
	if commandExists(commands, "migration-plan") {
		t.Fatalf("migration-plan must require migration_plan input: %#v", commands)
	}

	plan, planExitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.migration_plan",
		"goal":          "retire_local_infrastructure",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "migration_plan",
				"ref":  "proofkit/migration-plan.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("plan Build returned error: %v", err)
	}
	if planExitCode != 0 {
		t.Fatalf("plan exitCode = %d, want 0", planExitCode)
	}
	planCommands := plan["nextCommands"].([]any)
	if len(planCommands) != 1 {
		t.Fatalf("plan nextCommands length = %d, want 1: %#v", len(planCommands), planCommands)
	}
	if got := argValue(findCommandArgv(t, planCommands, "migration-plan"), "--input"); got != "proofkit/migration-plan.v1.json" {
		t.Fatalf("migration-plan input=%q, want plan ref", got)
	}
}

func TestBuildEmitsExecutableBrowserViewRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		goal      string
		inputKind string
		inputRef  string
		view      string
	}{
		{
			name:      "inspect coverage",
			goal:      "inspect_coverage",
			inputKind: "coverage_view_input",
			inputRef:  "docs/contracts/coverage-view-input.v1.json",
			view:      "coverage",
		},
		{
			name:      "render source",
			goal:      "render_human_view",
			inputKind: "requirement_source",
			inputRef:  "docs/specs/module/requirements.v1.json",
			view:      "source",
		},
		{
			name:      "render proof",
			goal:      "render_human_view",
			inputKind: "proof_binding",
			inputRef:  "docs/contracts/requirement-proof-bindings/module.json",
			view:      "proof",
		},
		{
			name:      "render coverage",
			goal:      "render_human_view",
			inputKind: "coverage_view_input",
			inputRef:  "docs/contracts/coverage-view-input.v1.json",
			view:      "coverage",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report, exitCode, err := Build(map[string]any{
				"schemaVersion": jsonNumber("1"),
				"routeId":       "consumer.route." + tt.goal + "." + tt.inputKind,
				"goal":          tt.goal,
				"mode":          "observe",
				"availableInputs": []any{
					map[string]any{
						"kind": tt.inputKind,
						"ref":  tt.inputRef,
					},
				},
			})
			if err != nil {
				t.Fatalf("Build returned error: %v", err)
			}
			if exitCode != 0 {
				t.Fatalf("exitCode = %d, want 0", exitCode)
			}
			commands := report["nextCommands"].([]any)
			assertNoInvalidSpecialCommandArgv(t, commands)
			argv := findCommandArgv(t, commands, "requirement-browser-server")
			assertArgvContainsPair(t, argv, "--view", tt.view)
			assertArgvContainsPair(t, argv, "--input", tt.inputRef)
		})
	}
}

func TestBuildEmitsBrowserServerOnlyForExplicitServeIntent(t *testing.T) {
	t.Parallel()

	planOnly, planExitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.render.plan",
		"goal":          "render_human_view",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "requirement_source",
				"ref":  "docs/specs/module/requirements.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build plan returned error: %v", err)
	}
	if planExitCode != 0 {
		t.Fatalf("plan exitCode = %d, want 0", planExitCode)
	}
	planArgv := findCommandArgv(t, planOnly["nextCommands"].([]any), "requirement-browser-server")
	assertArgvNotContains(t, planArgv, "--serve")
	assertArgvNotContains(t, planArgv, "--open")

	server, serverExitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.render.server",
		"goal":          "render_human_view",
		"mode":          "observe",
		"browserMode":   "serve_local_view",
		"openBrowser":   true,
		"availableInputs": []any{
			map[string]any{
				"kind": "requirement_source",
				"ref":  "docs/specs/module/requirements.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build server returned error: %v", err)
	}
	if serverExitCode != 0 {
		t.Fatalf("server exitCode = %d, want 0", serverExitCode)
	}
	serverArgv := findCommandArgv(t, server["nextCommands"].([]any), "requirement-browser-server")
	assertArgvContains(t, serverArgv, "--serve")
	assertArgvContains(t, serverArgv, "--open")

	if _, _, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.render.invalid_open",
		"goal":          "render_human_view",
		"mode":          "observe",
		"openBrowser":   true,
	}); err == nil {
		t.Fatal("Build accepted openBrowser without serve_local_view")
	}
}

func TestBuildTreatsKnownChangedPathsAsDiagnosticOnly(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion":     jsonNumber("1"),
		"routeId":           "consumer.route.changed_paths_only",
		"goal":              "plan_selective_checks",
		"mode":              "observe",
		"knownChangedPaths": []any{"packages/example/src/index.ts"},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	requiredInputs := report["requiredInputs"].([]any)
	if len(requiredInputs) != 1 {
		t.Fatalf("requiredInputs length = %d, want 1", len(requiredInputs))
	}
	reason := requiredInputs[0].(map[string]any)["reason"]
	if !strings.Contains(fmt.Sprint(reason), "knownChangedPaths are diagnostic-only") {
		t.Fatalf("missing diagnostic-only reason: %#v", requiredInputs[0])
	}
}

func TestBuildSelectiveRouteRequiresExactInputKinds(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.selective_exact_inputs",
		"goal":          "plan_selective_checks",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "changed_path_set",
				"ref":  "artifacts/proofkit/changed-path-set.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("nextCommands length = %d, want only changed-path-set: %#v", len(commands), commands)
	}
	argv := findCommandArgv(t, commands, "changed-path-set")
	if got := argValue(argv, "--input"); got != "artifacts/proofkit/changed-path-set.json" {
		t.Fatalf("changed-path-set input = %q, want changed-path-set ref", got)
	}
	for _, forbidden := range []string{"impact", "selective-gate-plan"} {
		if commandExists(commands, forbidden) {
			t.Fatalf("%s must not be emitted with changed_path_set input only: %#v", forbidden, commands)
		}
	}

	full, fullExitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.selective_all_inputs",
		"goal":          "plan_selective_checks",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "changed_path_set",
				"ref":  "artifacts/proofkit/changed-path-set.json",
			},
			map[string]any{
				"kind": "impact_input",
				"ref":  "artifacts/proofkit/impact-input.json",
			},
			map[string]any{
				"kind": "selective_gate_plan_input",
				"ref":  "artifacts/proofkit/selective-gate-plan-input.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("full Build returned error: %v", err)
	}
	if fullExitCode != 0 {
		t.Fatalf("full exitCode = %d, want 0", fullExitCode)
	}
	fullCommands := full["nextCommands"].([]any)
	if got := argValue(findCommandArgv(t, fullCommands, "impact"), "--input"); got != "artifacts/proofkit/impact-input.json" {
		t.Fatalf("impact input = %q, want impact_input ref", got)
	}
	if got := argValue(findCommandArgv(t, fullCommands, "selective-gate-plan"), "--input"); got != "artifacts/proofkit/selective-gate-plan-input.json" {
		t.Fatalf("selective-gate-plan input = %q, want selective_gate_plan_input ref", got)
	}
}

func TestBuildRoutesTypeScriptPublicAPIAsExplicitScanner(t *testing.T) {
	t.Parallel()

	blocked, blockedExitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.typescript_public_api",
		"goal":          "verify_typescript_public_api",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "typescript_public_api_manifest",
				"ref":  "docs/contracts/public-api-surfaces.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("blocked Build returned error: %v", err)
	}
	if blockedExitCode != 1 {
		t.Fatalf("blocked exitCode = %d, want 1", blockedExitCode)
	}
	if state := blocked["state"]; state != "blocked_missing_input" {
		t.Fatalf("blocked state = %v, want blocked_missing_input", state)
	}
	if commands := blocked["nextCommands"].([]any); len(commands) != 0 {
		t.Fatalf("blocked scanner route emitted executable commands: %#v", commands)
	}

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.typescript_public_api",
		"goal":          "verify_typescript_public_api",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "typescript_public_api_manifest",
				"ref":  "docs/contracts/public-api-surfaces.v1.json",
			},
			map[string]any{
				"kind": "typescript_public_api_repo_root",
				"ref":  ".",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if family := report["selectedFamily"]; family != "repository_structure" {
		t.Fatalf("selectedFamily = %v, want repository_structure", family)
	}
	argv := findCommandArgv(t, report["nextCommands"].([]any), "typescript-public-api-surfaces")
	assertArgvContainsPair(t, argv, "--input", "docs/contracts/public-api-surfaces.v1.json")
	assertArgvContainsPair(t, argv, "--repo-root", ".")
	guidanceSlice := report["guidanceSlice"].(map[string]any)
	nonClaims := toStringSlice(t, guidanceSlice["nonClaims"].([]any))
	if !containsString(nonClaims, "The TypeScript public API slice does not infer repository intent, prove checkout freshness, or approve merge.") {
		t.Fatalf("scanner non-claim missing: %#v", nonClaims)
	}
}

func TestInputContractMatchesAdmissionVocabulary(t *testing.T) {
	t.Parallel()

	contract := InputContract()
	fields := contract["fields"].(map[string]any)
	assertContractEnum(t, fields, "goal", goalValues)
	assertContractEnum(t, fields, "mode", modeValues)
	assertContractEnum(t, fields, "browserMode", browserModeValues)
	availableInputs := fields["availableInputs"].(map[string]any)
	availableItem := availableInputs["item"].(map[string]any)
	availableKind := availableItem["kind"].(map[string]any)
	if !sameAnyStrings(availableKind["enum"].([]any), sortedKeys(inputKindValues)) {
		t.Fatalf("available input kinds drift: %#v", availableKind["enum"])
	}
	observedReports := fields["observedReports"].(map[string]any)
	observedItem := observedReports["item"].(map[string]any)
	reportKind := observedItem["kind"].(map[string]any)
	reportState := observedItem["state"].(map[string]any)
	if !sameAnyStrings(reportKind["enum"].([]any), sortedKeys(reportKindValues)) {
		t.Fatalf("report kind enum drift: %#v", reportKind["enum"])
	}
	if !sameAnyStrings(reportState["enum"].([]any), sortedKeys(reportStateValues)) {
		t.Fatalf("report state enum drift: %#v", reportState["enum"])
	}
}

func TestRouteSpecsUseAdmittedCommandInputKindMatrix(t *testing.T) {
	t.Parallel()

	allowed := admittedRouteCommandInputKindMatrix()
	for goal, spec := range routeSpecs {
		for _, command := range spec.NextCommands {
			key := command.Command + "\x00" + command.InputKind
			if _, ok := allowed[key]; !ok {
				t.Fatalf("route %s emits unadmitted command/input pair %s/%s", goal, command.Command, command.InputKind)
			}
			for _, argInput := range command.ArgInputs {
				key := command.Command + "\x00" + argInput.InputKind
				if _, ok := allowed[key]; !ok {
					t.Fatalf("route %s emits unadmitted command arg input pair %s %s/%s", goal, command.Command, argInput.Flag, argInput.InputKind)
				}
			}
		}
	}
}

func TestBuildDoesNotGuessMissingStackPreset(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.scaffold",
		"goal":          "scaffold_first_module",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "scaffold_profile_plan",
				"ref":  "docs/proofkit/scaffold-profile-plan.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := report["nextCommands"].([]any)
	assertNoInvalidSpecialCommandArgv(t, commands)
	if got := argValue(findCommandArgv(t, commands, "scaffold-profile-plan"), "--input"); got != "docs/proofkit/scaffold-profile-plan.v1.json" {
		t.Fatalf("scaffold-profile-plan input=%q, want scaffold profile ref", got)
	}
	if commandExists(commands, "scaffold-project-structure") {
		t.Fatalf("scaffold-project-structure must require scaffold_project_structure input: %#v", commands)
	}
	for _, item := range commands {
		command := item.(map[string]any)["command"]
		if command == "stack-preset" {
			t.Fatal("stack-preset must not be emitted without an explicit preset id")
		}
	}
}

func TestBuildDoesNotTreatSpecTreeBundleAsBrowserInput(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.spec_tree",
		"goal":          "render_human_view",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "spec_tree_bundle",
				"ref":  "docs/spec-tree-bundle.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if state := report["state"]; state != "blocked_missing_input" {
		t.Fatalf("state = %v, want blocked_missing_input", state)
	}
	if commands := report["nextCommands"].([]any); len(commands) != 0 {
		t.Fatalf("nextCommands length = %d, want 0", len(commands))
	}
}

func TestBuildBlocksMissingRouteInput(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.missing_source",
		"goal":          "validate_requirement_source",
		"mode":          "warn",
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if state := report["state"]; state != "blocked_missing_input" {
		t.Fatalf("state = %v, want blocked_missing_input", state)
	}
	requiredInputs := report["requiredInputs"].([]any)
	if len(requiredInputs) != 1 {
		t.Fatalf("requiredInputs length = %d, want 1", len(requiredInputs))
	}
	required := requiredInputs[0].(map[string]any)
	if oneOf := toStringSlice(t, required["oneOf"].([]any)); !sameStringSet(oneOf, []string{"requirement_source", "requirement_source_transition"}) {
		t.Fatalf("missing oneOf = %v, want requirement_source or requirement_source_transition", oneOf)
	}
	if commands := report["nextCommands"].([]any); len(commands) != 0 {
		t.Fatalf("nextCommands length = %d, want 0 when input is missing", len(commands))
	}
}

func TestBuildPreservesCallerNonClaimsAndBlocksFailedObservedReports(t *testing.T) {
	t.Parallel()

	report, exitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.with_failed_report",
		"goal":          "validate_requirement_source",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "requirement_source",
				"ref":  "docs/specs/module/requirements.v1.json",
			},
		},
		"observedReports": []any{
			map[string]any{
				"kind":  "requirement_source",
				"ref":   "artifacts/proofkit/source-report.json",
				"state": "failed",
			},
		},
		"nonClaims": []any{"Caller report fixture does not prove merge readiness."},
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if state := report["state"]; state != "blocked_ambiguous_state" {
		t.Fatalf("state = %v, want blocked_ambiguous_state", state)
	}
	if commands := report["nextCommands"].([]any); len(commands) != 0 {
		t.Fatalf("nextCommands length = %d, want 0 when observed report failed", len(commands))
	}
	if !containsString(toStringSlice(t, report["nonClaims"].([]any)), "Caller report fixture does not prove merge readiness.") {
		t.Fatalf("caller non-claim not preserved: %#v", report["nonClaims"])
	}
}

func TestBuildRejectsUnboundedCallerNonClaims(t *testing.T) {
	t.Parallel()

	tooMany := make([]any, 0, maxCallerNonClaims+1)
	for index := 0; index <= maxCallerNonClaims; index++ {
		tooMany = append(tooMany, fmt.Sprintf("Caller bounded non-claim %02d.", index))
	}
	for _, tt := range []struct {
		name      string
		nonClaims []any
	}{
		{
			name:      "too many",
			nonClaims: tooMany,
		},
		{
			name:      "too long",
			nonClaims: []any{strings.Repeat("x", maxCallerNonClaimTextRunes+1)},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := Build(map[string]any{
				"schemaVersion": jsonNumber("1"),
				"routeId":       "consumer.route.unbounded_non_claims",
				"goal":          "validate_requirement_source",
				"mode":          "observe",
				"availableInputs": []any{
					map[string]any{
						"kind": "requirement_source",
						"ref":  "docs/specs/module/requirements.v1.json",
					},
				},
				"nonClaims": tt.nonClaims,
			})
			if err == nil {
				t.Fatal("Build accepted unbounded caller non-claims")
			}
		})
	}
}

func TestBuildRejectsUnboundedRouteID(t *testing.T) {
	t.Parallel()

	_, _, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "route." + strings.Repeat("a", maxRouteIDRunes),
		"goal":          "validate_requirement_source",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "requirement_source",
				"ref":  "docs/specs/module/requirements.v1.json",
			},
		},
	})
	if err == nil {
		t.Fatal("Build accepted an unbounded routeId")
	}
}

func TestBuildGuidanceSliceIDsIdentifyDistinctRoutePayloads(t *testing.T) {
	t.Parallel()

	first, firstExitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.admit_receipts",
		"goal":          "admit_receipts",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "selective_evidence",
				"ref":  "artifacts/proofkit/selective-evidence.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build first returned error: %v", err)
	}
	if firstExitCode != 0 {
		t.Fatalf("first exitCode = %d, want 0", firstExitCode)
	}
	second, secondExitCode, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.decide_obligations",
		"goal":          "decide_obligations",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "obligation_decision",
				"ref":  "artifacts/proofkit/obligation-decision.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("Build second returned error: %v", err)
	}
	if secondExitCode != 0 {
		t.Fatalf("second exitCode = %d, want 0", secondExitCode)
	}
	firstSlice := first["guidanceSlice"].(map[string]any)
	secondSlice := second["guidanceSlice"].(map[string]any)
	if firstSlice["sliceId"] == secondSlice["sliceId"] {
		t.Fatalf("distinct route payloads share sliceId: first=%#v second=%#v", firstSlice, secondSlice)
	}
	if firstSlice["sliceSummary"] == secondSlice["sliceSummary"] && firstSlice["sliceId"] != secondSlice["sliceId"] {
		t.Fatalf("test fixture no longer proves distinct payloads: first=%#v second=%#v", firstSlice, secondSlice)
	}
}

func TestBuildEnvelopeProjectsBoundedGuidanceSlice(t *testing.T) {
	t.Parallel()

	envelope, exitCode, err := BuildEnvelope(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.coverage",
		"goal":          "inspect_coverage",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "coverage_view_input",
				"ref":  "docs/contracts/coverage-view-input.v1.json",
			},
		},
		"nonClaims": []any{"Caller coverage fixture is not native test execution."},
	})
	if err != nil {
		t.Fatalf("BuildEnvelope returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if envelope["envelopeId"] != "consumer.route.coverage.agent-envelope" {
		t.Fatalf("envelopeId = %v", envelope["envelopeId"])
	}
	nonClaims := toStringSlice(t, envelope["nonClaims"].([]any))
	if !containsString(nonClaims, "Caller coverage fixture is not native test execution.") {
		t.Fatalf("caller non-claim not preserved in envelope: %#v", nonClaims)
	}
	contextRefs := envelope["contextRefs"].([]any)
	if !containsMapValue(contextRefs, "role", "guidance_slice") {
		t.Fatalf("envelope context refs missing guidance slice: %#v", contextRefs)
	}
	commands := envelope["commands"].([]any)
	if len(commands) != 2 {
		t.Fatalf("commands length = %d, want 2: %#v", len(commands), commands)
	}
	cost := envelope["costContract"].(map[string]any)
	if stop := cost["stopReason"]; stop != "wide_or_full_gate_required" {
		t.Fatalf("stopReason = %v, want wide_or_full_gate_required", stop)
	}
}

func TestBuildEnvelopeCreatesUniqueRefsForRepeatedRenderCommands(t *testing.T) {
	t.Parallel()

	envelope, exitCode, err := BuildEnvelope(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.render_all",
		"goal":          "render_human_view",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "coverage_view_input",
				"ref":  "docs/contracts/coverage-view-input.v1.json",
			},
			map[string]any{
				"kind": "proof_binding",
				"ref":  "docs/contracts/requirement-proof-bindings/module.json",
			},
			map[string]any{
				"kind": "requirement_source",
				"ref":  "docs/specs/module/requirements.v1.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildEnvelope returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	commands := envelope["commands"].([]any)
	if len(commands) != 6 {
		t.Fatalf("commands length = %d, want 6: %#v", len(commands), commands)
	}
	assertUniqueMapValues(t, commands, "commandId")
	actions := envelope["actionPlan"].([]any)
	if len(actions) != 6 {
		t.Fatalf("actionPlan length = %d, want 6: %#v", len(actions), actions)
	}
	assertUniqueMapValues(t, actions, "stepId")
	cost := envelope["costContract"].(map[string]any)
	if got, ok := cost["commandRefCount"].(int); !ok || got != len(commands) {
		t.Fatalf("commandRefCount = %d, want %d", got, len(commands))
	}
}

func TestBuildEnvelopeKeepsMachineRefIDsBoundedForLongInputRefs(t *testing.T) {
	t.Parallel()

	longRef := "docs/specs/" + strings.Repeat("a", 5000) + ".json"
	envelope, exitCode, err := BuildEnvelope(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.long_ref",
		"goal":          "validate_requirement_source",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "requirement_source",
				"ref":  longRef,
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildEnvelope returned error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	assertMapStringValueRunesAtMost(t, envelope["commands"].([]any), "commandId", 96)
	assertMapStringValueRunesAtMost(t, envelope["actionPlan"].([]any), "stepId", 96)
	assertMapStringValueRunesAtMost(t, envelope["contextRefs"].([]any), "refId", 96)
}

func TestBuildEnvelopeKeepsBlockedRoutesAsStopSignals(t *testing.T) {
	t.Parallel()

	envelope, exitCode, err := BuildEnvelope(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.missing",
		"goal":          "inventory_tests",
		"mode":          "observe",
	})
	if err != nil {
		t.Fatalf("BuildEnvelope returned error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	source := envelope["sourceReport"].(map[string]any)
	if source["state"] != "failed" {
		t.Fatalf("source state = %v, want failed", source["state"])
	}
	if commands := envelope["commands"].([]any); len(commands) != 0 {
		t.Fatalf("commands length = %d, want 0 for blocked route", len(commands))
	}
	if blocked := envelope["blockedPreconditions"].([]any); len(blocked) == 0 {
		t.Fatalf("blocked route must expose blocked preconditions: %#v", envelope)
	}
	cost := envelope["costContract"].(map[string]any)
	if stop := cost["stopReason"]; stop != "blocked_precondition" {
		t.Fatalf("stopReason = %v, want blocked_precondition", stop)
	}
}

func TestBuildEnvelopeCarriesBlockedObservedReportPreconditions(t *testing.T) {
	t.Parallel()

	envelope, exitCode, err := BuildEnvelope(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.observed_failed",
		"goal":          "validate_requirement_source",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "requirement_source",
				"ref":  "docs/specs/module/requirements.v1.json",
			},
		},
		"observedReports": []any{
			map[string]any{
				"kind":  "requirement_source",
				"ref":   "artifacts/proofkit/source-report.json",
				"state": "warning",
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildEnvelope returned error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("exitCode = %d, want 1", exitCode)
	}
	if commands := envelope["commands"].([]any); len(commands) != 0 {
		t.Fatalf("commands length = %d, want 0 for blocked observed report", len(commands))
	}
	blocked := envelope["blockedPreconditions"].([]any)
	if !containsMapValue(blocked, "preconditionId", "consumer.route.observed_failed.blocked.observed-report.01") {
		t.Fatalf("blocked preconditions missing observed report blocker: %#v", blocked)
	}
}

func TestBuildRejectsUnsafeInputRefs(t *testing.T) {
	t.Parallel()

	_, _, err := Build(map[string]any{
		"schemaVersion": jsonNumber("1"),
		"routeId":       "consumer.route.unsafe",
		"goal":          "validate_requirement_source",
		"mode":          "observe",
		"availableInputs": []any{
			map[string]any{
				"kind": "requirement_source",
				"ref":  "../requirements.v1.json",
			},
		},
	})
	if err == nil {
		t.Fatal("Build accepted an unsafe input ref")
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func containsMapValue(items []any, key string, value string) bool {
	for _, item := range items {
		record, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if record[key] == value {
			return true
		}
	}
	return false
}

func assertUniqueMapValues(t *testing.T, items []any, key string) {
	t.Helper()

	seen := map[string]struct{}{}
	for _, item := range items {
		record, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("item is not a map: %#v", item)
		}
		value, ok := record[key].(string)
		if !ok || value == "" {
			t.Fatalf("%s missing string value in %#v", key, record)
		}
		if _, exists := seen[value]; exists {
			t.Fatalf("%s duplicated: %s in %#v", key, value, items)
		}
		seen[value] = struct{}{}
	}
}

func assertContractEnum(t *testing.T, fields map[string]any, field string, values map[string]struct{}) {
	t.Helper()
	record := fields[field].(map[string]any)
	if !sameAnyStrings(record["enum"].([]any), sortedKeys(values)) {
		t.Fatalf("%s enum drift: %#v", field, record["enum"])
	}
}

func sameAnyStrings(left []any, right []any) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameStringSet(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string{}, left...)
	rightCopy := append([]string{}, right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}

func admittedRouteCommandInputKindMatrix() map[string]struct{} {
	pairs := [][2]string{
		{"adoption-workflow-plan", "adoption_workflow"},
		{"witness-plan", "binding_witness_plan_input"},
		{"capability-map-admission", "capability_map"},
		{"changed-path-set", "changed_path_set"},
		{"deployment-evidence-admission", "deployment_evidence_input"},
		{"impact", "impact_input"},
		{"migration-parity-admission", "migration_parity"},
		{"migration-plan", "migration_plan"},
		{"obligation-decision", "obligation_decision"},
		{"proof-slice", "proof_binding"},
		{"readiness-closeout", "readiness_closeout_input"},
		{"registry-consumer", "registry_consumer_input"},
		{"release-authority", "release_authority_input"},
		{"requirement-coverage-input-compose", "coverage_compose_input"},
		{"requirement-authoring-plan", "authoring_plan"},
		{"requirement-bindings", "proof_binding"},
		{"requirement-browser-server", "coverage_view_input"},
		{"requirement-browser-server", "proof_binding"},
		{"requirement-browser-server", "requirement_source"},
		{"requirement-coverage-view", "coverage_view_input"},
		{"requirement-proof-view", "proof_binding"},
		{"requirement-source-admission", "requirement_source"},
		{"requirement-source-transition", "requirement_source_transition"},
		{"requirement-source-view", "requirement_source"},
		{"scaffold-profile-plan", "scaffold_profile_plan"},
		{"scaffold-project-structure", "scaffold_project_structure"},
		{"selective-gate-evidence", "selective_evidence"},
		{"selective-gate-obligation-decision-input", "obligation_decision_input"},
		{"selective-gate-plan", "selective_gate_plan_input"},
		{"spec-overview-claims", "overview_claims"},
		{"test-evidence-inventory", "test_discovery"},
		{"test-evidence-inventory", "test_inventory"},
		{"typescript-public-api-surfaces", "typescript_public_api_manifest"},
		{"typescript-public-api-surfaces", "typescript_public_api_repo_root"},
		{"witness-plan", "witness_command_catalog"},
	}
	result := make(map[string]struct{}, len(pairs))
	for _, pair := range pairs {
		result[pair[0]+"\x00"+pair[1]] = struct{}{}
	}
	return result
}

func assertMapStringValueRunesAtMost(t *testing.T, items []any, key string, limit int) {
	t.Helper()

	for _, item := range items {
		record, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("item is not a map: %#v", item)
		}
		value, ok := record[key].(string)
		if !ok || value == "" {
			t.Fatalf("%s missing string value in %#v", key, record)
		}
		if length := len([]rune(value)); length > limit {
			t.Fatalf("%s length = %d, want <= %d: %s", key, length, limit, value)
		}
	}
}

func jsonNumber(value string) json.Number {
	return json.Number(value)
}

func assertNoInvalidSpecialCommandArgv(t *testing.T, commands []any) {
	t.Helper()

	for _, item := range commands {
		command := item.(map[string]any)
		commandName := command["command"]
		argv := toStringSlice(t, command["argv"].([]any))
		switch commandName {
		case "stack-preset":
			assertArgvContainsPair(t, argv, "--preset", "")
		case "requirement-browser-server":
			view := argValue(argv, "--view")
			if view != "source" && view != "proof" && view != "coverage" {
				t.Fatalf("requirement-browser-server argv = %v, want --view source|proof|coverage", argv)
			}
			if argValue(argv, "--input") == "" {
				t.Fatalf("requirement-browser-server argv = %v, want --input <ref>", argv)
			}
		}
	}
}

func findCommandArgv(t *testing.T, commands []any, name string) []string {
	t.Helper()

	for _, item := range commands {
		command := item.(map[string]any)
		if command["command"] == name {
			return toStringSlice(t, command["argv"].([]any))
		}
	}
	t.Fatalf("command %s not found in %v", name, commands)
	return nil
}

func commandExists(commands []any, name string) bool {
	for _, item := range commands {
		command := item.(map[string]any)
		if command["command"] == name {
			return true
		}
	}
	return false
}

func omittedCommandMissingInput(omitted []any, commandName string, inputKind string) bool {
	for _, item := range omitted {
		record := item.(map[string]any)
		if record["command"] == commandName && record["missingInputKind"] == inputKind {
			return true
		}
	}
	return false
}

func omittedCommandReason(omitted []any, commandName string) string {
	for _, item := range omitted {
		record := item.(map[string]any)
		if record["command"] == commandName {
			return record["reason"].(string)
		}
	}
	return ""
}

func assertArgvContainsPair(t *testing.T, argv []string, flag string, value string) {
	t.Helper()

	got := argValue(argv, flag)
	if value == "" {
		if got == "" {
			t.Fatalf("argv = %v, want %s <value>", argv, flag)
		}
		return
	}
	if got != value {
		t.Fatalf("argv = %v, %s = %q, want %q", argv, flag, got, value)
	}
}

func assertArgvContains(t *testing.T, argv []string, flag string) {
	t.Helper()

	for _, value := range argv {
		if value == flag {
			return
		}
	}
	t.Fatalf("argv = %v, want %s", argv, flag)
}

func assertArgvNotContains(t *testing.T, argv []string, flag string) {
	t.Helper()

	for _, value := range argv {
		if value == flag {
			t.Fatalf("argv = %v, did not expect %s", argv, flag)
		}
	}
}

func argValue(argv []string, flag string) string {
	for index := 0; index < len(argv)-1; index++ {
		if argv[index] == flag {
			return argv[index+1]
		}
	}
	return ""
}

func toStringSlice(t *testing.T, values []any) []string {
	t.Helper()

	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("argv contains non-string value: %#v", value)
		}
		result = append(result, text)
	}
	return result
}
