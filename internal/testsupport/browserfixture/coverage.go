package browserfixture

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// CoverageInput keeps native server and browser witnesses on the same authored
// input, not on a hand-assembled approximation of the coverage output schema.
func CoverageInput(mode string) (map[string]any, error) {
	if mode != "structured" && mode != "compact" {
		return nil, fmt.Errorf("unsupported coverage fixture mode")
	}
	value, err := admission.DecodeJSON(strings.NewReader(`{
  "schemaVersion": 2,
  "viewInputId": "proofkit.browser.coverage.view",
  "requirementSource": {
    "schemaVersion": 1,
    "sourceId": "proofkit.browser.coverage.source",
    "specPackagePath": "docs/specs/browser-coverage",
    "overviewPath": "docs/specs/browser-coverage/overview.md",
    "requirementsPath": "docs/specs/browser-coverage/requirements.v1.json",
    "requirements": [
      {
        "requirementId": "REQ-BROWSER-COVERAGE-001",
        "ownerId": "browser.coverage",
        "invariant": "Coverage browser views render test evidence for each requirement.",
        "claimLevel": "blocking",
        "riskClass": "high",
        "proofBindingRefs": ["proofkit/browser-coverage-bindings.json"],
        "nonClaimRefs": [],
        "nonClaims": ["Coverage browser fixture does not execute tests."],
        "lifecycle": {"state": "active", "replacementRequirementIds": [], "evidenceRefs": []},
        "deferral": null,
        "updatePolicy": {
          "reviewOwnerId": "browser.coverage",
          "requiresImpactDeclaration": true,
          "requiresProofBindingReview": true
        }
      }
    ],
    "nonClaims": ["Coverage browser source fixture does not own native tests."]
  },
  "requirementProofBinding": {
    "schemaVersion": 1,
    "bindingId": "proofkit.browser.coverage.binding",
    "requirements": [
      {
        "requirementId": "REQ-BROWSER-COVERAGE-001",
        "ownerId": "browser.coverage",
        "specPath": "docs/specs/browser-coverage/requirements.v1.json",
        "claimLevel": "blocking",
        "proofState": "witness_backed",
        "nonClaims": ["Coverage browser binding fixture does not execute witnesses."]
      }
    ],
    "bindings": [
      {
        "requirementId": "REQ-BROWSER-COVERAGE-001",
        "scenarioId": "proofkit.browser.coverage.scenario",
        "witnessId": "proofkit.browser.coverage.witness",
        "witnessKind": "contract",
        "witnessPath": "internal/browser_coverage_test.go",
        "commandIds": ["proofkit.browser.coverage.command"],
        "environmentClasses": ["local-go"]
      }
    ],
    "witnessCommands": [
      {
        "commandId": "proofkit.browser.coverage.command",
        "command": "go test ./internal/command/requirementbrowser",
        "environmentClass": "local-go"
      }
    ],
    "selection": {"changedPaths": [], "ownerIds": [], "requirementIds": []},
    "nonClaims": ["Coverage browser binding fixture does not prove command pass evidence."]
  },
  "compactProofContract": null,
  "ownerInvariantRegistry": null,
  "coverageUniverse": {
    "schemaVersion": 1,
    "universeId": "proofkit.browser.coverage.universe",
    "authority": "caller_owned_inventory",
    "completenessDeclaration": "selected_owner_surfaces",
    "ownerIds": ["browser.coverage"],
    "codeSurfaces": [{"surfaceId": "browser.coverage.code", "ownerId": "browser.coverage", "path": "internal/command/requirementbrowser"}],
    "specSurfaces": [{"surfaceId": "browser.coverage.spec", "ownerId": "browser.coverage", "path": "docs/specs/browser-coverage/requirements.v1.json"}],
    "testSurfaces": [{"surfaceId": "browser.coverage.test", "ownerId": "browser.coverage", "path": "internal/command/requirementbrowser/server_test.go"}],
    "commandRefs": ["proofkit.browser.coverage.command"],
    "nonClaims": ["Coverage browser universe is selected-owner scope only."]
  },
  "testEvidenceInventory": {
    "schemaVersion": 1,
    "inventoryId": "proofkit.browser.coverage.inventory",
    "authority": "caller_owned_inventory",
    "entries": [
      {
        "testId": "test.browser.coverage.semantic",
        "selector": "go test ./internal/command/requirementbrowser -run TestStartServerServesExplicitCoverageViews",
        "sourcePath": "internal/command/requirementbrowser/server_test.go",
        "ownerId": "browser.coverage",
        "evidenceClass": "declared_semantic_falsifier_route",
        "requirementRefs": ["REQ-BROWSER-COVERAGE-001"],
        "ownerInvariantRefs": [],
        "commandRefs": ["proofkit.browser.coverage.command"],
        "witnessRefs": ["proofkit.browser.coverage.witness"],
        "falsifier": {
          "falsifierId": "falsifier.browser.coverage",
          "negativeCaseId": "case.browser.coverage.route-only",
          "wrongImplementationClassId": "wrong.browser.coverage.no-test-detail",
          "dominanceGroup": "browser.coverage",
          "supersedes": []
        },
        "oracle": {
          "oracleId": "oracle.browser.coverage",
          "oracleKind": "html_contains_test_detail",
          "expectedPublicOutcome": "rendered report contains semantic test detail",
          "assertionSummary": "Route-only evidence remains insufficient."
        },
        "nonClaims": []
      }
    ],
    "nonClaims": ["Coverage browser inventory fixture does not execute native tests."]
  },
  "localEnvironmentPolicy": null,
  "options": {"scope": "graph"}
}`), 1<<20)
	if err != nil {
		return nil, err
	}
	input := value.(map[string]any)
	if mode == "compact" {
		input["requirementProofBinding"] = nil
		input["localEnvironmentPolicy"] = map[string]any{"authority": "caller_provided", "localEnvironmentClasses": []any{"local-go"}}
		input["testEvidenceInventory"].(map[string]any)["entries"].([]any)[0].(map[string]any)["witnessRefs"] = []any{}
		command := []any{"go test ./internal/command/requirementbrowser"}
		input["compactProofContract"] = map[string]any{
			"schema_version": json.Number("2"), "authority_state": "caller_owned_declaration",
			"contract_id": "proofkit.browser.coverage.compact", "contract_kind": "requirement_proof_route_declaration",
			"normalization_profile": "proofkit.compact.declaration.v2",
			"non_claims":            []any{"Compact fixture does not execute native witnesses."},
			"surface_columns":       []any{"surface_id", "required_environment_classes", "preconditioned_environment_classes"},
			"surfaces":              []any{[]any{"browser.coverage", []any{"local-go"}, []any{}}},
			"witness_columns":       []any{"selector", "environment_classes", "verify_commands", "resolution_order_index"},
			"binding_columns":       []any{"requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "blocking_status", "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "declared_mutation_resistance_claim_id"},
			"bindings": []any{[]any{
				"REQ-BROWSER-COVERAGE-001", "browser.coverage", "browser.coverage::scenario", "contract", "browser.coverage.invariant", "blocking", []any{"local-go"},
				[]any{"internal/browser_coverage_test.go::positive", []any{"local-go"}, command, json.Number("0")},
				[]any{"internal/browser_coverage_test.go::falsification", []any{"local-go"}, command, json.Number("1")},
				command, "browser.coverage.mutation-claim",
			}},
		}
	}
	return input, nil
}

// CoverageWorkspace includes one unreported requirement alongside an actual
// owner-produced coverage report. Empty reports remain admitted present inputs.
func CoverageWorkspace(mode string, empty bool) (map[string]any, error) {
	input, err := CoverageInput(mode)
	if err != nil {
		return nil, err
	}
	source := input["requirementSource"]
	if empty {
		source = nil
		input["requirementSource"].(map[string]any)["requirements"] = []any{}
		input["testEvidenceInventory"].(map[string]any)["entries"] = []any{}
		if mode == "compact" {
			input["compactProofContract"].(map[string]any)["bindings"] = []any{}
		} else {
			binding := input["requirementProofBinding"].(map[string]any)
			binding["requirements"], binding["bindings"], binding["witnessCommands"] = []any{}, []any{}, []any{}
		}
	}
	raw, _, err := requirementcoverageview.BuildJSON(input, requirementcoverageview.Options{})
	if err != nil {
		return nil, err
	}
	coverage, err := requirementcoverageview.AdmitOutput(raw)
	if err != nil {
		return nil, err
	}
	workspace, err := Workspace()
	if err != nil {
		return nil, err
	}
	current := workspace["context"].(map[string]any)
	projections := current["projections"].(map[string]any)
	projections["coverage"] = coverage
	sources := current["sources"].([]any)
	if source != nil {
		projections["requirementSources"] = append(projections["requirementSources"].([]any), source)
		node := projections["specTree"].(map[string]any)["nodes"].([]any)[0].(map[string]any)
		node["sourceRefs"] = append(node["sourceRefs"].([]any), map[string]any{"sourceId": "proofkit.browser.coverage.source", "sourceRefId": "spec.root.coverage", "sourceRefKind": "source_id", "sourceRole": "requirements"})
		sources = append(sources, map[string]any{
			"currentDigest": digest.SHA256TextRef("coverage source fixture"), "kind": "requirement_source", "nodeId": "spec.root",
			"path": "docs/specs/browser-coverage/requirements.v1.json", "sourceRef": "proofkit.browser.coverage.source", "sourceRole": "requirements",
		})
	}
	encoded, err := stablejson.Marshal(coverage)
	if err != nil {
		return nil, err
	}
	sources = append(sources, map[string]any{"currentDigest": digest.SHA256TextRef(string(encoded)), "kind": "coverage", "path": "proofkit/browser-coverage.json", "sourceRef": "coverage:proofkit.browser.coverage.view"})
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].(map[string]any)["sourceRef"].(string) < sources[j].(map[string]any)["sourceRef"].(string)
	})
	current["sources"] = sources
	canonicalSources := []any{}
	for _, value := range projections["requirementSources"].([]any) {
		result, err := requirementsourceadmission.Evaluate(value)
		if err != nil {
			return nil, err
		}
		if result.ExitCode != 0 {
			return nil, fmt.Errorf("coverage fixture source failed admission")
		}
		canonicalSources = append(canonicalSources, requirementsourceadmission.SourceValue(result.Source))
	}
	projections["requirementSources"] = canonicalSources
	tree, err := requirementspectree.Evaluate(projections["specTree"])
	if err != nil {
		return nil, err
	}
	if tree.ExitCode != 0 {
		return nil, fmt.Errorf("coverage fixture tree failed admission")
	}
	projections["specTree"] = requirementspectree.TreeValue(tree.Tree)
	// Empty expected digests belong to the identity projection, not input fields.
	identitySources := make([]any, 0, len(sources))
	for _, rawSource := range sources {
		identitySource := map[string]any{"expectedDigest": ""}
		for key, value := range rawSource.(map[string]any) {
			identitySource[key] = value
		}
		identitySources = append(identitySources, identitySource)
	}
	identity, err := stablejson.Marshal(map[string]any{"catalogId": current["catalogId"], "sources": identitySources, "projections": projections})
	if err != nil {
		return nil, err
	}
	current["snapshotId"] = digest.SHA256TextRef(string(identity))
	return workspace, nil
}
