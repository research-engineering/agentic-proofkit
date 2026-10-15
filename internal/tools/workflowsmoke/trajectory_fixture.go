package workflowsmoke

import (
	"encoding/json"
	"slices"
	"strings"
)

// The trajectory fixture is one small two-language repository. Its native
// files are consumer-owned bytes: Proofkit never executes them, and the smoke
// digests them only in its declared consumer-runner role.
const (
	trajectoryOwner            = "greeter.owner"
	trajectorySourcePath       = "docs/specs/greeter/requirements.v2.json"
	trajectoryBindingPath      = "proofkit/requirement-bindings.json"
	trajectoryInventoryPath    = "proofkit/test-evidence-inventory.json"
	trajectoryManifestPath     = "proofkit/project.v1.json"
	trajectorySpecTreePath     = "proofkit/spec-tree.json"
	trajectoryEmptyNameID      = "REQ-GREETER-001"
	trajectoryFarewellID       = "REQ-GREETER-002"
	trajectoryEmptyScenario    = "greeter.empty_name"
	trajectoryFarewellScenario = "greeter.farewell"
	trajectorySchedulerID      = "greeter.scheduler"
	trajectoryPythonCommand    = "greeter.python-test"
	trajectoryGoGreetCommand   = "greeter.go-test-greet"
	trajectoryFarewellCommand  = "greeter.go-test-farewell"
	trajectoryPythonWitness    = "tests/test_greeter.py"
	trajectoryGoGreetWitness   = "greeter/greeter_test.go"
	trajectoryFarewellTest     = "greeter/farewell_test.go"
)

const trajectoryReadme = `# Greeter

Task for an agent that may use only the installed agentic-proofkit CLI:

1. Adopt Proofkit for this repository. Start with the CLI bootstrap and
   ` + "`next --repo-root <repository>`" + `; follow only routes named by CLI output.
2. Materialize two owner-approved requirements with typed scenario bodies:
   REQ-GREETER-001 (empty names are rejected) bound to the Python test, and
   REQ-GREETER-002 (farewells name the caller once) bound to the Go test.
3. Record execution receipts, link them to the bindings and check currentness.
4. Extend REQ-GREETER-001 to whitespace-only names, extend its Python test
   with a whitespace-only case, make the implementation pass it, and show
   that only REQ-GREETER-001 evidence is stale until the extended test is
   re-executed.
5. Migrate the REQ-GREETER-001 witness from Python to Go without changing
   requirement or scenario IDs; old Python evidence must not stay current.
`

func trajectoryNativeFiles() map[string]string {
	return map[string]string{
		"README.md": trajectoryReadme,
		"go.mod":    "module example.com/greeter\n\ngo 1.22\n",
		"pygreeter/__init__.py": `def greet(name):
    if not name:
        raise ValueError("empty_name")
    return "Hello, " + name + "!"
`,
		trajectoryPythonWitness: `import unittest

from pygreeter import greet


class GreeterTest(unittest.TestCase):
    def test_rejects_empty_name(self):
        with self.assertRaises(ValueError):
            greet("")


if __name__ == "__main__":
    unittest.main()
`,
		"greeter/farewell.go": `package greeter

// Farewell names the caller exactly once.
func Farewell(name string) string {
	return "Goodbye, " + name + "."
}
`,
		trajectoryFarewellTest: `package greeter

import (
	"strings"
	"testing"
)

func TestFarewellNamesOnce(t *testing.T) {
	for _, name := range []string{"Ada", "Grace"} {
		if got := Farewell(name); strings.Count(got, name) != 1 {
			t.Fatalf("Farewell(%q) = %q, want the name exactly once", name, got)
		}
	}
}
`,
	}
}

// trajectoryWhitespaceFiles returns the Python witness extended with the
// whitespace-only case of the changed REQ-GREETER-001 and the implementation
// repaired to pass it.
func trajectoryWhitespaceFiles() map[string]string {
	return map[string]string{
		"pygreeter/__init__.py": `def greet(name):
    if not name or not name.strip():
        raise ValueError("empty_name")
    return "Hello, " + name + "!"
`,
		trajectoryPythonWitness: `import unittest

from pygreeter import greet


class GreeterTest(unittest.TestCase):
    def test_rejects_empty_name(self):
        for name in ("", "   "):
            with self.subTest(name=name), self.assertRaises(ValueError):
                greet(name)


if __name__ == "__main__":
    unittest.main()
`,
	}
}

// trajectoryMigratedFiles replaces the Python implementation and witness by Go.
func trajectoryMigratedFiles() (map[string]string, []string) {
	return map[string]string{
		"greeter/greeter.go": `package greeter

import (
	"errors"
	"strings"
)

// ErrEmptyName rejects a greeting without a name.
var ErrEmptyName = errors.New("empty_name")

// Greet greets a name that is not empty or whitespace-only.
func Greet(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", ErrEmptyName
	}
	return "Hello, " + name + "!", nil
}
`,
		trajectoryGoGreetWitness: `package greeter

import (
	"errors"
	"testing"
)

func TestGreetRejectsEmptyName(t *testing.T) {
	for _, name := range []string{"", "   "} {
		if _, err := Greet(name); !errors.Is(err, ErrEmptyName) {
			t.Fatalf("Greet(%q) error = %v, want ErrEmptyName", name, err)
		}
	}
}
`,
	}, []string{"pygreeter/__init__.py", trajectoryPythonWitness}
}

// trajectorySpec is the owner-approved meaning at one point of the trajectory.
type trajectorySpec struct {
	EmptyNameStatement string
	EmptyNameAction    string
	Migrated           bool
}

func trajectoryInitialSpec() trajectorySpec {
	return trajectorySpec{
		EmptyNameStatement: "Empty names are rejected with a stable error.",
		EmptyNameAction:    "Call greet with an empty name.",
	}
}

func trajectoryRequirementNonClaims() []any {
	return []any{"Trajectory fixture requirement; native execution is caller-owned."}
}

func trajectoryMember(requirementID, statement string) map[string]any {
	return map[string]any{
		"requirementId": requirementID, "statementCompletion": statement,
		"fields": map[string]any{
			"ownerId": trajectoryOwner, "claimLevel": "blocking", "riskClass": "high",
			"lifecycle": map[string]any{"state": "active"}, "deferral": nil,
			"nonClaimRefs": []any{}, "externalNonClaimRefs": []any{}, "nonClaims": trajectoryRequirementNonClaims(),
			"proofBindingRefs": []any{trajectoryBindingPath},
			"updatePolicy":     map[string]any{"requiresImpactDeclaration": true, "requiresProofBindingReview": true, "reviewOwnerId": trajectoryOwner},
		},
	}
}

// trajectoryScenarios are typed, membership-bound bodies stored once in the
// grouped source; bindings and native tests carry only their stable IDs.
func trajectoryScenarios(spec trajectorySpec) []any {
	return []any{
		map[string]any{
			"scenarioId": trajectoryEmptyScenario, "requirementIds": []any{trajectoryEmptyNameID},
			"parameters": []any{}, "preconditions": []any{"The greeter is importable."},
			"actionSequence":        []any{spec.EmptyNameAction},
			"expectedObservations":  []any{"The call fails with the empty_name error."},
			"forbiddenObservations": []any{"A greeting is returned."},
			"examples":              []any{}, "vocabularyRefs": []any{}, "nonClaimRefs": []any{},
		},
		map[string]any{
			"scenarioId": trajectoryFarewellScenario, "requirementIds": []any{trajectoryFarewellID},
			"parameters": []any{"name"}, "preconditions": []any{"The greeter is importable."},
			"actionSequence":        []any{"Call farewell with ${name}."},
			"expectedObservations":  []any{"The farewell contains ${name} exactly once."},
			"forbiddenObservations": []any{"The farewell omits or repeats ${name}."},
			"examples": []any{
				map[string]any{"exampleId": "EX-ADA", "values": map[string]any{"name": "Ada"}},
				map[string]any{"exampleId": "EX-GRACE", "values": map[string]any{"name": "Grace"}},
			},
			"vocabularyRefs": []any{}, "nonClaimRefs": []any{},
		},
	}
}

func trajectorySource(spec trajectorySpec) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("2"), "kind": "proofkit.requirement-source",
		"sourceId": "greeter.requirements", "specPackagePath": "docs/specs/greeter",
		"sourceNonClaims": []any{"Trajectory fixture source; no product intent beyond the fixture is claimed."},
		"groups": []any{map[string]any{
			"groupId": "RGRP-GREETER", "profileId": "", "statementStem": "", "sharedPremises": []any{},
			"members": []any{
				trajectoryMember(trajectoryEmptyNameID, spec.EmptyNameStatement),
				trajectoryMember(trajectoryFarewellID, "Farewells name the caller exactly once."),
			},
		}},
		"scenarios": trajectoryScenarios(spec),
	}
}

type trajectoryEdge struct {
	RequirementID string
	ScenarioID    string
	WitnessID     string
	WitnessPath   string
	CommandID     string
	Command       string
	// InputSelectors are the sorted repository paths Command reads: the Go
	// module file and package directory, or the Python package and witness.
	InputSelectors []string
	Environment    string
	TestID         string
	Selector       string
}

func trajectoryEdges(spec trajectorySpec) []trajectoryEdge {
	emptyName := trajectoryEdge{
		RequirementID: trajectoryEmptyNameID, ScenarioID: trajectoryEmptyScenario,
		WitnessID: "greeter.witness.empty-name-python", WitnessPath: trajectoryPythonWitness,
		CommandID: trajectoryPythonCommand, Command: "python3 -m unittest tests.test_greeter", Environment: "local-python",
		InputSelectors: []string{"pygreeter", trajectoryPythonWitness},
		TestID:         "greeter.test.empty-name-python", Selector: trajectoryPythonWitness + "::GreeterTest.test_rejects_empty_name",
	}
	if spec.Migrated {
		emptyName = trajectoryEdge{
			RequirementID: trajectoryEmptyNameID, ScenarioID: trajectoryEmptyScenario,
			WitnessID: "greeter.witness.empty-name-go", WitnessPath: trajectoryGoGreetWitness,
			CommandID: trajectoryGoGreetCommand, Command: "go test ./greeter -run TestGreetRejectsEmptyName", Environment: "local-go",
			InputSelectors: []string{"go.mod", "greeter"},
			TestID:         "greeter.test.empty-name-go", Selector: trajectoryGoGreetWitness + "::TestGreetRejectsEmptyName",
		}
	}
	return []trajectoryEdge{emptyName, {
		RequirementID: trajectoryFarewellID, ScenarioID: trajectoryFarewellScenario,
		WitnessID: "greeter.witness.farewell-go", WitnessPath: trajectoryFarewellTest,
		CommandID: trajectoryFarewellCommand, Command: "go test ./greeter -run TestFarewellNamesOnce", Environment: "local-go",
		InputSelectors: []string{"go.mod", "greeter"},
		TestID:         "greeter.test.farewell-go", Selector: trajectoryFarewellTest + "::TestFarewellNamesOnce",
	}}
}

func trajectoryBinding(spec trajectorySpec) map[string]any {
	edges := trajectoryEdges(spec)
	requirements, bindings, commands := []any{}, []any{}, []any{}
	for _, edge := range edges {
		requirements = append(requirements, map[string]any{
			"requirementId": edge.RequirementID, "ownerId": trajectoryOwner, "claimLevel": "blocking",
			"proofState": "witness_backed", "specPath": trajectorySourcePath, "nonClaims": trajectoryRequirementNonClaims(),
		})
		bindings = append(bindings, map[string]any{
			"requirementId": edge.RequirementID, "scenarioId": edge.ScenarioID, "witnessId": edge.WitnessID,
			"witnessKind": "contract", "witnessPath": edge.WitnessPath,
			"commandIds": []any{edge.CommandID}, "environmentClasses": []any{edge.Environment},
		})
		commands = append(commands, map[string]any{"commandId": edge.CommandID, "command": edge.Command, "environmentClasses": []any{edge.Environment}})
	}
	slices.SortFunc(commands, func(left, right any) int {
		return strings.Compare(left.(map[string]any)["commandId"].(string), right.(map[string]any)["commandId"].(string))
	})
	return map[string]any{
		"schemaVersion": json.Number("1"), "bindingId": "greeter.bindings",
		"requirements": requirements, "bindings": bindings, "witnessCommands": commands,
		"selection": map[string]any{"changedPaths": []any{}, "ownerIds": []any{}, "requirementIds": []any{}},
		"nonClaims": []any{"Trajectory fixture bindings declare routes, not passing runs."},
	}
}

func trajectoryInventory(spec trajectorySpec) map[string]any {
	entries := []any{}
	for _, edge := range trajectoryEdges(spec) {
		entries = append(entries, map[string]any{
			"testId": edge.TestID, "ownerId": trajectoryOwner, "sourcePath": edge.WitnessPath, "selector": edge.Selector,
			"evidenceClass": "declared_semantic_falsifier_route", "requirementRefs": []any{edge.RequirementID},
			"ownerInvariantRefs": []any{}, "commandRefs": []any{edge.CommandID}, "witnessRefs": []any{edge.WitnessID},
			"falsifier": map[string]any{
				"falsifierId": edge.TestID + ".falsifier", "negativeCaseId": edge.TestID + ".case",
				"wrongImplementationClassId": edge.TestID + ".wrong", "dominanceGroup": edge.ScenarioID, "supersedes": []any{},
			},
			"oracle": map[string]any{
				"oracleId": edge.TestID + ".oracle", "oracleKind": "negative_exit_and_diagnostic",
				"expectedPublicOutcome": "The test fails when the scenario behavior is broken.",
				"assertionSummary":      "The native test asserts the scenario observation.",
			},
			"nonClaims": []any{},
		})
	}
	slices.SortFunc(entries, func(left, right any) int {
		return strings.Compare(left.(map[string]any)["testId"].(string), right.(map[string]any)["testId"].(string))
	})
	return map[string]any{
		"schemaVersion": json.Number("1"), "inventoryId": "greeter.inventory", "authority": "caller_owned_inventory",
		"entries": entries, "nonClaims": []any{"Trajectory fixture inventory; native execution is caller-owned."},
	}
}

func trajectoryPacket(sourcePlan any, spec trajectorySpec) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("2"), "requestKind": "proofkit.adoption-materialization-request",
		"requestId": "greeter.materialization", "projectId": "greeter.project", "sourcePlan": sourcePlan,
		"requirementSources":      []any{trajectorySource(spec)},
		"requirementProofBinding": map[string]any{"path": trajectoryBindingPath, "record": trajectoryBinding(spec)},
		"testEvidenceInventory":   map[string]any{"path": trajectoryInventoryPath, "record": trajectoryInventory(spec)},
		"nonClaims":               []any{"Trajectory fixture materialization request."},
	}
}

func trajectoryVocabulary() map[string]any {
	policy := func(class string) any {
		return map[string]any{"environmentClass": class, "networkPolicies": []any{"none"}, "credentialClasses": []any{"none"}, "cachePolicies": []any{"disabled"}}
	}
	return map[string]any{
		"artifactKinds": []any{"log"}, "credentialClasses": []any{"none"},
		"environmentClasses":            []any{"local-go", "local-python"},
		"environmentClassPolicies":      []any{policy("local-go"), policy("local-python")},
		"parallelGroups":                []any{"greeter.native"},
		"nonCacheableCredentialClasses": []any{}, "maxTimeoutMs": json.Number("60000"),
	}
}

func trajectoryPolicies(spec trajectorySpec) []any {
	policies := []any{}
	for _, edge := range trajectoryEdges(spec) {
		inputSelectors := []any{}
		for _, selector := range edge.InputSelectors {
			inputSelectors = append(inputSelectors, selector)
		}
		policies = append(policies, map[string]any{
			"commandId": edge.CommandID, "inputSelectors": inputSelectors,
			"outputSelectors": []any{}, "resourceReads": []any{}, "resourceWrites": []any{}, "exclusiveLocks": []any{},
			"sideEffectClass": "none", "deterministicOutput": true, "cacheAdmissionRefs": []any{},
			"retryPolicy":        map[string]any{"kind": "none", "maxAttempts": json.Number("1")},
			"cancellationPolicy": map[string]any{"kind": "cooperative", "graceMs": json.Number("1000")},
			"timeoutPolicy":      map[string]any{"kind": "bounded", "timeoutMs": json.Number("60000")},
			"nonClaims":          []any{"Trajectory scheduling policy does not execute commands."},
		})
	}
	slices.SortFunc(policies, func(left, right any) int {
		return strings.Compare(left.(map[string]any)["commandId"].(string), right.(map[string]any)["commandId"].(string))
	})
	return policies
}

func trajectorySpecTree() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("2"), "treeId": "greeter.tree", "rootNodeId": "greeter.root",
		"callerAnnotations": []any{}, "edges": []any{}, "overlays": []any{},
		"nodes": []any{map[string]any{
			"nodeId": "greeter.root", "nodeKind": "meta_spec", "label": "Greeter behavior", "displayOrder": json.Number("1"),
			"callerAnnotations": []any{},
			"sourceRefs": []any{map[string]any{
				"sourceId": "greeter.requirements", "sourceRefId": "greeter.root.requirements",
				"sourceRefKind": "source_id", "sourceRole": "requirements",
			}},
		}},
	}
}

func trajectoryCatalog() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("2"), "catalogId": "greeter.context",
		"specTree":           map[string]any{"path": trajectorySpecTreePath},
		"requirementSources": []any{map[string]any{"path": trajectorySourcePath, "nodeId": "greeter.root"}},
		"proofBinding":       map[string]any{"path": trajectoryBindingPath},
	}
}

func trajectoryCoverageInput(spec trajectorySpec) map[string]any {
	edges := trajectoryEdges(spec)
	tests, commands := []any{}, []any{}
	for _, edge := range edges {
		tests = append(tests, map[string]any{"surfaceId": edge.TestID, "ownerId": trajectoryOwner, "path": edge.WitnessPath})
		commands = append(commands, edge.CommandID)
	}
	sortAnyMaps(tests, "surfaceId")
	slices.SortFunc(commands, func(left, right any) int { return strings.Compare(left.(string), right.(string)) })
	return map[string]any{
		"schemaVersion": json.Number("3"), "composerInputId": "greeter.coverage.compose", "viewInputId": "greeter.coverage.view",
		"selectedOwnerIds":        []any{trajectoryOwner},
		"requirementSource":       trajectorySource(spec),
		"requirementProofBinding": trajectoryBinding(spec),
		"testEvidenceInventory":   trajectoryInventory(spec),
		"coverageUniverse": map[string]any{
			"schemaVersion": json.Number("1"), "universeId": "greeter.universe", "authority": "caller_owned_inventory",
			"completenessDeclaration": "selected_owner_surfaces", "ownerIds": []any{trajectoryOwner},
			"codeSurfaces": []any{map[string]any{"surfaceId": "greeter.code", "ownerId": trajectoryOwner, "path": "greeter"}},
			"specSurfaces": []any{map[string]any{"surfaceId": "greeter.spec", "ownerId": trajectoryOwner, "path": trajectorySourcePath}},
			"testSurfaces": tests, "commandRefs": commands,
			"nonClaims": []any{"Declared scope does not prove discovery or test execution."},
		},
		"ownerInvariantRegistry": nil, "localEnvironmentPolicy": nil, "options": nil,
	}
}

func sortAnyMaps(values []any, key string) {
	slices.SortFunc(values, func(left, right any) int {
		return strings.Compare(left.(map[string]any)[key].(string), right.(map[string]any)[key].(string))
	})
}
