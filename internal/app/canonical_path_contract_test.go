package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const canonicalPathContractPolicy = "Current path equivalence is Unicode 17 canonical caseless matching (D145); fresh plans and journals use transaction schemaVersion=3. Retained transaction versions 1 and 2 preserve their original path equivalence and recovery identities; receipt schemaVersion=2 is independent."

func verifyCanonicalPathContracts(contract map[string]any) error {
	commands, _, err := indexPublicABIRecords(contract["commands"], "command")
	if err != nil {
		return err
	}
	for _, name := range []string{"adopt-materialize-apply", "adopt-materialize-plan", "adopt-materialize-recover", "integration-apply", "integration-plan", "integration-recover"} {
		command, ok := commands[name]
		if !ok {
			return fmt.Errorf("missing canonical-path command %s", name)
		}
		for _, direction := range []string{"input", "output"} {
			wireVersion, semanticVersion := "1", "2"
			if direction == "input" {
				if name != "adopt-materialize-apply" && name != "adopt-materialize-plan" {
					continue
				}
				wireVersion, semanticVersion = "2", "3"
			}
			value, ok := command[direction+"Contract"].(map[string]any)
			if !ok || value["schemaVersion"] != json.Number(wireVersion) || value["contractId"] != "proofkit."+name+"."+direction+".v"+semanticVersion {
				return fmt.Errorf("canonical path semantic/wire identity mismatch: %s %s", name, direction)
			}
			summary, ok := value["compatibilitySummary"].([]any)
			if !ok || len(summary) == 0 || summary[len(summary)-1] != canonicalPathContractPolicy {
				return fmt.Errorf("canonical path policy missing: %s %s", name, direction)
			}
			sources, ok := value["nativeSources"].([]any)
			if !ok {
				return fmt.Errorf("canonical path native closure missing: %s %s", name, direction)
			}
			paths := make([]string, 0, len(sources))
			for _, source := range sources {
				entry, ok := source.(map[string]any)
				if !ok {
					return fmt.Errorf("invalid native source")
				}
				path, ok := entry["path"].(string)
				if !ok {
					return fmt.Errorf("invalid native source path")
				}
				paths = append(paths, path)
			}
			for _, owner := range []string{"internal/kernel/pathidentity", "internal/kernel/repositorytransaction", "internal/kernel/rootpath"} {
				if !slices.Contains(paths, owner) {
					return fmt.Errorf("canonical path owner missing: %s", owner)
				}
			}
		}
	}
	return nil
}

func TestCanonicalPathContractIdentitySeparatesWireVersion(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"old-input-identity", "canonical path semantic/wire identity mismatch: adopt-materialize-plan input"},
		{"wire-version-churn", "canonical path semantic/wire identity mismatch: adopt-materialize-plan input"},
		{"missing-policy", "canonical path policy missing: adopt-materialize-plan input"},
		{"missing-path-owner", "canonical path owner missing: internal/kernel/pathidentity"},
		{"old-plan-output-identity", "canonical path semantic/wire identity mismatch: integration-plan output"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			changed := readCLIContractRaw(t)
			if err := verifyCanonicalPathContracts(changed); err != nil {
				t.Fatalf("pristine contract fixture was rejected: %v", err)
			}
			commands, _, err := indexPublicABIRecords(changed["commands"], "command")
			if err != nil {
				t.Fatal(err)
			}
			input := commands["adopt-materialize-plan"]["inputContract"].(map[string]any)
			switch test.name {
			case "old-input-identity":
				input["contractId"] = "proofkit.adopt-materialize-plan.input.v2"
			case "wire-version-churn":
				input["schemaVersion"] = json.Number("3")
			case "missing-policy":
				summary := input["compatibilitySummary"].([]any)
				input["compatibilitySummary"] = summary[:len(summary)-1]
			case "missing-path-owner":
				sources := input["nativeSources"].([]any)
				input["nativeSources"] = slices.DeleteFunc(sources, func(raw any) bool {
					return raw.(map[string]any)["path"] == "internal/kernel/pathidentity"
				})
			case "old-plan-output-identity":
				commands["integration-plan"]["outputContract"].(map[string]any)["contractId"] = "proofkit.integration-plan.output.v1"
			}
			if err := verifyCanonicalPathContracts(changed); err == nil || err.Error() != test.want {
				t.Fatalf("contract boundary mutation rejection: got %v, want %q", err, test.want)
			}
		})
	}
}

// The contract map restates these lifecycle identities for readers, and
// ADOPTION.md and the agent-workflow overview restate the fresh journal
// version. Deriving the expected sentences from the shipped contract keeps a
// version bump from leaving these owner surfaces behind.
func TestContractMapDocStatesLifecycleContractVersions(t *testing.T) {
	commands, _, err := indexPublicABIRecords(readCLIContractRaw(t)["commands"], "command")
	if err != nil {
		t.Fatal(err)
	}
	identity := func(name, direction string) (string, string, []any) {
		value, ok := commands[name][direction+"Contract"].(map[string]any)
		if !ok {
			t.Fatalf("missing %s %s contract", name, direction)
		}
		contractID, _ := value["contractId"].(string)
		prefix := "proofkit." + name + "." + direction + ".v"
		wire, ok := value["schemaVersion"].(json.Number)
		if !strings.HasPrefix(contractID, prefix) || !ok {
			t.Fatalf("unexpected %s %s identity %q", name, direction, contractID)
		}
		summary, _ := value["compatibilitySummary"].([]any)
		return strings.TrimPrefix(contractID, prefix), wire.String(), summary
	}
	inputSemantic, inputWire, inputSummary := identity("adopt-materialize-plan", "input")
	if semantic, wire, _ := identity("adopt-materialize-apply", "input"); semantic != inputSemantic || wire != inputWire {
		t.Fatalf("materialization plan/apply input identities diverge: v%s/%s and v%s/%s", inputSemantic, inputWire, semantic, wire)
	}
	outputSemantic, outputWire, _ := identity("adopt-materialize-apply", "output")
	for _, name := range []string{"adopt-materialize-plan", "adopt-materialize-recover", "integration-apply", "integration-plan", "integration-recover"} {
		if semantic, wire, _ := identity(name, "output"); semantic != outputSemantic || wire != outputWire {
			t.Fatalf("lifecycle output identity of %s diverges: v%s/%s, want v%s/%s", name, semantic, wire, outputSemantic, outputWire)
		}
	}
	if len(inputSummary) == 0 {
		t.Fatal("materialization input has no compatibility summary")
	}
	policy, _ := inputSummary[len(inputSummary)-1].(string)
	journal := regexp.MustCompile(`fresh plans and journals use transaction schemaVersion=([0-9]+)`).FindStringSubmatch(policy)
	if journal == nil {
		t.Fatalf("canonical path policy does not name the fresh journal version: %q", policy)
	}
	for _, surface := range []struct {
		path       string
		statements []string
	}{
		{path: "docs/proofkit-contract-map.md", statements: []string{
			fmt.Sprintf("Adoption materialization plan/apply input v%s retains payload `schemaVersion: %s`", inputSemantic, inputWire),
			fmt.Sprintf("six adoption/integration lifecycle output contracts use semantic v%s with outer `schemaVersion: %s`", outputSemantic, outputWire),
			fmt.Sprintf("Fresh transaction plans and journals use `schemaVersion: %s`", journal[1]),
		}},
		{path: "ADOPTION.md", statements: []string{fmt.Sprintf("New journals use schema v%s for presence and absence", journal[1])}},
		{path: "docs/specs/proofkit-agent-workflow/overview.md", statements: []string{fmt.Sprintf("New journals use v%s for presence and absence", journal[1])}},
	} {
		document, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(surface.path)))
		if err != nil {
			t.Fatal(err)
		}
		normalized := strings.Join(strings.Fields(string(document)), " ")
		for _, statement := range surface.statements {
			if !strings.Contains(normalized, statement) {
				t.Fatalf("%s does not state the shipped contract identity: %s", surface.path, statement)
			}
		}
	}
}
