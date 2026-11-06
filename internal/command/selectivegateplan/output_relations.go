package selectivegateplan

import (
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

// Field admission precedes relation admission; failed plans remain reportable.
func validateOutputRelations(state string, failures []string, commands []map[string]any, plan map[string]any) error {
	scan := plan["scanObligation"].(map[string]any)
	coverageRecords := plan["fallbackCoverage"].([]any)
	edgeRecords := plan["unknownEdges"].([]any)
	if (state == "ok") != (len(failures) == 0) {
		return fmt.Errorf("selective gate plan output planState contradicts failures")
	}
	byKey := make(map[string]map[string]any, len(commands))
	for _, item := range commands {
		key := outputCommandKey(item)
		if _, exists := byKey[key]; exists {
			return fmt.Errorf("selective gate plan output required command keys must be unique")
		}
		byKey[key] = item
	}
	coverage := make([]fallbackCoverage, 0, len(coverageRecords))
	fallbackByID := make(map[string]map[string]any, len(coverageRecords))
	for _, raw := range coverageRecords {
		item := raw.(map[string]any)
		cmd := item["command"].(map[string]any)
		id := cmd["id"].(string)
		if _, exists := fallbackByID[id]; exists {
			return fmt.Errorf("selective gate plan output fallback command ids must be unique")
		}
		fallbackByID[id] = cmd
		coverage = append(coverage, fallbackCoverage{Command: command{ID: id}, EdgeClasses: admit.AnySliceToString(item["edgeClasses"].([]any))})
	}
	edges := make([]unknownEdge, 0, len(edgeRecords))
	seen := make(map[string]struct{}, len(edgeRecords))
	for _, raw := range edgeRecords {
		item := raw.(map[string]any)
		id := item["edgeId"].(string)
		if _, exists := seen[id]; exists {
			return fmt.Errorf("selective gate plan output unknown edge ids must be unique")
		}
		seen[id] = struct{}{}
		edges = append(edges, unknownEdge{EdgeID: id, EdgeClass: item["edgeClass"].(string)})
	}
	var uncoveredFailures []string
	assessments := assessUnknownEdges(edges, coverage, &uncoveredFailures)
	for i, assessed := range assessments {
		item := edgeRecords[i].(map[string]any)
		ids := admit.AnySliceToString(item["fallbackCommandIds"].([]any))
		if assessed.CoverageState != item["coverageState"] || !slices.Equal(assessed.FallbackCommandIDs, ids) {
			return fmt.Errorf("selective gate plan output unknown edge fallback relation is inconsistent")
		}
		if state == "ok" {
			for _, id := range assessed.FallbackCommandIDs {
				if !hasOutputCommand(byKey, fallbackByID[id]) {
					return fmt.Errorf("selective gate plan output covered fallback is missing its required command")
				}
			}
		}
	}
	if state == "ok" {
		if len(uncoveredFailures) != 0 {
			return fmt.Errorf("selective gate plan output successful state contains uncovered edges")
		}
		scanCommand := map[string]any{"id": scan["commandId"], "command": scan["command"], "commandOwnership": scan["commandOwnership"]}
		if !hasOutputCommand(byKey, scanCommand) {
			return fmt.Errorf("selective gate plan output scan obligation is missing its required command")
		}
		if err := validateDerivedCommands(byKey, commands, plan); err != nil {
			return err
		}
	}
	return nil
}

func validateDerivedCommands(byKey map[string]map[string]any, commands []map[string]any, plan map[string]any) error {
	type route struct{ id, path, reason string }
	routes := make(map[route]struct{}, len(commands))
	for _, item := range commands {
		path, _ := item["sourcePath"].(string)
		routes[route{item["id"].(string), path, item["reason"].(string)}] = struct{}{}
	}
	require := func(id, path, reason string) error {
		if _, ok := routes[route{id, path, reason}]; !ok {
			return fmt.Errorf("selective gate plan output %s obligation is missing its required command", id)
		}
		return nil
	}
	if plan["publicApiContractTouched"].(bool) {
		if err := require("public-api", "", "public_api_contract_surface_changed"); err != nil {
			return err
		}
	}
	if len(plan["proofLikePaths"].([]any)) > 0 {
		if err := require("requirement-impact", "", "changed_requirement_or_proof_surface"); err != nil {
			return err
		}
	}
	for _, raw := range plan["generatedArtifacts"].([]any) {
		artifact := raw.(map[string]any)
		if err := require("generated-artifact", artifact["path"].(string), "generated_artifact_"+artifact["reason"].(string)); err != nil {
			return err
		}
	}
	for _, raw := range plan["artifactIntegrity"].([]any) {
		artifact := raw.(map[string]any)
		expected := map[string]any{"id": "artifact-integrity", "command": artifact["command"], "sourcePath": artifact["path"]}
		if !hasOutputCommand(byKey, expected) || byKey[outputCommandKey(expected)]["reason"] != artifact["policy"] {
			return fmt.Errorf("selective gate plan output artifact-integrity obligation is missing its required command")
		}
	}
	for _, raw := range plan["touchedRequirementWitnesses"].([]any) {
		witness := raw.(map[string]any)
		for _, command := range witness["commands"].([]any) {
			expected := map[string]any{"id": "requirement-witness", "command": command, "sourcePath": witness["path"]}
			if !hasOutputCommand(byKey, expected) || byKey[outputCommandKey(expected)]["reason"] != "changed_requirement_witness" {
				return fmt.Errorf("selective gate plan output requirement-witness obligation is missing its required command")
			}
		}
	}
	return nil
}

func hasOutputCommand(byKey map[string]map[string]any, expected map[string]any) bool {
	actual, exists := byKey[outputCommandKey(expected)]
	if !exists {
		return false
	}
	ownership, declared := expected["commandOwnership"]
	return !declared || actual["commandOwnership"] == ownership
}
