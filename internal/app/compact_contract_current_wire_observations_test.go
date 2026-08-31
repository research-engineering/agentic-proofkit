package app

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbrowser"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
)

func currentCompactV2WireObservations(t *testing.T) map[string]any {
	t.Helper()
	compactInput := compactV2WireContract()
	contract, err := compactproofcontract.Admit(compactInput)
	if err != nil {
		t.Fatalf("admit current compact wire contract: %v", err)
	}
	resolver, err := contract.ResolverProjection(compactproofcontract.ResolverOptions{LocalEnvironmentClasses: []string{"local-go"}})
	if err != nil {
		t.Fatalf("build current compact resolver observation: %v", err)
	}
	adoptionInput := strictJSONObjectFromText(t, cliAdoptionContractEnvelopeInput(), "current adoption aggregate input")
	pilotDirect := cliPilotInput("proofkit.cli.pilot.first", false)
	pilotEnvelope := strictJSONObjectFromText(t, cliPilotContractEnvelopeInput("all"), "current pilot envelope input")
	conformanceInput := strictJSONObjectFromText(t, cliConformanceProfileInput(), "current conformance input")
	conformanceOutput := runCLIForJSON(t, []string{"conformance-profile", "--input", "-", "--profile", "local"}, cliJSON(conformanceInput))

	impactFixture := strings.Replace(
		cliImpactInputComposeInput(),
		`"paths":["docs/specs/proofkit-cli-impact/requirements.v1.json"]`,
		`"paths":["docs/specs/proofkit-cli-impact/requirements.v1.json","internal/app/cli_abi_test.go"]`,
		1,
	)
	impactComposeInput := strictJSONObjectFromText(t, impactFixture, "current impact compose input")
	impactInput := runCLIForJSON(t, []string{"requirement-impact-input-compose", "--input", "-"}, cliJSON(impactComposeInput))
	impactOutput := runCLIForJSON(t, []string{"impact", "--input", "-"}, cliJSON(impactInput))

	sourceInput := cliProofSourceSetInput(t, "canonical_contract")
	sourceOutput := runAppJSON(t, []string{"requirement-proof-source-set", "--input", "-"}, sourceInput)
	sourceFragment := strictJSONObjectFromText(t, sourceInput["sources"].([]any)[0].(map[string]any)["text"].(string), "current compact source fragment")
	sourceRow := compactSourceRoleObservation(t, sourceInput["sourceSet"].(map[string]any))

	coverageComposeInput := strictJSONObjectFromText(t, cliCoverageInputComposeInput(), "current coverage compose input")
	coverageInput := runCLIForJSON(t, []string{"requirement-coverage-input-compose", "--input", "-"}, cliJSON(coverageComposeInput))
	coverageOutput := runCLIForJSON(t, []string{"requirement-coverage-view", "--input", "-", "--format", "json"}, cliJSON(coverageInput))
	coverageScenario := firstCompactCoverageScenario(t, coverageOutput)

	inventoryInput := strictJSONObjectFromText(t, cliProofBindingDerivedInventoryInput(), "current proof-binding inventory input")
	inventoryOutput := runCLIForJSON(t, []string{"test-evidence-inventory", "--input", "-", "--projection", "proof-binding-derived", "--normalized-inventory"}, cliJSON(inventoryInput))
	proofViewOutput := runCLIForJSON(t, []string{"requirement-proof-view", "--input", "-", "--format", "json", "--local-environment-class", "local-go"}, cliJSON(compactInput))

	result := map[string]any{
		compactWireObservationKey("adoption-contract-envelope", "input", "aggregate"):            adoptionInput,
		compactWireObservationKey("compact-contract", "input", "direct"):                         compactInput,
		compactWireObservationKey("compact-resolver", "output", "resolver"):                      resolver,
		compactWireObservationKey("conformance-profile", "input", "direct"):                      conformanceInput,
		compactWireObservationKey("conformance-profile", "output", "profile"):                    conformanceOutput,
		compactWireObservationKey("impact", "input", "direct"):                                   impactInput,
		compactWireObservationKey("impact", "output", "direct"):                                  impactOutput,
		compactWireObservationKey("pilot-admission", "input", "direct"):                          pilotDirect,
		compactWireObservationKey("pilot-admission", "input", "envelope"):                        pilotEnvelope,
		compactWireObservationKey("requirement-coverage-input-compose", "input", "wrapper"):      coverageComposeInput,
		compactWireObservationKey("requirement-coverage-input-compose", "output", "wrapper"):     coverageInput,
		compactWireObservationKey("requirement-coverage-view", "input", "wrapper"):               coverageInput,
		compactWireObservationKey("requirement-coverage-view", "output", "compact-scenario"):     coverageScenario,
		compactWireObservationKey("requirement-coverage-view", "output", "root"):                 coverageOutput,
		compactWireObservationKey("requirement-impact-input-compose", "input", "wrapper"):        impactComposeInput,
		compactWireObservationKey("requirement-impact-input-compose", "output", "wrapper"):       impactInput,
		compactWireObservationKey("requirement-proof-resolver", "output", "resolver"):            resolver,
		compactWireObservationKey("requirement-proof-source-set", "input", "canonical-envelope"): sourceInput["canonicalEnvelope"],
		compactWireObservationKey("requirement-proof-source-set", "input", "fragment"):           sourceFragment,
		compactWireObservationKey("requirement-proof-source-set", "input", "source-row"):         sourceRow,
		compactWireObservationKey("requirement-proof-source-set", "input", "source-set"):         sourceInput["sourceSet"],
		compactWireObservationKey("requirement-proof-source-set", "input", "wrapper"):            sourceInput,
		compactWireObservationKey("requirement-proof-source-set", "output", "wrapper"):           sourceOutput,
		compactWireObservationKey("requirement-proof-view", "input", "compact"):                  compactInput,
		compactWireObservationKey("requirement-proof-view", "output", "compact"):                 proofViewOutput,
		compactWireObservationKey("test-evidence-inventory", "input", "proof-binding"):           inventoryInput,
		compactWireObservationKey("test-evidence-inventory", "output", "normalized"):             inventoryOutput,
	}
	for key, observation := range currentCompactParentContractObservations(t) {
		result[key] = observation
	}
	for key, observation := range currentCompactContextChainObservations(t) {
		result[key] = observation
	}
	return result
}

func currentCompactContextChainObservations(t *testing.T) map[string]any {
	t.Helper()
	root := t.TempDir()
	coverageCompose := strictJSONObjectFromText(t, cliCoverageInputComposeInput(), "compact context coverage compose input")
	coverageInput := runCLIForJSON(t, []string{"requirement-coverage-input-compose", "--input", "-"}, cliJSON(coverageCompose))
	requirementSource := coverageCompose["requirementSource"].(map[string]any)
	sourceID := requirementSource["sourceId"].(string)
	tree := map[string]any{
		"schemaVersion": json.Number("2"), "treeId": "proofkit.compact.context-tree", "rootNodeId": "proofkit.compact.context-root",
		"callerAnnotations": []any{}, "edges": []any{}, "overlays": []any{},
		"nodes": []any{map[string]any{
			"nodeId": "proofkit.compact.context-root", "nodeKind": "meta_spec", "label": "Compact context fixture", "displayOrder": json.Number("1"),
			"callerAnnotations": []any{},
			"sourceRefs": []any{map[string]any{
				"sourceRefId": "proofkit.compact.context-root.requirements", "sourceRefKind": "source_id",
				"sourceRole": "requirements", "sourceId": sourceID,
			}},
		}},
	}
	writeCLIJSONFixture(t, root, "proofkit/spec-tree.json", tree)
	writeCLIJSONFixture(t, root, "docs/specs/compact/requirements.v1.json", requirementSource)
	writeCLIJSONFixture(t, root, "proofkit/coverage-input.json", coverageInput)
	catalog := map[string]any{
		"schemaVersion": json.Number("1"), "catalogId": "proofkit.compact.context",
		"specTree": map[string]any{"path": "proofkit/spec-tree.json"},
		"requirementSources": []any{map[string]any{
			"nodeId": "proofkit.compact.context-root", "path": "docs/specs/compact/requirements.v1.json",
		}},
		"coverage": map[string]any{"path": "proofkit/coverage-input.json"},
	}
	base := runAppJSON(t, []string{"requirement-context-compose", "--input", "-", "--repo-root", root}, catalog)
	sliceInput := map[string]any{
		"schemaVersion": json.Number("1"), "sliceId": "proofkit.compact.context.slice", "context": base,
		"query": map[string]any{"profile": "coverage", "requirementIds": []any{"REQ-PROOFKIT-CLI-COVERAGE-001"}},
	}
	sliceOutput := runAppJSON(t, []string{"requirement-context-slice", "--input", "-"}, sliceInput)

	requirements := requirementSource["requirements"].([]any)
	requirements[0].(map[string]any)["invariant"] = "Compact context fixture changed invariant."
	writeCLIJSONFixture(t, root, "docs/specs/compact/requirements.v1.json", requirementSource)
	current := runAppJSON(t, []string{"requirement-context-compose", "--input", "-", "--repo-root", root}, catalog)
	diffInput := map[string]any{
		"schemaVersion": json.Number("2"), "diffId": "proofkit.compact.context.diff",
		"baseContext": base, "currentContext": current,
	}
	diffOutput := runAppJSON(t, []string{"requirement-semantic-diff", "--input", "-"}, diffInput)
	graphInput := map[string]any{
		"schemaVersion": json.Number("2"), "graphId": "proofkit.compact.context.graph", "context": current,
	}
	graphOutput := runAppJSON(t, []string{"requirement-traceability-graph", "--input", "-"}, graphInput)
	workspaceInput := map[string]any{
		"schemaVersion": json.Number("2"), "workspaceId": "proofkit.compact.context.workspace", "context": current,
		"diffInput": diffInput, "graphInput": graphInput,
	}
	browserHandle, err := requirementbrowser.StartServer(workspaceInput, requirementbrowser.Options{Host: "127.0.0.1", Port: 0, PortSet: true, View: "workspace"})
	if err != nil {
		t.Fatalf("start compact context workspace server: %v", err)
	}
	closeCompactObservationServer(t, browserHandle)

	baseCoverage := jsonObjectField(t, jsonObjectField(t, base, "projections"), "coverage")
	currentCoverage := jsonObjectField(t, jsonObjectField(t, current, "projections"), "coverage")
	sliceCoverage := jsonObjectField(t, jsonObjectField(t, sliceOutput, "projections"), "coverage")
	baseIdentity := compactCoverageIdentityObservation(t, baseCoverage)
	assertCompactIdentityObservation(t, sliceCoverage, baseIdentity, "context slice output")
	assertCompactIdentityObservation(t, currentCoverage, baseIdentity, "current context output")
	if diffOutput["baseSnapshotId"] != base["snapshotId"] || diffOutput["currentSnapshotId"] != current["snapshotId"] {
		t.Fatalf("semantic diff output lost context identity: base=%v current=%v", diffOutput["baseSnapshotId"], diffOutput["currentSnapshotId"])
	}
	if graphOutput["snapshotId"] != current["snapshotId"] {
		t.Fatalf("traceability graph output snapshotId=%v want %v", graphOutput["snapshotId"], current["snapshotId"])
	}
	if browserHandle.SnapshotID != current["snapshotId"] {
		t.Fatalf("browser runtime snapshotId=%v want %v", browserHandle.SnapshotID, current["snapshotId"])
	}
	baseCoverageDigest := compactWireValueDigest(t, baseCoverage)
	return map[string]any{
		compactWireObservationKey("requirement-browser-server", "output", "workspace-runtime"): map[string]any{
			"snapshotId": browserHandle.SnapshotID,
		},
		compactWireObservationKey("requirement-context-compose", "output", "coverage-runtime"): map[string]any{
			"coverageSha256": baseCoverageDigest, "identities": baseIdentity,
		},
		compactWireObservationKey("requirement-context-slice", "output", "coverage-runtime"): map[string]any{
			"coverageSha256": compactWireValueDigest(t, sliceCoverage), "identities": compactCoverageIdentityObservation(t, sliceCoverage),
		},
		compactWireObservationKey("requirement-semantic-diff", "output", "coverage-runtime"): map[string]any{
			"baseSnapshotId": diffOutput["baseSnapshotId"], "currentSnapshotId": diffOutput["currentSnapshotId"],
			"outputSha256": compactWireValueDigest(t, diffOutput),
		},
		compactWireObservationKey("requirement-traceability-graph", "output", "coverage-runtime"): map[string]any{
			"outputSha256": compactWireValueDigest(t, graphOutput), "snapshotId": graphOutput["snapshotId"],
		},
	}
}

func compactCoverageIdentityObservation(t *testing.T, value any) map[string]any {
	t.Helper()
	bindingIDs := map[string]struct{}{}
	routeIDs := map[string]struct{}{}
	collectCompactIdentityValues(value, bindingIDs, routeIDs)
	if len(bindingIDs) == 0 || len(routeIDs) == 0 {
		t.Fatalf("compact coverage projection has no stable identities: bindings=%v routes=%v", sortedSetKeys(bindingIDs), sortedSetKeys(routeIDs))
	}
	return map[string]any{
		"bindingRecordIds": stringsToAny(sortedSetKeys(bindingIDs)),
		"witnessRouteIds":  stringsToAny(sortedSetKeys(routeIDs)),
	}
}

func collectCompactIdentityValues(value any, bindingIDs, routeIDs map[string]struct{}) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if text, ok := child.(string); ok {
				switch key {
				case "bindingRecordId":
					bindingIDs[text] = struct{}{}
				case "witnessRouteId":
					routeIDs[text] = struct{}{}
				}
			}
			collectCompactIdentityValues(child, bindingIDs, routeIDs)
		}
	case []any:
		for _, child := range typed {
			collectCompactIdentityValues(child, bindingIDs, routeIDs)
		}
	}
}

func assertCompactIdentityObservation(t *testing.T, value any, want map[string]any, context string) {
	t.Helper()
	got := compactCoverageIdentityObservation(t, value)
	if !compactJSONEqual(got, want) {
		t.Fatalf("%s identity projection=%v want %v", context, got, want)
	}
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func closeCompactObservationServer(t *testing.T, handle requirementbrowser.ServerHandle) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := handle.Close(ctx); err != nil {
		t.Fatalf("close compact context workspace server: %v", err)
	}
	select {
	case err := <-handle.Done():
		if err != nil {
			t.Fatalf("wait for compact context workspace server: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("wait for compact context workspace server: %v", ctx.Err())
	}
}

func compactWireValueDigest(t *testing.T, value any) string {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode compact nested wire value: %v", err)
	}
	return sha256Text(string(content))
}

func currentCompactParentContractObservations(t *testing.T) map[string]any {
	t.Helper()
	contract := readCLIContract(t)
	commands := make(map[string]cliContractCommand, len(contract.Commands))
	for _, command := range contract.Commands {
		commands[command.Command] = command
	}
	result := map[string]any{}
	for _, key := range expectedCompactWireObservationKeys {
		parts := strings.Split(key, "|")
		if len(parts) != 3 || parts[2] != "union" {
			continue
		}
		command, ok := commands[parts[0]]
		if !ok {
			t.Fatalf("expected parent observation references unknown command %s", parts[0])
		}
		raw := command.InputContract
		if parts[1] == "output" {
			raw = command.OutputContract
		}
		if raw == nil {
			t.Fatalf("expected parent observation %s has no contract", key)
		}
		content, err := json.Marshal(raw)
		if err != nil {
			t.Fatalf("encode expected parent observation %s: %v", key, err)
		}
		value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
		if err != nil {
			t.Fatalf("admit expected parent observation %s: %v", key, err)
		}
		record := value.(map[string]any)
		result[key] = map[string]any{"contract": record}
	}
	return result
}

func compactSourceRoleObservation(t *testing.T, sourceSet map[string]any) map[string]any {
	t.Helper()
	columns := sourceSet["source_columns"].([]any)
	rows := sourceSet["sources"].([]any)
	if len(rows) == 0 {
		t.Fatal("current source set has no source rows")
	}
	row := rows[0].([]any)
	for index, raw := range columns {
		if raw == "role" {
			return map[string]any{"role": row[index]}
		}
	}
	t.Fatal("current source set has no role column")
	return nil
}

func firstCompactCoverageScenario(t *testing.T, report map[string]any) map[string]any {
	t.Helper()
	requirements := report["requirementCoverage"].([]any)
	if len(requirements) == 0 {
		t.Fatal("current compact coverage report has no requirements")
	}
	scenarios := requirements[0].(map[string]any)["scenarios"].([]any)
	if len(scenarios) == 0 {
		t.Fatal("current compact coverage report has no scenarios")
	}
	return scenarios[0].(map[string]any)
}
