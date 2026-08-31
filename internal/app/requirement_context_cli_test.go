package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementdiff"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementgraph"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestRequirementContextCommandsComposeThroughWholeCLI(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.097109304805955804866101416335094065400345464281933061498534528351192063227949")
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.057550300858348527262188220465911463572498394140028790265329600017071610078423")
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.113360119918311296442974485154252820603874120183883324682989554068354518930712")
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.064478426397925014174625523910101201444776310349803627924470071707127905708426")
	root := t.TempDir()
	tree := map[string]any{
		"schemaVersion": json.Number("2"), "treeId": "consumer.spec-tree", "rootNodeId": "consumer.root",
		"callerAnnotations": []any{}, "edges": []any{}, "overlays": []any{},
		"nodes": []any{map[string]any{
			"nodeId": "consumer.root", "nodeKind": "meta_spec", "label": "Consumer specification", "displayOrder": json.Number("1"),
			"callerAnnotations": []any{},
			"sourceRefs": []any{map[string]any{
				"sourceRefId": "consumer.root.requirements", "sourceRefKind": "source_id",
				"sourceRole": "requirements", "sourceId": "consumer.requirements",
			}},
		}},
	}
	requirementSource := cliRequirementSource("The CLI composes the baseline requirement context.")
	writeCLIJSONFixture(t, root, "proofkit/spec-tree.json", tree)
	writeCLIJSONFixture(t, root, "docs/specs/consumer/requirements.v1.json", requirementSource)
	catalog := map[string]any{
		"schemaVersion": json.Number("1"), "catalogId": "consumer.context",
		"specTree": map[string]any{"path": "proofkit/spec-tree.json"},
		"requirementSources": []any{map[string]any{
			"nodeId": "consumer.root", "path": "docs/specs/consumer/requirements.v1.json",
		}},
	}

	base := runAppJSON(t, []string{"requirement-context-compose", "--input", "-", "--repo-root", root}, catalog)
	if _, err := requirementcontext.AdmitSnapshot(base); err != nil {
		t.Fatalf("whole-CLI context output failed owner admission: %v", err)
	}
	if base["schemaVersion"] != json.Number("2") || base["expectedDigestCoverage"] != "none" || base["baselineVerification"] != nil {
		t.Fatalf("whole-CLI context output did not use the v2 digest-coverage contract: %#v", base)
	}
	slice := runAppJSON(t, []string{"requirement-context-slice", "--input", "-"}, map[string]any{
		"schemaVersion": json.Number("1"), "sliceId": "consumer.context.slice", "context": base,
		"query": map[string]any{"profile": "specification", "requirementIds": []any{"REQ-CONSUMER-001"}},
	})
	if slice["contextKind"] != "proofkit.requirement-context-slice" || slice["state"] != "selected" || slice["snapshotId"] != base["snapshotId"] {
		t.Fatalf("unexpected whole-CLI context slice: %#v", slice)
	}

	requirementSource["requirements"].([]any)[0].(map[string]any)["invariant"] = "The CLI composes the current requirement context."
	writeCLIJSONFixture(t, root, "docs/specs/consumer/requirements.v1.json", requirementSource)
	current := runAppJSON(t, []string{"requirement-context-compose", "--input", "-", "--repo-root", root}, catalog)
	diff := runAppJSON(t, []string{"requirement-semantic-diff", "--input", "-"}, map[string]any{
		"schemaVersion": json.Number("2"), "diffId": "consumer.requirement.diff",
		"baseContext": base, "currentContext": current,
	})
	if diff["changeCount"] != json.Number("1") {
		t.Fatalf("whole-CLI semantic diff changeCount=%v, want 1", diff["changeCount"])
	}
	if diff["schemaVersion"] != json.Number("2") || diff["baseExpectedDigestCoverage"] != "none" || diff["currentExpectedDigestCoverage"] != "none" || diff["baseBaselineVerification"] != nil || diff["currentBaselineVerification"] != nil {
		t.Fatalf("whole-CLI semantic diff did not use the v2 digest-coverage contract: %#v", diff)
	}
	if _, err := requirementdiff.AdmitOutput(diff, current["snapshotId"].(string)); err != nil {
		t.Fatalf("whole-CLI semantic diff failed owner admission: %v", err)
	}

	graph := runAppJSON(t, []string{"requirement-traceability-graph", "--input", "-"}, map[string]any{
		"schemaVersion": json.Number("2"), "graphId": "consumer.requirement.graph", "context": current,
	})
	if _, err := requirementgraph.AdmitOutput(graph, current["snapshotId"].(string)); err != nil {
		t.Fatalf("whole-CLI traceability graph failed owner admission: %v", err)
	}
}

func TestLegacyDigestVocabularyConfinedToV1AdaptersAndFixtures(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	allowed := map[string]struct{}{
		"internal/app/requirement_context_cli_test.go":                   {},
		"internal/command/requirementbrowser/v1_adapter.go":              {},
		"internal/command/requirementbrowser/workspace_test.go":          {},
		"internal/command/requirementcontext/requirementcontext_test.go": {},
		"internal/command/requirementcontext/v1_adapter.go":              {},
		"internal/command/requirementdiff/requirementdiff_test.go":       {},
		"internal/command/requirementdiff/v1_adapter.go":                 {},
		"internal/command/requirementgraph/requirementgraph_test.go":     {},
	}
	legacy := []string{
		"BaselineVerification",
		"baselineVerification",
		"baseBaselineVerification",
		"currentBaselineVerification",
		"partially_verified",
		"Baseline:",
	}
	roots := []string{
		"internal/app",
		"internal/command/requirementbrowser",
		"internal/command/requirementcontext",
		"internal/command/requirementdiff",
		"internal/command/requirementgraph",
		"internal/testsupport/browserfixture",
		"tests/browser",
	}
	for _, root := range roots {
		err := filepath.WalkDir(filepath.Join(repoRoot, root), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			if _, ok := allowed[relative]; ok {
				return nil
			}
			extension := filepath.Ext(relative)
			if extension != ".go" && extension != ".js" && extension != ".json" && extension != ".mjs" {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, token := range legacy {
				if strings.Contains(string(content), token) {
					t.Errorf("legacy digest vocabulary %q escaped into %s", token, relative)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	contract, err := os.ReadFile(filepath.Join(repoRoot, "proofkit/cli-contract.v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range legacy {
		if strings.Contains(string(contract), token) {
			t.Errorf("legacy digest vocabulary %q escaped into proofkit/cli-contract.v2.json", token)
		}
	}
}

func TestConditionSensitiveProofCommandsUseExactRootVariants(t *testing.T) {
	for _, projection := range []struct {
		kind    string
		variant string
	}{
		{kind: "canonical_contract", variant: "01-canonical-contract"},
		{kind: "resolver_input", variant: "02-resolver-input"},
	} {
		t.Run("source-set/"+projection.kind, func(t *testing.T) {
			input := cliProofSourceSetInput(t, projection.kind)
			assertPublicCLIRootVariant(t, "requirement-proof-source-set", "input", "01-root", input)
			output := runAppJSON(t, []string{"requirement-proof-source-set", "--input", "-"}, input)
			assertPublicCLIRootVariant(t, "requirement-proof-source-set", "output", projection.variant, output)
		})
	}

	structured := readCLIJSONObject(t, "proofkit/requirement-bindings.json")
	assertPublicCLIRootVariant(t, "requirement-proof-view", "input", "02-structured", structured)
	structuredOutput := runAppJSON(t, []string{"requirement-proof-view", "--input", "-", "--scope", "graph"}, structured)
	assertPublicCLIRootVariant(t, "requirement-proof-view", "output", "02-structured", structuredOutput)

	compact := cliCompactProofContract()
	assertPublicCLIRootVariant(t, "requirement-proof-view", "input", "01-compact", compact)
	compactOutput := runAppJSON(t, []string{"requirement-proof-view", "--input", "-", "--empty-local-environment-policy"}, compact)
	assertPublicCLIRootVariant(t, "requirement-proof-view", "output", "01-compact", compactOutput)

	directWitnessPlan := cliWitnessPlanDirectInput()
	assertPublicCLIRootVariant(t, "witness-plan", "input", "01-direct", directWitnessPlan)
	_ = runAppJSON(t, []string{"witness-plan", "--input", "-"}, directWitnessPlan)

	projectedWitnessPlan := cliWitnessPlanProjectionInput()
	assertPublicCLIRootVariant(t, "witness-plan", "input", "02-requirement-bindings-projection", projectedWitnessPlan)
	_ = runAppJSON(t, []string{"witness-plan", "--input", "-"}, projectedWitnessPlan)
}

func readCLIJSONObject(t *testing.T, path string) map[string]any {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s must be an object", path)
	}
	return record
}

func cliProofSourceSetInput(t *testing.T, projection string) map[string]any {
	t.Helper()
	fragment := map[string]any{
		"schema_version":        json.Number("2"),
		"contract_kind":         "requirement_proof_route_declaration_fragment",
		"contract_id":           "requirement-proof-route-declarations/fragment/v3",
		"authority_state":       "caller_owned_requirement_proof_route_fragment",
		"normalization_profile": "json/v2:utf8+lf+owner-defaulted-declaration-row-arrays",
		"source_id":             "source.local",
		"surfaces": []any{
			[]any{"source.local", []any{"local-go"}, []any{}},
		},
		"bindings": []any{
			[]any{
				"REQ-PROOFKIT-SOURCE-001",
				"owned_invariant",
				"contract",
				"blocking",
				[]any{"local-go"},
				[]any{"internal/source_test.go::TestPositive", json.Number("0")},
				[]any{"internal/source_test.go::TestNegative", json.Number("1")},
				[]any{"go test ./..."},
				"claim.checked",
			},
		},
	}
	fragmentBytes, err := stablejson.Marshal(fragment)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(fragmentBytes)
	path := "docs/contracts/requirement-proof-routes/local.v3.json"
	return map[string]any{
		"schemaVersion": json.Number("2"),
		"canonicalEnvelope": map[string]any{
			"schemaVersion":        json.Number("2"),
			"contractKind":         "requirement_proof_route_declaration_source",
			"contractId":           "requirement-proof-route-declarations/v2",
			"authorityState":       "caller_owned_requirement_proof_route_source",
			"normalizationProfile": "json/v2:utf8+lf+declaration-row-arrays",
			"nonClaims":            []any{"CLI source-set fixture does not prove repository coverage."},
			"surfaceColumns":       []any{"surface_id", "required_environment_classes", "preconditioned_environment_classes"},
			"bindingColumns":       []any{"requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "blocking_status", "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "declared_mutation_resistance_claim_id"},
			"witnessColumns":       []any{"selector", "environment_classes", "verify_commands", "resolution_order_index"},
		},
		"sourceSet": map[string]any{
			"schema_version":        json.Number("2"),
			"contract_kind":         "requirement_proof_route_declaration_source_set",
			"contract_id":           "requirement-proof-route-declarations/source-set/v2",
			"authority_state":       "caller_owned_requirement_proof_route_source_index",
			"normalization_profile": "json/v2:utf8+lf+ordered-source-refs",
			"source_columns":        []any{"source_id", "path", "sha256", "role", "non_claims"},
			"sources": []any{
				[]any{"source.local", path, hex.EncodeToString(sum[:]), "requirement_proof_route_declaration_fragment", []any{"CLI source owns its fixture rows."}},
			},
			"non_claims": []any{"CLI source-set fixture does not prove repository coverage."},
		},
		"sources":    []any{map[string]any{"path": path, "text": string(fragmentBytes)}},
		"projection": map[string]any{"kind": projection},
	}
}

func cliCompactProofContract() map[string]any {
	return map[string]any{
		"schema_version":        json.Number("2"),
		"authority_state":       "caller_owned_declaration",
		"contract_id":           "proofkit.cli.compact",
		"contract_kind":         "requirement_proof_route_declaration",
		"normalization_profile": "proofkit.compact.declaration.v2",
		"non_claims":            []any{"Compact CLI fixture does not execute witnesses."},
		"surface_columns":       []any{"surface_id", "required_environment_classes", "preconditioned_environment_classes"},
		"surfaces":              []any{[]any{"proofkit.surface", []any{"local-go"}, []any{}}},
		"witness_columns":       []any{"selector", "environment_classes", "verify_commands", "resolution_order_index"},
		"binding_columns":       []any{"requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "blocking_status", "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "declared_mutation_resistance_claim_id"},
		"bindings": []any{[]any{
			"REQ-PROOFKIT-COMPACT-001",
			"proofkit.surface",
			"proofkit.surface::scenario.compact",
			"contract",
			"proofkit.compact",
			"blocking",
			[]any{"local-go"},
			[]any{"tests/positive_test.go::TestPositive", []any{"local-go"}, []any{"go test ./... -run TestPositive"}, json.Number("0")},
			[]any{"tests/negative_test.go::TestNegative", []any{"local-go"}, []any{"go test ./... -run TestNegative"}, json.Number("1")},
			[]any{"go test ./... -run TestPositive", "go test ./... -run TestNegative"},
			"claim.no_known_advisory_gap",
		}},
	}
}

func cliWitnessPlanProjectionInput() map[string]any {
	vocabulary := cliWitnessPlanVocabulary()
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"projection":    "requirement-bindings",
		"vocabulary":    vocabulary,
		"requirementProofBinding": map[string]any{
			"schemaVersion": json.Number("1"),
			"bindingId":     "proofkit.cli.witnessplan.binding",
			"requirements": []any{map[string]any{
				"claimLevel":    "blocking",
				"nonClaims":     []any{"Witness-plan CLI fixture does not execute commands."},
				"ownerId":       "proofkit.witnessplan",
				"proofState":    "witness_backed",
				"requirementId": "REQ-PROOFKIT-WITNESSPLAN-001",
				"specPath":      "docs/specs/proofkit-witnessplan/requirements.v1.json",
			}},
			"bindings": []any{map[string]any{
				"commandIds":         []any{"proofkit.test-command"},
				"environmentClasses": []any{"local-go"},
				"requirementId":      "REQ-PROOFKIT-WITNESSPLAN-001",
				"scenarioId":         "proofkit.witnessplan.scenario",
				"witnessId":          "proofkit.witnessplan.witness",
				"witnessKind":        "contract",
				"witnessPath":        "internal/command/witnessplan/witnessplan_test.go",
			}},
			"witnessCommands": []any{map[string]any{
				"command":          "go test ./internal/command/witnessplan",
				"commandId":        "proofkit.test-command",
				"environmentClass": "local-go",
			}},
			"selection": map[string]any{
				"changedPaths":   []any{},
				"ownerIds":       []any{},
				"requirementIds": []any{},
			},
			"nonClaims": []any{"Witness-plan CLI fixture does not prove command pass evidence."},
		},
	}
}

func cliWitnessPlanDirectInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"vocabulary":    cliWitnessPlanVocabulary(),
		"commands": []any{map[string]any{
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
		}},
	}
}

func cliWitnessPlanVocabulary() map[string]any {
	return map[string]any{
		"artifactKinds":                 []any{"report"},
		"credentialClasses":             []any{"none"},
		"environmentClasses":            []any{"local-go"},
		"nonCacheableCredentialClasses": []any{},
		"parallelGroups":                []any{"local"},
		"maxTimeoutMs":                  json.Number("10000"),
		"environmentClassPolicies": []any{map[string]any{
			"environmentClass":  "local-go",
			"networkPolicies":   []any{"none"},
			"credentialClasses": []any{"none"},
			"cachePolicies":     []any{"disabled"},
		}},
	}
}

func cliRequirementSource(invariant string) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"), "sourceId": "consumer.requirements",
		"specPackagePath": "docs/specs/consumer", "overviewPath": "docs/specs/consumer/overview.md",
		"requirementsPath": "docs/specs/consumer/requirements.v1.json",
		"requirements": []any{map[string]any{
			"requirementId": "REQ-CONSUMER-001", "ownerId": "consumer.owner", "invariant": invariant,
			"claimLevel": "blocking", "riskClass": "high",
			"proofBindingRefs": []any{"proofkit/requirement-bindings.json"}, "nonClaimRefs": []any{"NC-CONSUMER-001"},
			"nonClaims":    []any{"This requirement does not approve merge."},
			"lifecycle":    map[string]any{"state": "active", "replacementRequirementIds": []any{}, "evidenceRefs": []any{}},
			"deferral":     nil,
			"updatePolicy": map[string]any{"reviewOwnerId": "consumer.owner", "requiresImpactDeclaration": true, "requiresProofBindingReview": true},
		}},
		"nonClaims": []any{"This source does not execute proof witnesses."},
	}
}

func runAppJSON(t *testing.T, args []string, input any) map[string]any {
	t.Helper()
	encoded, err := stablejson.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exit := Run(context.Background(), args, bytes.NewReader(encoded), &stdout, &stderr); exit != 0 {
		t.Fatalf("Run(%v) exit=%d stderr=%s stdout=%s", args, exit, stderr.String(), stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("Run(%v) wrote stderr on success: %s", args, stderr.String())
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(stdout.Bytes()), int64(stdout.Len()))
	if err != nil {
		t.Fatalf("Run(%v) emitted invalid JSON: %v", args, err)
	}
	record, ok := decoded.(map[string]any)
	if !ok {
		t.Fatalf("Run(%v) output is not an object", args)
	}
	return record
}

func writeCLIJSONFixture(t *testing.T, root, path string, value any) {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}
