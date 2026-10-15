package pilotadmission

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func validStackDiversePilotInput() map[string]any {
	input := validPilotInput()
	input["pilotId"] = "proofkit.test.pilot.stack-diverse"
	input["stackDiversity"] = validStackDiversity()
	input["cacheNegativeChecks"] = validCacheNegativeChecks()
	impactInput := input["impactDemos"].([]any)[0].(map[string]any)["impactInput"].(map[string]any)
	impactInput["changedBindingRecordIds"] = []any{pilotTestBindingRecordID}
	impactInput["changedPaths"] = []any{"docs/specs/proofkit/requirements.v1.json", "internal/proofkit/witness_test.go"}
	impactInput["changedWitnessPathCoverage"] = []any{map[string]any{
		"path": "internal/proofkit/witness_test.go",
		"routes": []any{map[string]any{
			"bindingRecordId": pilotTestBindingRecordID, "resolutionOrderIndex": json.Number("0"),
			"role": "positive", "selector": pilotTestWitnessSelector, "witnessRouteId": pilotTestWitnessRouteID,
		}},
	}}
	return input
}

type pilotAdmissionCase struct {
	name     string
	mutate   func(map[string]any)
	failed   bool // admitted, but the report fails
	semantic bool // natively refused by a policy the structure names but does not express
}

func pilotAdmissionCorpus() []pilotAdmissionCase {
	set := func(path []string, value any) func(map[string]any) {
		return func(input map[string]any) {
			var current any = input
			for _, key := range path[:len(path)-1] {
				switch typed := current.(type) {
				case map[string]any:
					current = typed[key]
				case []any:
					current = typed[0]
				}
			}
			current.(map[string]any)[path[len(path)-1]] = value
		}
	}
	remove := func(path ...string) func(map[string]any) {
		return func(input map[string]any) {
			var current any = input
			for _, key := range path[:len(path)-1] {
				switch typed := current.(type) {
				case map[string]any:
					current = typed[key]
				case []any:
					current = typed[0]
				}
			}
			delete(current.(map[string]any), path[len(path)-1])
		}
	}
	route := []string{"agentReportRoutes", "0"}
	demo := []string{"impactDemos", "0"}
	customRule := map[string]any{"downgradeGenericFailures": false, "owner": "owner", "purpose": "purpose", "ruleId": "proofkit.custom.rule"}
	return []pilotAdmissionCase{
		{name: "valid", mutate: func(map[string]any) {}},
		{name: "root-foreign", mutate: set([]string{"foreign"}, true)},
		{name: "version-one", mutate: set([]string{"schemaVersion"}, json.Number("1"))},
		{name: "version-text", mutate: set([]string{"schemaVersion"}, "2")},
		{name: "pilot-id", mutate: set([]string{"pilotId"}, "1bad")},
		{name: "pilot-id-limit", mutate: set([]string{"pilotId"}, strings.Repeat("A", 256))},
		{name: "pilot-id-bound", mutate: set([]string{"pilotId"}, strings.Repeat("A", 257))},
		{name: "pilot-id-missing", mutate: remove("pilotId")},
		{name: "profile-type", mutate: set([]string{"profile"}, []any{})},
		{name: "profile-foreign", mutate: set([]string{"profile", "foreign"}, true)},
		{name: "profile-repository-id", mutate: remove("profile", "repositoryId")},
		{name: "profile-class-blank", mutate: set([]string{"profile", "repositoryClass"}, " \t")},
		{name: "profile-languages-empty", mutate: set([]string{"profile", "primaryLanguages"}, []any{})},
		{name: "profile-languages-duplicate", mutate: set([]string{"profile", "primaryLanguages"}, []any{"go", "go"})},
		{name: "profile-languages-unsorted", mutate: set([]string{"profile", "primaryLanguages"}, []any{"ts", "go"})},
		{name: "profile-languages-trimmed-duplicate", mutate: set([]string{"profile", "primaryLanguages"}, []any{"go", " go"}), semantic: true},
		{name: "profile-policy", mutate: set([]string{"profile", "structuredWitnessCommands"}, false), failed: true},
		{name: "profile-policy-absent", mutate: remove("profile", "commandMatcherBridge"), failed: true},
		{name: "blocking-type", mutate: set([]string{"blockingRequirements"}, "x")},
		{name: "blocking-empty", mutate: set([]string{"blockingRequirements"}, map[string]any{}), failed: true},
		{name: "blocking-foreign", mutate: set([]string{"blockingRequirements", "foreign"}, true), failed: true},
		{name: "blocking-records", mutate: set([]string{"blockingRequirements", "requirements"}, []any{7}), failed: true},
		{name: "routes-missing", mutate: remove("agentReportRoutes")},
		{name: "routes-type", mutate: set([]string{"agentReportRoutes"}, map[string]any{})},
		{name: "routes-empty", mutate: set([]string{"agentReportRoutes"}, []any{}), failed: true},
		{name: "route-type", mutate: set([]string{"agentReportRoutes"}, []any{"route"})},
		{name: "route-foreign", mutate: set(append(route, "foreign"), true), failed: true},
		{name: "route-command-missing", mutate: remove(append(route, "command")...)},
		{name: "route-command-shell", mutate: set(append(route, "command"), "agentic-proofkit render && curl example.test"), semantic: true},
		{name: "route-path-blank", mutate: set(append(route, "artifactPath"), " ")},
		{name: "route-path-absolute", mutate: set(append(route, "artifactPath"), "/tmp/report.json"), semantic: true},
		{name: "route-path-trimmed", mutate: set(append(route, "artifactPath"), " artifacts/report.json ")},
		{name: "route-task", mutate: set(append(route, "taskType"), "bad task")},
		{name: "route-duplicate", mutate: func(input map[string]any) {
			routes := input["agentReportRoutes"].([]any)
			input["agentReportRoutes"] = append(routes, routes[0])
		}, failed: true},
		{name: "scheduler-type", mutate: set([]string{"cacheScheduler"}, false)},
		{name: "scheduler-groups-missing", mutate: remove("cacheScheduler", "parallelGroups")},
		{name: "scheduler-groups-empty", mutate: set([]string{"cacheScheduler", "parallelGroups"}, []any{})},
		{name: "scheduler-groups-duplicate", mutate: set([]string{"cacheScheduler", "parallelGroups"}, []any{"a", "a"})},
		{name: "scheduler-foreign", mutate: set([]string{"cacheScheduler", "foreign"}, true), failed: true},
		{name: "scheduler-policy", mutate: set([]string{"cacheScheduler", "schedulerPolicy"}, 1), failed: true},
		{name: "scheduler-paths", mutate: set([]string{"cacheScheduler", "cacheKeyInputs"}, "go.mod"), failed: true},
		{name: "timing-type", mutate: set([]string{"timingBudget"}, nil)},
		{name: "timing-path-missing", mutate: remove("timingBudget", "reportArtifactPath")},
		{name: "timing-seconds", mutate: set([]string{"timingBudget", "maxAddedSeconds"}, "five"), failed: true},
		{name: "timing-foreign", mutate: set([]string{"timingBudget", "foreign"}, true), failed: true},
		{name: "infrastructure-type", mutate: set([]string{"infrastructureBudget"}, []any{})},
		{name: "rules-type", mutate: set([]string{"infrastructureBudget", "customRules"}, "none"), failed: true},
		{name: "rules-absent", mutate: remove("infrastructureBudget", "customRules"), failed: true},
		{name: "rules-item", mutate: set([]string{"infrastructureBudget", "customRules"}, []any{7})},
		{name: "rules-owner", mutate: set([]string{"infrastructureBudget", "customRules"}, []any{map[string]any{"purpose": "p", "ruleId": "proofkit.rule"}})},
		{name: "rules-valid", mutate: func(input map[string]any) {
			budget := input["infrastructureBudget"].(map[string]any)
			budget["customRules"], budget["customRuleCount"], budget["maxCustomRuleCount"] = []any{customRule}, json.Number("1"), json.Number("1")
		}},
		{name: "rules-foreign", mutate: func(input map[string]any) {
			rule := map[string]any{"foreign": true}
			for key, value := range customRule {
				rule[key] = value
			}
			input["infrastructureBudget"].(map[string]any)["customRules"] = []any{rule}
		}, failed: true},
		{name: "false-positive-type", mutate: set([]string{"falsePositiveBudget"}, 1)},
		{name: "false-positive-owner", mutate: remove("falsePositiveBudget", "dispositionOwner")},
		{name: "false-positive-foreign", mutate: set([]string{"falsePositiveBudget", "foreign"}, true), failed: true},
		{name: "rollback-type", mutate: set([]string{"rollback"}, "x")},
		{name: "rollback-foreign", mutate: set([]string{"rollback", "foreign"}, true)},
		{name: "rollback-pin", mutate: remove("rollback", "versionPin")},
		{name: "rollback-shell", mutate: set([]string{"rollback", "rollbackCommand"}, "revert; rm -rf x"), semantic: true},
		{name: "demos-empty", mutate: set([]string{"impactDemos"}, []any{}), failed: true},
		{name: "demos-text", mutate: set([]string{"impactDemos"}, "none"), failed: true},
		{name: "demos-item", mutate: set([]string{"impactDemos"}, []any{7})},
		{name: "demos-ignore-single", mutate: set([]string{"impactDemo"}, 7)},
		{name: "demo-single", mutate: func(input map[string]any) {
			input["impactDemo"] = input["impactDemos"].([]any)[0]
			delete(input, "impactDemos")
		}},
		{name: "demo-single-null", mutate: func(input map[string]any) {
			input["impactDemo"] = nil
			delete(input, "impactDemos")
		}},
		{name: "demo-single-overrides-text", mutate: func(input map[string]any) {
			input["impactDemo"] = 7
			input["impactDemos"] = "ignored"
		}},
		{name: "demo-foreign", mutate: set(append(demo, "foreign"), true), failed: true},
		{name: "demo-id-null", mutate: set(append(demo, "demoId"), nil)},
		{name: "demo-id-absent", mutate: remove(append(demo, "demoId")...)},
		{name: "demo-id", mutate: set(append(demo, "demoId"), "bad id")},
		{name: "demo-input-missing", mutate: remove(append(demo, "impactInput")...)},
		{name: "demo-input-empty", mutate: set(append(demo, "impactInput"), map[string]any{})},
		{name: "demo-input-version", mutate: set(append(demo, "impactInput", "schemaVersion"), json.Number("1"))},
		{name: "demo-paths", mutate: set(append(demo, "sourceOwnedChangedPaths"), "x"), failed: true},
		{name: "diversity-null", mutate: set([]string{"stackDiversity"}, nil)},
		{name: "diversity-type", mutate: set([]string{"stackDiversity"}, "x")},
		{name: "diversity-baseline", mutate: set([]string{"stackDiversity"}, map[string]any{"dimensions": []any{}})},
		{name: "diversity-dimensions", mutate: set([]string{"stackDiversity"}, map[string]any{"baselinePilotId": "proofkit.base", "dimensions": "x"})},
		{name: "diversity-empty", mutate: set([]string{"stackDiversity"}, map[string]any{"baselinePilotId": "proofkit.base", "dimensions": []any{}})},
		{name: "diversity-item", mutate: set([]string{"stackDiversity"}, map[string]any{"baselinePilotId": "proofkit.base", "dimensions": []any{1}})},
		{name: "diversity-item-text", mutate: set([]string{"stackDiversity"}, map[string]any{"baselinePilotId": "proofkit.base", "dimensions": []any{map[string]any{"baseline": "a", "candidate": "b"}}})},
		{name: "diversity-item-open", mutate: set([]string{"stackDiversity"}, map[string]any{"baselinePilotId": "proofkit.base", "foreign": 1, "dimensions": []any{map[string]any{"baseline": "a", "candidate": "b", "evidence": "e", "dimension": 7, "foreign": 1}}}), failed: true},
		{name: "checks-null", mutate: set([]string{"cacheNegativeChecks"}, nil)},
		{name: "checks-absent", mutate: remove("cacheNegativeChecks")},
		{name: "checks-type", mutate: set([]string{"cacheNegativeChecks"}, map[string]any{})},
		{name: "checks-item", mutate: set([]string{"cacheNegativeChecks"}, []any{"x"})},
		{name: "checks-evidence", mutate: set([]string{"cacheNegativeChecks"}, []any{map[string]any{"checkId": "proofkit.check", "evidence": ""}})},
		{name: "checks-open", mutate: set([]string{"cacheNegativeChecks"}, []any{map[string]any{"checkId": "proofkit.check", "evidence": "e", "foreign": 1}}), failed: true},
		{name: "claims-empty", mutate: set([]string{"nonClaims"}, []any{})},
		{name: "claims-missing", mutate: remove("nonClaims")},
		{name: "claims-duplicate", mutate: set([]string{"nonClaims"}, []any{"a", "a"})},
		{name: "claims-secret", mutate: set([]string{"nonClaims"}, []any{"api_" + "key=synthetic-structure-fixture"}), semantic: true},
		{name: "mode", mutate: set([]string{"pilotMode"}, "blocking"), failed: true},
		{name: "mode-absent", mutate: remove("pilotMode"), failed: true},
		{name: "rollout", mutate: set([]string{"rolloutClaim"}, true), failed: true},
		{name: "package-ref", mutate: set([]string{"packageVersionRef"}, 7), failed: true},
		{name: "package-ref-absent", mutate: remove("packageVersionRef"), failed: true},
		{name: "metrics", mutate: set([]string{"metrics"}, []any{nil, map[string]any{"x": 1}})},
	}
}

func TestPilotInputStructuresAgreeWithNativeAdmission(t *testing.T) {
	direct := InputStructure()
	contracts := map[string]map[string]any{
		"input": ContractInputStructure("input"), "stackDiverseInput": ContractInputStructure("stackDiverseInput"),
	}
	all := ContractInputStructure("input", "stackDiverseInput")
	for _, item := range pilotAdmissionCorpus() {
		t.Run(item.name, func(t *testing.T) {
			input := validPilotInput()
			item.mutate(input)
			structural := schemacheck.Validate(direct, input) == nil
			for _, options := range []Options{{}, {RequireStackDiverseReleaseCandidate: true}} {
				record, code, err := Build(input, options)
				if (err == nil) != (item.semantic || structural) && !item.semantic {
					t.Fatalf("structure=%t native=%v", structural, err)
				}
				if item.semantic && (err == nil || !structural) {
					t.Fatalf("semantic case must be structurally accepted and natively refused: %v", err)
				}
				if err == nil && !options.RequireStackDiverseReleaseCandidate && (record.State == "failed") != item.failed {
					t.Fatalf("state=%s exit=%d, want failed=%t: %#v", record.State, code, item.failed, record.RuleResults)
				}
			}
			for field, schema := range contracts {
				envelope := map[string]any{"schema": contractEnvelopeSchema, field: input}
				_, _, err := BuildFromContractEnvelope(envelope, field, Options{})
				if (schemacheck.Validate(schema, envelope) == nil) != structural || (err == nil) != (structural && !item.semantic) {
					t.Fatalf("%s contract envelope changed the direct domain: %v", field, err)
				}
			}
			pair := map[string]any{"schema": contractEnvelopeSchema, "input": input, "stackDiverseInput": validStackDiversePilotInput()}
			_, _, _, _, err := BuildAllFromContractEnvelope(pair)
			if (schemacheck.Validate(all, pair) == nil) != structural || (err == nil) != (structural && !item.semantic) {
				t.Fatalf("all contract envelope changed the direct domain: %v", err)
			}
		})
	}
	for name, envelope := range map[string]map[string]any{
		"header":    {"schema": "proofkit.pilot-admission.v1", "input": validPilotInput()},
		"foreign":   {"schema": contractEnvelopeSchema, "input": validPilotInput(), "stackDiverseInput": validPilotInput()},
		"type":      {"schema": contractEnvelopeSchema, "input": []any{}},
		"missing":   {"schema": contractEnvelopeSchema},
		"no-header": {"input": validPilotInput()},
	} {
		if _, _, err := BuildFromContractEnvelope(envelope, "input", Options{}); err == nil || schemacheck.Validate(contracts["input"], envelope) == nil {
			t.Fatalf("%s: malformed contract envelope accepted", name)
		}
	}
}

func TestPilotReportStructuresAcceptEveryReportState(t *testing.T) {
	report, pair := ReportStructure(), AllOutputStructure()
	states := map[string]bool{}
	inputs := []map[string]any{validPilotInput(), validStackDiversePilotInput()}
	for _, item := range pilotAdmissionCorpus() {
		input := validPilotInput()
		item.mutate(input)
		inputs = append(inputs, input)
	}
	for _, input := range inputs {
		for _, options := range []Options{{}, {RequireStackDiverseReleaseCandidate: true}} {
			record, code, err := Build(input, options)
			if err != nil {
				continue
			}
			states[record.State] = true
			if (code == 0) != (record.State == "passed") {
				t.Fatal("report state and exit code diverged")
			}
			if err := schemacheck.Validate(report, record.JSONValue()); err != nil {
				t.Fatalf("%s report: %v", record.State, err)
			}
		}
		first, _, stack, _, err := BuildAllFromContractEnvelope(map[string]any{"schema": contractEnvelopeSchema, "input": input, "stackDiverseInput": input})
		if err == nil {
			if err := schemacheck.Validate(pair, []any{first.JSONValue(), stack.JSONValue()}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !states["passed"] || !states["failed"] {
		t.Fatalf("corpus did not reach both report states: %v", states)
	}
	passed, _, _ := Build(validPilotInput(), Options{})
	failed, _, _ := Build(validPilotInput(), Options{RequireStackDiverseReleaseCandidate: true})
	for name, mutate := range map[string]func(map[string]any){
		"passed-failure-rule":  func(value map[string]any) { value["ruleResults"] = failed.JSONValue()["ruleResults"] },
		"passed-pilot-mode":    func(value map[string]any) { value["summary"].(map[string]any)["pilotMode"] = "blocking" },
		"passed-copied-file":   func(value map[string]any) { value["summary"].(map[string]any)["copiedVerifierFileCount"] = 1 },
		"negative-seconds":     func(value map[string]any) { value["summary"].(map[string]any)["maxAddedSeconds"] = -1 },
		"foreign-root":         func(value map[string]any) { value["foreign"] = true },
		"diagnostic-order":     func(value map[string]any) { d := value["diagnostics"].([]any); d[0], d[1] = d[1], d[0] },
		"impact-state":         func(value map[string]any) { setDemoState(value, "unknown") },
		"report-kind":          func(value map[string]any) { value["reportKind"] = "proofkit.foreign" },
		"empty-claims":         func(value map[string]any) { value["nonClaims"] = []any{} },
		"rule-diagnostics":     func(value map[string]any) { value["ruleResults"].([]any)[0].(map[string]any)["diagnostics"] = []any{1} },
		"failed-accepted-rule": func(value map[string]any) { value["state"] = "failed" },
	} {
		value, err := schemacheck.Normalize(passed.JSONValue())
		if err != nil {
			t.Fatal(err)
		}
		mutate(value.(map[string]any))
		if schemacheck.Validate(report, value) == nil {
			t.Fatalf("%s: drifted report accepted", name)
		}
	}
	if err := schemacheck.Validate(pair, []any{passed.JSONValue()}); err == nil {
		t.Fatal("single report accepted as the ordered pair")
	}
}

func setDemoState(report map[string]any, state string) {
	for _, raw := range report["diagnostics"].([]any) {
		diagnostic := raw.(map[string]any)
		if diagnostic["key"] == "impactDemos" {
			diagnostic["value"].([]any)[0].(map[string]any)["state"] = state
		}
	}
}

func TestPilotStructuresShareDefinitionsOnlyAtVariantRoots(t *testing.T) {
	for _, schema := range []map[string]any{InputStructure(), ContractInputStructure("input", "stackDiverseInput")} {
		defs := schema["$defs"].(map[string]any)
		if _, ok := defs[impactDemoDefinition]; !ok {
			t.Fatal("impact demo definition is not at the variant root")
		}
		if _, nested := defs[impactDemoDefinition].(map[string]any)["properties"].(map[string]any)["impactInput"].(map[string]any)["$schema"]; nested {
			t.Fatal("embedded impact owner kept a nested dialect header")
		}
	}
	first := InputStructure()
	first["properties"].(map[string]any)["pilotId"].(map[string]any)["maxLength"] = 1
	if InputStructure()["properties"].(map[string]any)["pilotId"].(map[string]any)["maxLength"] == 1 {
		t.Fatal("structure projection aliases caller-mutated state")
	}
}
