package adoptionworkflow

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func structureRenderers(t *testing.T) []cliexec.Renderer {
	t.Helper()
	renderers := []cliexec.Renderer{}
	for _, profile := range []struct{ name, python string }{
		{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""}, {cliexec.ProfilePythonModule, "/tmp/proofkit venv/bin/python"},
	} {
		renderer, err := cliexec.AdmitLauncherProfile(profile.name, profile.python)
		if err != nil {
			t.Fatal(err)
		}
		renderers = append(renderers, renderer)
	}
	return renderers
}

// Every scenario is built with no refs, all refs, each single ref and every
// ref but one, with and without a preset, so ready and blocked plans, empty
// and populated phases, and all blocker kinds are observed.
func structureWorkflowCorpus() []map[string]any {
	kinds := make([]string, 0, len(inputKinds))
	for kind := range inputKinds {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	subsets := [][]string{{}, kinds}
	for index := range kinds {
		subsets = append(subsets, []string{kinds[index]}, slices.Delete(slices.Clone(kinds), index, index+1))
	}
	corpus := []map[string]any{}
	for _, scenario := range []string{"existing_gradual_adoption", "legacy_proof_migration", "new_repository", "release_channel"} {
		for _, preset := range []any{nil, stackpreset.IDs()[0]} {
			for _, subset := range subsets {
				refs := []any{}
				for _, kind := range subset {
					refs = append(refs, map[string]any{"inputKind": kind, "path": "proofkit/" + kind + ".json", "refId": "proofkit.ref." + kind})
				}
				input := validWorkflowInput()
				input["scenario"], input["presetId"], input["inputRefs"] = scenario, preset, refs
				corpus = append(corpus, input)
			}
		}
	}
	return corpus
}

func TestWorkflowOutputStructuresAcceptEveryReachableCarrier(t *testing.T) {
	plan, envelope, sum := OutputStructure(), EnvelopeStructure(), EnvelopeOutputStructure()
	states := map[string]bool{}
	for _, renderer := range structureRenderers(t) {
		for _, input := range structureWorkflowCorpus() {
			output, code, err := BuildWithRenderer(input, renderer)
			if err != nil {
				t.Fatal(err)
			}
			states[output["planState"].(string)] = true
			if err := schemacheck.Validate(plan, output); err != nil {
				t.Fatalf("plan %v: %v", input["scenario"], err)
			}
			if (code == 0) != (output["planState"] == planStateReady) {
				t.Fatal("plan state and exit code diverged")
			}
			wrapped, wrappedCode, err := BuildEnvelopeWithRenderer(input, renderer)
			if err != nil || wrappedCode != code {
				t.Fatal("envelope changed the plan exit")
			}
			for _, schema := range []map[string]any{envelope, sum} {
				if err := schemacheck.Validate(schema, wrapped); err != nil {
					t.Fatalf("envelope %v: %v", input["scenario"], err)
				}
			}
		}
	}
	if !states[planStateReady] || !states[planStateBlocked] {
		t.Fatalf("corpus did not reach both plan states: %v", states)
	}
	// An admitted refId longer than the envelope's local identity bound is a
	// reachable degradation, not a refusal.
	long := validWorkflowInput()
	long["inputRefs"].([]any)[0].(map[string]any)["refId"] = strings.Repeat("A", 256)
	degraded, _, err := BuildEnvelope(long)
	if err != nil || len(degraded["omitted"].([]any)) == 0 || degraded["bounds"].(map[string]any)["truncated"] != true {
		t.Fatalf("overlong local identity did not degrade: %v", err)
	}
	if err := schemacheck.Validate(sum, degraded); err != nil {
		t.Fatal(err)
	}
	repair, code, err := BuildEnvelope(map[string]any{})
	if err != nil || code != 1 || repair["envelopeId"] != "proofkit.agent-envelope.invalid-input" {
		t.Fatal("refused envelope input lost its repair packet")
	}
	if schemacheck.Validate(sum, repair) != nil || schemacheck.Validate(envelope, repair) == nil {
		t.Fatal("repair packet must match only the invalid-input alternative")
	}
}

func TestWorkflowOutputStructureRefusesCarrierDrift(t *testing.T) {
	plan := OutputStructure()
	ready, _, err := Build(validWorkflowInput())
	if err != nil {
		t.Fatal(err)
	}
	blockedInput := validWorkflowInput()
	blockedInput["inputRefs"] = []any{}
	blocked, _, err := Build(blockedInput)
	if err != nil || blocked["planState"] != planStateBlocked {
		t.Fatal("blocked fixture is not blocked")
	}
	for name, mutate := range map[string]func(map[string]any){
		"ready-with-blocker": func(value map[string]any) { value["blockers"] = blocked["blockers"] },
		"blocked-state":      func(value map[string]any) { value["planState"] = planStateBlocked },
		"foreign-root":       func(value map[string]any) { value["foreign"] = true },
		"phase-order": func(value map[string]any) {
			phases := value["phases"].([]any)
			phases[0], phases[1] = phases[1], phases[0]
		},
		"phase-command": func(value map[string]any) {
			value["phases"].([]any)[0].(map[string]any)["commands"] = []any{map[string]any{
				"argv": []any{"agentic-proofkit"}, "commandId": "proofkit.adoption-workflow.command.release-authority",
				"inputRefIds": []any{}, "nonClaim": commandNonClaim, "owner": workflowOwner,
			}}
		},
		"builtin-claim": func(value map[string]any) {
			value["nonClaims"] = []any{"caller only", "second", "third", "fourth", "fifth", "sixth"}
		},
		"plan-kind": func(value map[string]any) { value["planKind"] = "proofkit.foreign" },
		"version":   func(value map[string]any) { value["schemaVersion"] = 2 },
	} {
		value, err := schemacheck.Normalize(ready)
		if err != nil {
			t.Fatal(err)
		}
		mutate(value.(map[string]any))
		if schemacheck.Validate(plan, value) == nil {
			t.Fatalf("%s: drifted plan accepted", name)
		}
	}
	unblocked, err := schemacheck.Normalize(blocked)
	if err != nil {
		t.Fatal(err)
	}
	unblocked.(map[string]any)["blockers"] = []any{}
	if schemacheck.Validate(plan, unblocked) == nil {
		t.Fatal("blocked plan without blockers accepted")
	}
}

type workflowAdmissionCase struct {
	name   string
	mutate func(map[string]any)
	// semantic marks native refusals the structural schema does not express.
	semantic bool
}

func workflowAdmissionCorpus() []workflowAdmissionCase {
	ref := func(input map[string]any) map[string]any { return input["inputRefs"].([]any)[0].(map[string]any) }
	cases := []workflowAdmissionCase{
		{name: "valid", mutate: func(map[string]any) {}},
		{name: "preset-absent", mutate: func(input map[string]any) { delete(input, "presetId") }},
		{name: "preset-known", mutate: func(input map[string]any) { input["presetId"] = stackpreset.IDs()[0] }},
		{name: "preset-unknown", mutate: func(input map[string]any) { input["presetId"] = "unknown_preset" }},
		{name: "preset-type", mutate: func(input map[string]any) { input["presetId"] = false }},
		{name: "refs-empty", mutate: func(input map[string]any) { input["inputRefs"] = []any{} }},
		{name: "refs-type", mutate: func(input map[string]any) { input["inputRefs"] = map[string]any{} }},
		{name: "ref-type", mutate: func(input map[string]any) { input["inputRefs"] = []any{"proofkit/x.json"} }},
		{name: "ref-foreign", mutate: func(input map[string]any) { ref(input)["foreign"] = true }},
		{name: "ref-kind", mutate: func(input map[string]any) { ref(input)["inputKind"] = "unknown_kind" }},
		{name: "ref-path-type", mutate: func(input map[string]any) { ref(input)["path"] = 7 }},
		{name: "ref-path-empty", mutate: func(input map[string]any) { ref(input)["path"] = "" }},
		{name: "ref-path-absolute", mutate: func(input map[string]any) { ref(input)["path"] = "/etc/passwd" }, semantic: true},
		{name: "ref-path-escape", mutate: func(input map[string]any) { ref(input)["path"] = "../outside.json" }, semantic: true},
		{name: "ref-id", mutate: func(input map[string]any) { ref(input)["refId"] = "1bad" }},
		{name: "ref-id-bound", mutate: func(input map[string]any) { ref(input)["refId"] = strings.Repeat("A", 257) }},
		{name: "ref-id-limit", mutate: func(input map[string]any) { ref(input)["refId"] = strings.Repeat("A", 256) }},
		{name: "ref-id-timestamp", mutate: func(input map[string]any) { ref(input)["refId"] = "proofkit.20260101" }, semantic: true},
		{name: "ref-missing-path", mutate: func(input map[string]any) { delete(ref(input), "path") }},
		{name: "duplicate-ref-id", mutate: func(input map[string]any) {
			input["inputRefs"].([]any)[1].(map[string]any)["refId"] = ref(input)["refId"]
		}, semantic: true},
		{name: "duplicate-kind", mutate: func(input map[string]any) {
			input["inputRefs"].([]any)[1].(map[string]any)["inputKind"] = ref(input)["inputKind"]
		}, semantic: true},
		{name: "refs-over-vocabulary", mutate: func(input map[string]any) {
			refs := []any{}
			for index := 0; index <= len(inputKinds); index++ {
				refs = append(refs, map[string]any{"inputKind": "release_authority", "path": "proofkit/x.json", "refId": "proofkit.ref" + strings.Repeat("x", index+1)})
			}
			input["inputRefs"] = refs
		}},
		{name: "scenario", mutate: func(input map[string]any) { input["scenario"] = "unknown_scenario" }},
		{name: "scenario-missing", mutate: func(input map[string]any) { delete(input, "scenario") }},
		{name: "version", mutate: func(input map[string]any) { input["schemaVersion"] = json.Number("2") }},
		{name: "version-text", mutate: func(input map[string]any) { input["schemaVersion"] = "1" }},
		{name: "workflow-id", mutate: func(input map[string]any) { input["workflowId"] = "bad id" }},
		{name: "workflow-id-missing", mutate: func(input map[string]any) { delete(input, "workflowId") }},
		{name: "root-foreign", mutate: func(input map[string]any) { input["foreign"] = true }},
		{name: "claims-empty", mutate: func(input map[string]any) { input["nonClaims"] = []any{} }},
		{name: "claims-blank", mutate: func(input map[string]any) { input["nonClaims"] = []any{" \u3000"} }},
		{name: "claims-item", mutate: func(input map[string]any) { input["nonClaims"] = []any{false} }},
		{name: "claims-duplicate", mutate: func(input map[string]any) { input["nonClaims"] = []any{"same", "same"} }},
		{name: "claims-unsorted", mutate: func(input map[string]any) { input["nonClaims"] = []any{"zulu", "alpha"} }},
		{name: "claims-builtin", mutate: func(input map[string]any) { input["nonClaims"] = []any{workflowNonClaims[0]} }},
		{name: "claims-trimmed-builtin", mutate: func(input map[string]any) { input["nonClaims"] = []any{workflowNonClaims[0] + " "} }, semantic: true},
		{name: "claims-trimmed-duplicate", mutate: func(input map[string]any) { input["nonClaims"] = []any{"same", " same"} }, semantic: true},
		{name: "claims-secret", mutate: func(input map[string]any) { input["nonClaims"] = []any{"api_" + "key=synthetic-structure-fixture"} }, semantic: true},
	}
	return cases
}

func TestWorkflowInputStructuresAgreeWithNativeAdmission(t *testing.T) {
	direct, contract := InputStructure(), ContractInputStructure()
	for _, item := range workflowAdmissionCorpus() {
		t.Run(item.name, func(t *testing.T) {
			input := validWorkflowInput()
			item.mutate(input)
			_, _, nativeErr := Build(input)
			structural := schemacheck.Validate(direct, input) == nil
			wrapped := map[string]any{"schema": contractEnvelopeSchema, "workflow": input}
			_, _, contractErr := BuildFromContractEnvelope(wrapped)
			if (nativeErr == nil) != (contractErr == nil) || structural != (schemacheck.Validate(contract, wrapped) == nil) {
				t.Fatal("contract envelope changed the direct admission domain")
			}
			if item.semantic {
				if !structural || nativeErr == nil {
					t.Fatalf("semantic case must be structurally accepted and natively refused: %v", nativeErr)
				}
				return
			}
			if structural != (nativeErr == nil) {
				t.Fatalf("structure=%t native=%v", structural, nativeErr)
			}
		})
	}
	for name, envelope := range map[string]any{
		"header":  map[string]any{"schema": "proofkit.adoption-workflow.v2", "workflow": validWorkflowInput()},
		"missing": map[string]any{"schema": contractEnvelopeSchema},
		"type":    map[string]any{"schema": contractEnvelopeSchema, "workflow": []any{}},
		"foreign": map[string]any{"schema": contractEnvelopeSchema, "workflow": validWorkflowInput(), "foreign": true},
		"root":    []any{},
	} {
		if _, _, err := BuildFromContractEnvelope(envelope); err == nil || schemacheck.Validate(contract, envelope) == nil {
			t.Fatalf("%s: malformed contract envelope accepted", name)
		}
	}
}

func TestWorkflowStructuresDeriveVocabulariesFromTheProducer(t *testing.T) {
	ids, _ := reachableBlockers()
	observed := map[string]struct{}{}
	commands := map[string]map[string]struct{}{}
	for _, input := range structureWorkflowCorpus() {
		output, _, err := Build(input)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range output["blockers"].([]any) {
			observed[raw.(map[string]any)["blockerId"].(string)] = struct{}{}
		}
		for _, raw := range output["phases"].([]any) {
			phase := raw.(map[string]any)
			for _, command := range phase["commands"].([]any) {
				if commands[phase["phase"].(string)] == nil {
					commands[phase["phase"].(string)] = map[string]struct{}{}
				}
				commands[phase["phase"].(string)][command.(map[string]any)["commandId"].(string)] = struct{}{}
			}
		}
	}
	if len(observed) != len(ids) {
		t.Fatalf("blocker vocabulary %d differs from observed %d", len(ids), len(observed))
	}
	for phase, ids := range reachableCommandIDs() {
		if len(ids) != len(commands[phase]) {
			t.Fatalf("%s command vocabulary %v differs from observed %v", phase, ids, commands[phase])
		}
	}
	first := OutputStructure()
	first["properties"].(map[string]any)["planKind"].(map[string]any)["const"] = "mutated"
	if OutputStructure()["properties"].(map[string]any)["planKind"].(map[string]any)["const"] != planKind {
		t.Fatal("structure projection aliases caller-mutated state")
	}
	if agentenvelope.InvalidInputStructure()["properties"].(map[string]any)["envelopeId"].(map[string]any)["const"] == envelopeID {
		t.Fatal("workflow and repair envelope identities must be disjoint")
	}
}
