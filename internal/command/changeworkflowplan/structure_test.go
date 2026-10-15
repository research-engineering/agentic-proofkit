package changeworkflowplan

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

// structuralWorkflowCorpus spans every relation row, the terminal row, every
// envelope blocker reachable through admitted input and the closure partition.
func structuralWorkflowCorpus() map[string]map[string]any {
	corpus := map[string]map[string]any{"terminal": terminalInput()}
	for index := range workflowCatalog.Stages {
		for _, definition := range workflowCatalog.CheckpointActions {
			corpus[fmt.Sprintf("%d/%s", index, definition.State)] = inputForStage(index, definition.State)
		}
	}
	corpus["verification/no-witness"] = verificationInput(false)
	corpus["verification/witness"] = verificationInput(true)
	omitted := reviewInput("ready_for_review")
	omitted["contextRefs"] = append(omitted["contextRefs"].([]any), contextValue("ctx.unrequired", "artifact", testDigest, nil))
	corpus["omitted-context"] = omitted
	spaced := reviewInput("review_findings")
	spaced["checkpoint"].(map[string]any)["subjectDigest"] = " \t" + strings.Replace(testDigest, ":", ":\u00a0", 1) + "\u3000"
	corpus["whitespace-digest"] = spaced
	closure := reviewInput("review_passed")
	closure["contextRefs"] = []any{
		contextValue("ctx.artifact", "artifact", testDigest, []string{"ctx.dependency"}),
		contextValue("ctx.authority", "authority", testDigest, nil),
		contextValue("ctx.dependency", "witness", testDigest, nil),
	}
	closure["requiredContextRefIds"] = []any{"ctx.dependency"}
	corpus["dependency-closure"] = closure
	return corpus
}

func uniqueStrings(values []any) bool {
	seen := map[any]struct{}{}
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func assertStagePrefix(t *testing.T, raw any, label string) {
	t.Helper()
	values, ok := raw.([]any)
	if !ok || len(values) > len(workflowCatalog.Stages) {
		t.Fatalf("%s is not a bounded stage list", label)
	}
	for index, value := range values {
		if value != workflowCatalog.Stages[index].ID {
			t.Fatalf("%s is not a catalog prefix", label)
		}
	}
}

func TestWorkflowStructuresAdmitEveryNativeProjection(t *testing.T) {
	envelope := EnvelopeShape()
	planShapes := []jsonshape.Shape{NextActionOutputShape(), AcceptStageOutputShape(), WorkflowCompleteOutputShape()}
	claims := stringsValue(envelopeNonClaims())
	for name, input := range structuralWorkflowCorpus() {
		t.Run(name, func(t *testing.T) {
			if _, err := InputShape().Admit(cloneValue(input), "input"); err != nil {
				t.Fatal(err)
			}
			plan := requireBuild(t, input)
			matched := []int{}
			for index, shape := range planShapes {
				if shape.CheckGenerated(plan, "plan") == nil {
					matched = append(matched, index)
				}
			}
			want := 0
			if plan["outputKind"] == "workflow_complete" {
				want = 2
			} else if _, successor := plan["successorStateDelta"]; successor {
				want = 1
			}
			if !slices.Equal(matched, []int{want}) {
				t.Fatalf("plan variant selection = %v, want [%d]: %v", matched, want, planShapes[want].CheckGenerated(plan, "plan"))
			}
			assertStagePrefix(t, plan["completedStageIds"], "plan completedStageIds")
			for _, key := range []string{"omittedContextRefIds", "retainedContextRefIds"} {
				if !uniqueStrings(plan[key].([]any)) {
					t.Fatalf("%s lost duplicate freedom", key)
				}
			}
			if prompt, ok := plan["prompt"].(map[string]any); ok {
				assertStagePrefix(t, prompt["observedFact"].(map[string]any)["completedStageIds"], "observed completedStageIds")
				coordinates := prompt["coordinates"].(map[string]any)
				_, digest := coordinates["subjectDigest"]
				_, ref := coordinates["subjectRefId"]
				_, findings := coordinates["findingRefs"]
				if digest != ref || findings && !ref {
					t.Fatal("coordinate dependencies drifted")
				}
			}
			if delta, ok := plan["successorStateDelta"].(map[string]any); ok {
				assertStagePrefix(t, delta["completedStageIds"], "successor completedStageIds")
			}
			value, err := BuildAgentEnvelope(input)
			if err != nil {
				t.Fatal(err)
			}
			if err := envelope.CheckGenerated(value, "envelope"); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(value["nonClaims"], claims) {
				t.Fatal("envelope non-claims differ from the merged producer tuple")
			}
		})
	}
}

func TestWorkflowInputStructureAgreesWithNativeRefusals(t *testing.T) {
	core := InputShape()
	cases := map[string]func(map[string]any){
		"foreign root":            func(value map[string]any) { value["foreign"] = true },
		"missing checkpoint":      func(value map[string]any) { delete(value, "checkpoint") },
		"missing required ids":    func(value map[string]any) { delete(value, "requiredContextRefIds") },
		"schema version":          func(value map[string]any) { value["schemaVersion"] = json.Number("2") },
		"schema version spelling": func(value map[string]any) { value["schemaVersion"] = json.Number("1.0") },
		"schema version text":     func(value map[string]any) { value["schemaVersion"] = "1" },
		"foreign stage":           func(value map[string]any) { value["completedStageIds"] = []any{"foreign"} },
		"surplus stages": func(value map[string]any) {
			value["completedStageIds"] = append(stringsValue(workflowStageIDs()), "closeout")
		},
		"context ref limit":   func(value map[string]any) { value["contextRefs"] = repeatedContextRefs(maxCandidateContextRefs + 1) },
		"context ref field":   func(value map[string]any) { value["contextRefs"].([]any)[0].(map[string]any)["foreign"] = true },
		"context ref missing": func(value map[string]any) { delete(value["contextRefs"].([]any)[0].(map[string]any), "refKind") },
		"context ref kind":    func(value map[string]any) { value["contextRefs"].([]any)[0].(map[string]any)["refKind"] = "foreign" },
		"context ref digest": func(value map[string]any) {
			value["contextRefs"].([]any)[0].(map[string]any)["subjectDigest"] = strings.ToUpper(testDigest)
		},
		"context ref empty path": func(value map[string]any) { value["contextRefs"].([]any)[0].(map[string]any)["artifactPath"] = "" },
		"context ref long path": func(value map[string]any) {
			value["contextRefs"].([]any)[0].(map[string]any)["artifactPath"] = strings.Repeat("a", maxPathBytes+1)
		},
		"context ref id grammar": func(value map[string]any) { value["contextRefs"].([]any)[0].(map[string]any)["refId"] = "1ctx" },
		"context ref id length": func(value map[string]any) {
			value["contextRefs"].([]any)[0].(map[string]any)["refId"] = strings.Repeat("a", 257)
		},
		"dependency limit": func(value map[string]any) {
			value["contextRefs"].([]any)[0].(map[string]any)["dependencyRefIds"] = repeatedIDs(maxDependenciesPerRef + 1)
		},
		"required limit":     func(value map[string]any) { value["requiredContextRefIds"] = repeatedIDs(maxRequiredContextRefs + 1) },
		"authority kind":     func(value map[string]any) { value["governingAuthorityRefId"] = false },
		"checkpoint field":   func(value map[string]any) { value["checkpoint"].(map[string]any)["foreign"] = true },
		"checkpoint state":   func(value map[string]any) { value["checkpoint"].(map[string]any)["state"] = "foreign" },
		"checkpoint kind":    func(value map[string]any) { value["checkpoint"] = []any{} },
		"finding refs empty": func(value map[string]any) { value["checkpoint"].(map[string]any)["findingRefs"] = []any{} },
		"finding refs limit": func(value map[string]any) {
			value["checkpoint"].(map[string]any)["findingRefs"] = repeatedIDs(maxFindings + 1)
		},
		"assessment digest prefix": func(value map[string]any) {
			value["checkpoint"].(map[string]any)["assessmentSubjectDigest"] = "sha512:" + testDigest[7:]
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value := cloneMap(reviewInput("review_findings"))
			mutate(value)
			if _, err := Build(value); err == nil {
				t.Fatal("native admission accepted a structural mutant")
			}
			if _, err := core.Admit(value, "input"); err == nil {
				t.Fatal("structural core accepted a native structural refusal")
			}
		})
	}
	// These refusals are expressed only by the published refinements.
	for name, mutate := range map[string]func(map[string]any){
		"non-prefix stages":   func(value map[string]any) { value["completedStageIds"] = []any{"design"} },
		"duplicate required":  func(value map[string]any) { value["requiredContextRefIds"] = []any{"ctx.artifact", "ctx.artifact"} },
		"stage-bound subject": func(value map[string]any) { delete(value["checkpoint"].(map[string]any), "subjectDigest") },
		"terminal checkpoint": func(value map[string]any) {
			value["completedStageIds"] = stringsValue(workflowStageIDs())
			value["checkpoint"] = map[string]any{"state": "not_started"}
		},
	} {
		t.Run("refinement/"+name, func(t *testing.T) {
			value := cloneMap(inputForStage(1, "not_started"))
			mutate(value)
			if _, err := Build(value); err == nil {
				t.Fatal("native admission accepted a refinement mutant")
			}
		})
	}
}

func repeatedContextRefs(count int) []any {
	refs := make([]any, count)
	for index := range refs {
		refs[index] = contextValue(fmt.Sprintf("ctx.ref%03d", index), "artifact", testDigest, nil)
	}
	return refs
}

func repeatedIDs(count int) []any {
	ids := make([]any, count)
	for index := range ids {
		ids[index] = fmt.Sprintf("ctx.id%03d", index)
	}
	return ids
}

func schemaPointer(t *testing.T, schema map[string]any, path ...any) any {
	t.Helper()
	var current any = schema
	for _, segment := range path {
		switch key := segment.(type) {
		case string:
			current = current.(map[string]any)[key]
		case int:
			current = current.([]any)[key]
		}
	}
	return current
}

func TestWorkflowStructureRefinementsBindNativeCatalog(t *testing.T) {
	input := InputStructure()
	prefix := schemaPointer(t, input, "properties", "completedStageIds").(map[string]any)
	if prefix["items"] != false || len(prefix["prefixItems"].([]any)) != len(workflowCatalog.Stages) {
		t.Fatal("input stage list is not a catalog prefix")
	}
	for index, stage := range workflowCatalog.Stages {
		if prefix["prefixItems"].([]any)[index].(map[string]any)["const"] != stage.ID {
			t.Fatal("stage prefix order drifted from the catalog")
		}
	}
	for _, path := range [][]any{
		{"properties", "requiredContextRefIds"},
		{"properties", "contextRefs", "items", "properties", "dependencyRefIds"},
		{"properties", "checkpoint", "anyOf", 1, "properties", "findingRefs"},
	} {
		if schemaPointer(t, input, path...).(map[string]any)["uniqueItems"] != true {
			t.Fatalf("reference list %v is not duplicate-free", path)
		}
	}
	conditions := input["allOf"].([]any)
	if len(conditions) != len(workflowCatalog.Stages)+1 {
		t.Fatal("checkpoint conditions do not cover every stage count")
	}
	for index, stage := range workflowCatalog.Stages {
		selectors := schemaPointer(t, input, "allOf", index, "then", "properties", "checkpoint", "oneOf").([]any)
		for position, definition := range workflowCatalog.CheckpointActions {
			fields := slices.Sorted(slices.Values(checkpointFieldNames(definition, stage)))
			selector := selectors[position].(map[string]any)
			if !reflect.DeepEqual(selector["required"], stringsValue(fields)) || selector["maxProperties"] != len(fields) {
				t.Fatalf("stage %s checkpoint %s field set drifted", stage.ID, definition.State)
			}
		}
	}
	if schemaPointer(t, input, "allOf", len(workflowCatalog.Stages), "then", "properties", "checkpoint", "type") != "null" {
		t.Fatal("complete prefix does not require a null checkpoint")
	}
	next := NextActionOutputStructure()
	if schemaPointer(t, next, "properties", "prompt", "properties", "coordinates", "dependentRequired") == nil {
		t.Fatal("coordinate subject dependencies are missing")
	}
	complete := WorkflowCompleteOutputStructure()
	stages := schemaPointer(t, complete, "properties", "completedStageIds").(map[string]any)
	if stages["minItems"] != len(workflowCatalog.Stages) || len(stages["prefixItems"].([]any)) != len(workflowCatalog.Stages) {
		t.Fatal("terminal plan does not require the complete prefix")
	}
	envelope := EnvelopeStructure()
	if !reflect.DeepEqual(schemaPointer(t, envelope, "properties", "nonClaims"), nestedSchema(literalTupleShape(envelopeNonClaims()))) {
		t.Fatal("envelope non-claims are not the exact merged tuple")
	}
	blocked, clarifications := blockerCatalog()
	if len(blocked) != 3 || len(clarifications) != 3 {
		t.Fatal("blocker catalog lost a producer branch")
	}
	for _, schema := range []map[string]any{input, next, AcceptStageOutputStructure(), complete, envelope} {
		description, ok := schema["description"].(string)
		if !ok || !strings.Contains(description, "stderr") {
			t.Fatal("structure lost its native refusal boundary description")
		}
	}
	fresh := InputStructure()
	fresh["properties"].(map[string]any)["schemaVersion"] = map[string]any{}
	if reflect.DeepEqual(fresh, InputStructure()) {
		t.Fatal("input structure shares mutable projection state")
	}
	if !slices.Equal(slices.Sorted(maps.Keys(contextRoles())), []string{"evidence", "owner_surface", "proof_binding", "review_finding", "semantic_owner"}) {
		t.Fatal("context role projection drifted")
	}
}

func TestWorkflowStructureDoesNotGrantNativeAdmission(t *testing.T) {
	core := InputShape()
	for name, mutate := range map[string]func(map[string]any){
		"unresolved required ref": func(value map[string]any) { value["requiredContextRefIds"] = []any{"ctx.unknown"} },
		"authority kind":          func(value map[string]any) { value["governingAuthorityRefId"] = "ctx.artifact" },
		"assessment mismatch": func(value map[string]any) {
			value["checkpoint"].(map[string]any)["assessmentSubjectDigest"] = "sha256:" + strings.Repeat("9", 64)
		},
		"unsorted context refs": func(value map[string]any) {
			refs := value["contextRefs"].([]any)
			refs[0], refs[1] = refs[1], refs[0]
		},
		"unsafe path": func(value map[string]any) {
			value["contextRefs"].([]any)[0].(map[string]any)["artifactPath"] = "../escape.json"
		},
		"timestamp id": func(value map[string]any) { value["requiredContextRefIds"] = []any{"ctx.20240101"} },
	} {
		t.Run(name, func(t *testing.T) {
			value := cloneMap(reviewInput("review_findings"))
			mutate(value)
			if _, err := core.Admit(value, "input"); err != nil {
				t.Fatalf("structural core refused a semantic-only mutant: %v", err)
			}
			if _, err := Build(value); err == nil {
				t.Fatal("native semantic admission accepted the mutant")
			}
		})
	}
	text, err := BuildText(reviewInput("ready_for_review"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if json.Unmarshal([]byte(text), &decoded) == nil {
		t.Fatal("text presentation unexpectedly parses as JSON")
	}
}
