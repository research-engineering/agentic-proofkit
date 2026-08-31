package changeworkflowplan

import (
	"strings"
	"testing"
)

func TestWorkflowClosurePredicates(t *testing.T) {
	t.Run("all_seeds_retained", func(t *testing.T) {
		input := reviewInput("review_findings")
		input["requiredContextRefIds"] = []any{"ctx.authority"}
		plan := requireBuild(t, input)
		requireEqual(t, plan["retainedContextRefIds"], []any{"ctx.artifact", "ctx.authority", "ctx.finding"})
	})
	t.Run("candidate_bound", func(t *testing.T) {
		input := initialInput()
		refs := make([]any, maxCandidateContextRefs+1)
		for index := range refs {
			id := "ctx." + twoDigits(index+1)
			refs[index] = contextValue(id, "artifact", testDigest, nil)
		}
		input["contextRefs"] = refs
		requireReject(t, input)

		for _, mutate := range []func([]any){
			func(values []any) { values[0], values[1] = values[1], values[0] },
			func(values []any) { values[1] = cloneValue(values[0]) },
		} {
			input = initialInput()
			values := []any{contextValue("ctx.01", "artifact", testDigest, nil), contextValue("ctx.02", "artifact", testDigest, nil)}
			mutate(values)
			input["contextRefs"] = values
			requireReject(t, input)
		}
		input = initialInput()
		ref := contextValue("ctx.path", "artifact", testDigest, nil)
		ref["artifactPath"] = "evidence/" + strings.Repeat("p", maxPathBytes-len("evidence/")-len(".json")+1) + ".json"
		input["contextRefs"] = []any{ref}
		requireReject(t, input)
	})
	t.Run("cycles_finite", func(t *testing.T) {
		input := initialInput()
		input["contextRefs"] = []any{
			contextValue("cycle.a", "artifact", testDigest, []string{"cycle.b"}),
			contextValue("cycle.b", "witness", "sha256:3333333333333333333333333333333333333333333333333333333333333333", []string{"cycle.a"}),
		}
		input["requiredContextRefIds"] = []any{"cycle.a"}
		plan := requireBuild(t, input)
		requireEqual(t, plan["retainedContextRefIds"], []any{"cycle.a", "cycle.b"})
	})
	t.Run("dependency_bound", func(t *testing.T) {
		input := initialInput()
		dependencies := make([]string, maxDependenciesPerRef+1)
		for index := range dependencies {
			dependencies[index] = "dep." + twoDigits(index+1)
		}
		input["contextRefs"] = []any{contextValue("ctx.root", "artifact", testDigest, dependencies)}
		requireReject(t, input)
		for _, invalid := range [][]string{{"dep.02", "dep.01"}, {"dep.01", "dep.01"}, {"dep.missing"}} {
			input = initialInput()
			input["contextRefs"] = []any{contextValue("ctx.root", "artifact", testDigest, invalid)}
			requireReject(t, input)
		}
	})
	t.Run("dependency_closed", func(t *testing.T) {
		input := initialInput()
		input["contextRefs"] = []any{
			contextValue("ctx.root", "artifact", testDigest, []string{"ctx.witness"}),
			contextValue("ctx.witness", "witness", "sha256:4444444444444444444444444444444444444444444444444444444444444444", nil),
		}
		input["requiredContextRefIds"] = []any{"ctx.root"}
		plan := requireBuild(t, input)
		requireEqual(t, plan["retainedContextRefIds"], []any{"ctx.root", "ctx.witness"})
	})
	t.Run("empty_context", func(t *testing.T) {
		plan := requireBuild(t, initialInput())
		requireEqual(t, plan["retainedContextRefIds"], []any{})
		requireEqual(t, plan["omittedContextRefIds"], []any{})
	})
	t.Run("exact_omissions", func(t *testing.T) {
		input := initialInput()
		input["contextRefs"] = []any{
			contextValue("ctx.keep", "artifact", testDigest, nil),
			contextValue("ctx.omit", "finding", "sha256:3333333333333333333333333333333333333333333333333333333333333333", nil),
		}
		input["requiredContextRefIds"] = []any{"ctx.keep"}
		plan := requireBuild(t, input)
		requireEqual(t, plan["omittedContextRefIds"], []any{"ctx.omit"})
	})
	t.Run("json_envelope_caps", func(t *testing.T) {
		oversized := map[string]any{"payload": strings.Repeat("x", maxJSONBytes)}
		if err := enforceJSONCap(oversized); err == nil {
			t.Fatal("oversized JSON was admitted")
		}
		if _, err := BuildAgentEnvelope(initialInput()); err != nil {
			t.Fatalf("bounded envelope rejected: %v", err)
		}
	})
	t.Run("least_fixed_point", func(t *testing.T) {
		input := initialInput()
		input["contextRefs"] = []any{
			contextValue("ctx.branch", "artifact", testDigest, []string{"ctx.leaf"}),
			contextValue("ctx.irrelevant", "finding", "sha256:5555555555555555555555555555555555555555555555555555555555555555", nil),
			contextValue("ctx.leaf", "witness", "sha256:4444444444444444444444444444444444444444444444444444444444444444", nil),
		}
		input["requiredContextRefIds"] = []any{"ctx.branch"}
		plan := requireBuild(t, input)
		requireEqual(t, plan["retainedContextRefIds"], []any{"ctx.branch", "ctx.leaf"})
	})
	t.Run("ref_id_byte_bound", func(t *testing.T) {
		maxID := "r" + strings.Repeat("a", 255)
		input := initialInput()
		input["contextRefs"] = []any{contextValue(maxID, "artifact", testDigest, nil)}
		input["requiredContextRefIds"] = []any{maxID}
		if _, err := Build(input); err != nil {
			t.Fatalf("256-byte ID rejected: %v", err)
		}
		overID := "r" + strings.Repeat("a", 256)
		mutants := []map[string]any{}
		candidate := initialInput()
		candidate["contextRefs"] = []any{contextValue(overID, "artifact", testDigest, nil)}
		mutants = append(mutants, candidate)
		governing := initialInput()
		governing["governingAuthorityRefId"] = overID
		mutants = append(mutants, governing)
		required := initialInput()
		required["requiredContextRefIds"] = []any{overID}
		mutants = append(mutants, required)
		dependency := initialInput()
		dependency["contextRefs"] = []any{contextValue("ctx.root", "artifact", testDigest, []string{overID})}
		mutants = append(mutants, dependency)
		subject := reviewInput("ready_for_review")
		subject["checkpoint"].(map[string]any)["subjectRefId"] = overID
		mutants = append(mutants, subject)
		finding := reviewInput("review_findings")
		finding["checkpoint"].(map[string]any)["findingRefs"] = []any{overID}
		mutants = append(mutants, finding)
		for _, mutant := range mutants {
			err := requireReject(t, mutant)
			if RuleID(err) != "proofkit.workflow.ref_id_limit_exceeded" {
				t.Fatalf("unexpected rule %s", RuleID(err))
			}
		}
	})
	t.Run("retained_bound", func(t *testing.T) {
		input := initialInput()
		refs := make([]any, maxRetainedContextRefs+1)
		for index := range refs {
			id := "ctx." + twoDigits(index+1)
			dependencies := []string{}
			if index+1 < len(refs) {
				dependencies = []string{"ctx." + twoDigits(index+2)}
			}
			refs[index] = contextValue(id, "artifact", testDigest, dependencies)
		}
		input["contextRefs"] = refs
		input["requiredContextRefIds"] = []any{"ctx.01"}
		if rule := RuleID(requireReject(t, input)); rule != "proofkit.workflow.retained_context_limit_exceeded" {
			t.Fatalf("unexpected retained-count rule %s", rule)
		}
		input = initialInput()
		refs = make([]any, maxRetainedContextRefs+1)
		for index := range refs {
			id := "path." + twoDigits(index+1)
			dependencies := []string{}
			if index+1 < len(refs) {
				dependencies = []string{"path." + twoDigits(index+2)}
			}
			ref := contextValue(id, "artifact", testDigest, dependencies)
			ref["artifactPath"] = "evidence/" + twoDigits(index+1) + "-" + strings.Repeat("p", 367) + ".json"
			refs[index] = ref
		}
		input["contextRefs"] = refs
		input["requiredContextRefIds"] = []any{"path.01"}
		if rule := RuleID(requireReject(t, input)); rule != "proofkit.workflow.retained_path_bytes_exceeded" {
			t.Fatalf("unexpected retained-path rule %s", rule)
		}
	})
	t.Run("seed_bound", func(t *testing.T) {
		input := initialInput()
		seeds := make([]any, maxRequiredContextRefs+1)
		for index := range seeds {
			seeds[index] = "ctx." + twoDigits(index+1)
		}
		input["requiredContextRefIds"] = seeds
		requireReject(t, input)
		for _, invalid := range []([]any){{"ctx.02", "ctx.01"}, {"ctx.01", "ctx.01"}} {
			input = initialInput()
			input["requiredContextRefIds"] = invalid
			requireReject(t, input)
		}
	})
	t.Run("single_envelope_omission", func(t *testing.T) {
		input := initialInput()
		input["contextRefs"] = []any{contextValue("ctx.omit", "artifact", testDigest, nil)}
		envelope, err := BuildAgentEnvelope(input)
		if err != nil {
			t.Fatal(err)
		}
		omitted := envelope["omitted"].([]any)
		if len(omitted) != 1 || omitted[0].(map[string]any)["omittedCount"] != 1 {
			t.Fatalf("unexpected omission summary: %v", omitted)
		}
	})
	t.Run("text_cap", func(t *testing.T) {
		lines, err := BuildTextProjection(initialInput())
		if err != nil {
			t.Fatal(err)
		}
		lines[0].Label = strings.Repeat("x", maxTextBytes)
		if _, err := RenderText(lines); err == nil {
			t.Fatal("oversized text was admitted")
		}
	})
}

func twoDigits(value int) string {
	if value < 10 {
		return "0" + string(rune('0'+value))
	}
	return string([]byte{byte('0' + value/10), byte('0' + value%10)})
}
