package changeworkflowplan

import (
	"strings"
	"testing"
)

func TestWorkflowIdentityPredicates(t *testing.T) {
	t.Run("assessment_equality", func(t *testing.T) {
		input := reviewInput("review_passed")
		input["checkpoint"].(map[string]any)["assessmentSubjectDigest"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		requireReject(t, input)
	})
	t.Run("canonical_digest", func(t *testing.T) {
		input := reviewInput("ready_for_review")
		input["checkpoint"].(map[string]any)["subjectDigest"] = strings.ToUpper(testDigest)
		requireReject(t, input)
	})
	t.Run("declared_digest_equality", func(t *testing.T) {
		input := reviewInput("ready_for_review")
		input["checkpoint"].(map[string]any)["subjectDigest"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		requireReject(t, input)
	})
	t.Run("finding_kind", func(t *testing.T) {
		input := reviewInput("review_findings")
		input["checkpoint"].(map[string]any)["findingRefs"] = []any{"ctx.authority"}
		requireReject(t, input)
	})
	t.Run("identity_failure", func(t *testing.T) {
		mutants := []func(map[string]any){
			func(input map[string]any) { delete(input["checkpoint"].(map[string]any), "subjectRefId") },
			func(input map[string]any) { input["checkpoint"].(map[string]any)["surplus"] = true },
			func(input map[string]any) { input["checkpoint"].(map[string]any)["subjectRefId"] = "missing.artifact" },
			func(input map[string]any) { input["checkpoint"].(map[string]any)["subjectRefId"] = "ctx.authority" },
		}
		for _, mutate := range mutants {
			input := reviewInput("ready_for_review")
			mutate(input)
			requireReject(t, input)
		}
	})
	t.Run("subject_artifact", func(t *testing.T) {
		input := reviewInput("ready_for_review")
		input["checkpoint"].(map[string]any)["subjectRefId"] = "ctx.authority"
		requireReject(t, input)
	})
}
