package requirementcoverageview

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestCoverageBasisUsesDetachedRequirements(t *testing.T) {
	for _, count := range []int{0, 1, 3} {
		for _, mode := range []string{"full_repository", "selected_paths_advisory"} {
			for _, owner := range []string{"proofkit.coverage", "owner.outside"} {
				t.Run(fmt.Sprintf("%d/%s/%s", count, mode, owner), func(t *testing.T) {
					raw := validCoverageInput(t).(map[string]any)["requirementSource"].(map[string]any)
					group := coverageSourceGroup(raw)
					member := group["members"].([]any)[0]
					members := []any{}
					for index := count; index > 0; index-- {
						value := cloneRelationValue(t, member)
						value["requirementId"] = fmt.Sprintf("REQ-PROOFKIT-COVERAGE-%03d", index)
						if index%2 == 1 {
							value["fields"].(map[string]any)["ownerId"] = "owner.outside"
						}
						members = append(members, value)
					}
					group["members"] = members
					if count == 0 {
						raw["groups"] = []any{}
					}
					result, err := requirementsourceadmission.Evaluate(raw)
					if err != nil || result.ExitCode != 0 || result.Source.RequirementCount() != count {
						t.Fatalf("source fixture failed admission: %v; failures=%v", err, result.Failures)
					}
					input := compositeInput{Source: result.Source, CoverageUniverse: coverageUniverse{CompletenessDeclaration: mode, OwnerIDs: []string{owner}}}
					sourceBefore, err := requirementsourceadmission.SourceBytes(input.Source)
					if err != nil {
						t.Fatal(err)
					}
					requirementsBefore := input.Source.Requirements()
					basis, err := buildCoverageBasis(input, nil)
					if err != nil {
						t.Fatal(err)
					}
					rows, failures := []any{}, []string{}
					if mode == "full_repository" {
						for index := 1; index <= count; index++ {
							rowOwner := "proofkit.coverage"
							if index%2 == 1 {
								rowOwner = "owner.outside"
							}
							if rowOwner != owner {
								id := fmt.Sprintf("REQ-PROOFKIT-COVERAGE-%03d", index)
								rows = append(rows, map[string]any{"ownerId": rowOwner, "requirementId": id})
								failures = append(failures, "full_repository_source_requirement_outside_owner_scope:"+id)
							}
						}
					}
					want := map[string]any{"fullRepositoryOutOfScopeSourceRequirements": rows, "ownerIds": []any{owner}, "testInventoryDigest": nil}
					for _, layout := range []stablejson.Layout{stablejson.LayoutPretty, stablejson.LayoutCompact} {
						gotBytes, err := stablejson.MarshalLayout(basis, layout)
						if err != nil {
							t.Fatal(err)
						}
						wantBytes, err := stablejson.MarshalLayout(want, layout)
						if err != nil || !bytes.Equal(gotBytes, wantBytes) {
							t.Fatalf("coverage basis changed %s bytes: %v", layout, err)
						}
					}
					admitted, err := admitCoverageBasis(basis, true, mode, nil)
					if err != nil || !reflect.DeepEqual(admitted.ownerScopeFailures, failures) {
						t.Fatalf("coverage basis changed consumer-owned failures: %v; got=%v want=%v", err, admitted.ownerScopeFailures, failures)
					}
					basis["ownerIds"].([]any)[0] = "owner.changed"
					if values := basis["fullRepositoryOutOfScopeSourceRequirements"].([]any); len(values) > 0 {
						values[0].(map[string]any)["requirementId"] = "REQ-CHANGED"
					}
					sourceAfter, err := requirementsourceadmission.SourceBytes(input.Source)
					if err != nil || !bytes.Equal(sourceAfter, sourceBefore) || !reflect.DeepEqual(input.Source.Requirements(), requirementsBefore) {
						t.Fatalf("basis construction or caller mutation changed source bytes or review digests: %v", err)
					}
					again, err := buildCoverageBasis(input, nil)
					if err != nil || !reflect.DeepEqual(again, want) {
						t.Fatalf("basis mutation changed a later projection: %v", err)
					}
				})
			}
		}
	}
}
