package adoptionworkflow

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

// Each alternative is a complete AND bundle; any one bundle satisfies the
// prerequisite. Preset selection is a separate scalar, never an input kind.
type inputAlternatives [][]string

type prerequisite struct {
	AnswerKind        string
	Reason            string
	InputAlternatives inputAlternatives
}

func workflowPrerequisites(scenario string) []prerequisite {
	preset := prerequisite{AnswerKind: presetChoiceAnswer, Reason: "scenario requires caller-selected stack preset", InputAlternatives: inputAlternatives{}}
	var required []string
	var result []prerequisite
	switch scenario {
	case "new_repository":
		required = []string{"gradual_adoption_bootstrap", "gradual_adoption_guidance", "repo_profile_scaffold"}
		result = []prerequisite{preset, {
			AnswerKind: missingContextAnswer,
			Reason:     "new repository requires bootstrap witness plan or requirement bindings and witness plan input refs",
			InputAlternatives: inputAlternatives{
				{"bootstrap_witness_plan"}, {"requirement_bindings", "witness_plan"},
			},
		}}
	case "existing_gradual_adoption":
		required = []string{"gradual_adoption_bootstrap", "gradual_adoption_guidance", "repo_profile_scaffold", "requirement_bindings", "selective_gate_evidence", "selective_gate_plan", "witness_plan"}
		result = []prerequisite{preset}
	case "legacy_proof_migration":
		required = []string{"migration_plan", "requirement_bindings", "selective_gate_evidence", "selective_gate_plan"}
	default: // release_channel; scenario admission excludes other values.
		required = []string{"release_authority"}
		result = []prerequisite{{
			AnswerKind: missingContextAnswer,
			Reason:     "release channel requires external or registry consumer evidence input ref",
			InputAlternatives: inputAlternatives{
				{"external_consumer"}, {"registry_consumer"},
			},
		}}
	}
	for _, kind := range required {
		result = append(result, prerequisite{
			AnswerKind:        missingContextAnswer,
			Reason:            fmt.Sprintf("scenario requires %s input ref", kind),
			InputAlternatives: inputAlternatives{{kind}},
		})
	}
	return result
}

// Remove supplied kinds and retain only inclusion-minimal residual bundles.
// An empty residual satisfies the OR and therefore produces no input blocker.
func (alternatives inputAlternatives) remaining(refs map[string]inputRef) inputAlternatives {
	remaining := make(inputAlternatives, 0, len(alternatives))
	for _, bundle := range alternatives {
		missing := []string{}
		for _, kind := range bundle {
			if _, supplied := refs[kind]; !supplied {
				missing = append(missing, kind)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		slices.Sort(missing)
		remaining = append(remaining, slices.Compact(missing))
	}
	slices.SortFunc(remaining, slices.Compare[[]string])
	remaining = slices.CompactFunc(remaining, slices.Equal[[]string])
	minimal := make(inputAlternatives, 0, len(remaining))
	for _, candidate := range remaining {
		dominated := false
		for _, other := range remaining {
			if len(other) >= len(candidate) {
				continue
			}
			if containsBundle(candidate, other) {
				dominated = true
				break
			}
		}
		if !dominated {
			minimal = append(minimal, candidate)
		}
	}
	return minimal
}

func containsBundle(bundle, subset []string) bool {
	for _, kind := range subset {
		if !slices.Contains(bundle, kind) {
			return false
		}
	}
	return true
}

func (alternatives inputAlternatives) kinds() []string {
	kinds := []string{}
	for _, bundle := range alternatives {
		kinds = append(kinds, bundle...)
	}
	return uniqueSorted(kinds)
}

func (alternatives inputAlternatives) description() string {
	bundles := make([]string, 0, len(alternatives))
	for _, bundle := range alternatives {
		bundles = append(bundles, "("+strings.Join(bundle, " AND ")+")")
	}
	return strings.Join(bundles, " OR ")
}

func (alternatives inputAlternatives) json() []any {
	result := make([]any, 0, len(alternatives))
	for _, bundle := range alternatives {
		result = append(result, admit.StringSliceToAny(bundle))
	}
	return result
}
