package requirementsourceconversion

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

// writeFlat projects one model. Shared sections and metadata values are the
// grouped codec's canonical wire values; invariants are the model's resolved
// statements. The writer owns only record layout and coordinates.
func writeFlat(model requirementsourcemodel.Model) (map[string]any, error) {
	canonical, err := requirementsourcecodec.Format(model)
	if err != nil {
		return nil, refusal(documentInput, "invalid_model_projection", "")
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(canonical), int64(len(canonical)))
	if err != nil {
		return nil, refusal(documentInput, "invalid_model_projection", "")
	}
	grouped := decoded.(map[string]any)
	invariants := make(map[string]string, model.RequirementCount())
	order := make([]string, 0, model.RequirementCount())
	for _, requirement := range model.Requirements() {
		invariants[requirement.RequirementID] = requirement.Invariant
		order = append(order, requirement.RequirementID)
	}

	profileFields := map[string]map[string]any{}
	profiles := []any{}
	for _, raw := range section(grouped, "profiles") {
		profile := raw.(map[string]any)
		fields := profile["fields"].(map[string]any)
		profileID := profile["profileId"].(string)
		profileFields[profileID] = fields
		names := make([]string, 0, len(fields))
		for name := range fields {
			names = append(names, name)
		}
		slices.Sort(names)
		profiles = append(profiles, map[string]any{"profileId": profileID, "fieldIds": stringValues(names)})
	}

	rows := make(map[string]any, len(order))
	groups := []any{}
	for _, raw := range section(grouped, "groups") {
		group := raw.(map[string]any)
		profileID := group["profileId"].(string)
		members := group["members"].([]any)
		requirementIDs := make([]any, len(members))
		for index, rawMember := range members {
			member := rawMember.(map[string]any)
			requirementID := member["requirementId"].(string)
			fields, ok := resolvedFields(profileFields[profileID], member["fields"].(map[string]any))
			if !ok {
				return nil, refusal(documentInput, "invalid_model_projection", "")
			}
			rows[requirementID] = map[string]any{
				"requirementId":  requirementID,
				"invariant":      invariants[requirementID],
				"sharedPremises": group["sharedPremises"],
				"fields":         fields,
			}
			requirementIDs[index] = requirementID
		}
		groups = append(groups, map[string]any{
			"groupId":            group["groupId"],
			"profileId":          profileID,
			"statementStemBytes": json.Number(strconv.Itoa(len(group["statementStem"].(string)))),
			"requirementIds":     requirementIDs,
		})
	}
	requirements := make([]any, len(order))
	for index, requirementID := range order {
		requirements[index] = rows[requirementID]
	}
	return map[string]any{
		"kind":                FlatDocumentKind,
		"schemaVersion":       json.Number(strconv.Itoa(FlatSchemaVersion)),
		"basisDigest":         digest.SHA256BytesRef(canonical),
		"sourceId":            grouped["sourceId"],
		"specPackagePath":     grouped["specPackagePath"],
		"sourceNonClaims":     grouped["sourceNonClaims"],
		"sourceNonClaimRefs":  section(grouped, "sourceNonClaimRefs"),
		"nonClaimDefinitions": section(grouped, "nonClaimDefinitions"),
		"vocabulary":          section(grouped, "vocabulary"),
		"derivations":         section(grouped, "derivations"),
		"scenarios":           section(grouped, "scenarios"),
		"profiles":            profiles,
		"groups":              groups,
		"requirements":        requirements,
	}, nil
}

// resolvedFields joins the model's exclusive and total profile/member
// partition. Overlap or omission means the projection is not that partition.
func resolvedFields(profile, member map[string]any) (map[string]any, bool) {
	result := make(map[string]any, len(flatFieldIDs))
	for name, value := range profile {
		result[name] = value
	}
	for name, value := range member {
		if _, owned := result[name]; owned {
			return nil, false
		}
		result[name] = value
	}
	if len(result) != len(flatFieldIDs) {
		return nil, false
	}
	for _, name := range flatFieldIDs {
		if _, exists := result[name]; !exists {
			return nil, false
		}
	}
	return result, true
}

// section reads an optional canonical array; the codec omits empty ones.
func section(record map[string]any, name string) []any {
	values, _ := record[name].([]any)
	if values == nil {
		return []any{}
	}
	return values
}

func stringValues(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
