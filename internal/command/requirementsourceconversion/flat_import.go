package requirementsourceconversion

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

// flatReconstruction is one admitted model plus the flat coordinates needed to
// report later refusals at the caller's own record positions.
type flatReconstruction struct {
	model       requirementsourcemodel.Model
	basisDigest string
	locator     flatLocator
}

// flatLocator maps grouped draft positions back to flat document positions.
type flatLocator struct {
	groupRows        [][]int
	profileRows      []int
	rowByRequirement map[string]int
	coordinateOfRow  [][2]int
	groupByID        map[string]int
	profileByID      map[string]int
}

// readFlat is a structural transcoder. It turns explicit coordinates into the
// grouped draft and leaves every semantic decision to the grouped codec and
// model. It never derives ownership from equal values: profile, stem and
// premise values are taken from one member record and every other member
// record must state exactly the same JSON value.
func readFlat(raw any) (flatReconstruction, error) {
	admitted, err := flatShape.Admit(raw, "flat document")
	if err != nil {
		return flatReconstruction{}, &Error{Document: documentInput, Code: "invalid_flat_structure", Detail: err.Error()}
	}
	record := admitted.(map[string]any)
	rows := record["requirements"].([]any)
	profiles := record["profiles"].([]any)
	groups := record["groups"].([]any)
	locator := flatLocator{
		groupRows:        make([][]int, len(groups)),
		profileRows:      make([]int, len(profiles)),
		rowByRequirement: make(map[string]int, len(rows)),
		coordinateOfRow:  make([][2]int, len(rows)),
		groupByID:        make(map[string]int, len(groups)),
		profileByID:      make(map[string]int, len(profiles)),
	}

	for index, row := range rows {
		requirementID := row.(map[string]any)["requirementId"].(string)
		if _, exists := locator.rowByRequirement[requirementID]; exists {
			return flatReconstruction{}, refusal(documentInput, "duplicate_requirement_row", pointer("requirements", index, "requirementId"))
		}
		locator.rowByRequirement[requirementID] = index
	}

	fieldSets := make([]map[string]bool, len(profiles))
	for index, raw := range profiles {
		profile := raw.(map[string]any)
		profileID := profile["profileId"].(string)
		if _, exists := locator.profileByID[profileID]; exists {
			return flatReconstruction{}, refusal(documentInput, "duplicate_profile_coordinate", pointer("profiles", index, "profileId"))
		}
		locator.profileByID[profileID] = index
		locator.profileRows[index] = -1
		fieldSets[index] = map[string]bool{}
		for fieldIndex, field := range profile["fieldIds"].([]any) {
			name := field.(string)
			if fieldSets[index][name] {
				return flatReconstruction{}, refusal(documentInput, "duplicate_profile_field", pointer("profiles", index, "fieldIds", fieldIndex))
			}
			fieldSets[index][name] = true
		}
	}

	claimed := make([]bool, len(rows))
	for groupIndex, raw := range groups {
		group := raw.(map[string]any)
		if _, exists := locator.groupByID[group["groupId"].(string)]; !exists {
			locator.groupByID[group["groupId"].(string)] = groupIndex
		}
		profileID := group["profileId"].(string)
		profileIndex, profiled := locator.profileByID[profileID]
		if profileID != "" && !profiled {
			return flatReconstruction{}, refusal(documentInput, "unknown_profile_coordinate", pointer("groups", groupIndex, "profileId"))
		}
		for memberIndex, rawID := range group["requirementIds"].([]any) {
			rowIndex, exists := locator.rowByRequirement[rawID.(string)]
			if !exists {
				return flatReconstruction{}, refusal(documentInput, "unknown_requirement_coordinate", pointer("groups", groupIndex, "requirementIds", memberIndex))
			}
			if claimed[rowIndex] {
				return flatReconstruction{}, refusal(documentInput, "duplicate_requirement_coordinate", pointer("groups", groupIndex, "requirementIds", memberIndex))
			}
			claimed[rowIndex] = true
			locator.groupRows[groupIndex] = append(locator.groupRows[groupIndex], rowIndex)
			locator.coordinateOfRow[rowIndex] = [2]int{groupIndex, memberIndex}
			if profiled && locator.profileRows[profileIndex] < 0 {
				locator.profileRows[profileIndex] = rowIndex
			}
		}
	}
	for index := range rows {
		if !claimed[index] {
			return flatReconstruction{}, refusal(documentInput, "unassigned_requirement_row", pointer("requirements", index))
		}
	}
	for index, row := range locator.profileRows {
		if row < 0 {
			return flatReconstruction{}, refusal(documentInput, "unobserved_profile_coordinate", pointer("profiles", index))
		}
	}

	draftProfiles := make([]any, len(profiles))
	for index, raw := range profiles {
		reference := rows[locator.profileRows[index]].(map[string]any)["fields"].(map[string]any)
		fields := make(map[string]any, len(fieldSets[index]))
		for name := range fieldSets[index] {
			fields[name] = reference[name]
		}
		draftProfiles[index] = map[string]any{"profileId": raw.(map[string]any)["profileId"], "fields": fields}
	}

	draftGroups := make([]any, len(groups))
	for groupIndex, raw := range groups {
		group := raw.(map[string]any)
		profileID := group["profileId"].(string)
		var owned map[string]bool
		var profileValues map[string]any
		if profileID != "" {
			profileIndex := locator.profileByID[profileID]
			owned = fieldSets[profileIndex]
			profileValues = draftProfiles[profileIndex].(map[string]any)["fields"].(map[string]any)
		}
		stemBytes, _ := strconv.Atoi(group["statementStemBytes"].(json.Number).String())
		stem := ""
		var premises any = []any{}
		members := make([]any, len(locator.groupRows[groupIndex]))
		for position, rowIndex := range locator.groupRows[groupIndex] {
			row := rows[rowIndex].(map[string]any)
			invariant := row["invariant"].(string)
			completion := invariant
			if stemBytes > 0 {
				// The model joins a nonempty stem and completion with one space.
				if stemBytes >= len(invariant) || invariant[stemBytes] != ' ' {
					return flatReconstruction{}, refusal(documentInput, "invalid_statement_stem_bytes", pointer("requirements", rowIndex, "invariant"))
				}
				completion = invariant[stemBytes+1:]
				if position == 0 {
					stem = invariant[:stemBytes]
				} else if invariant[:stemBytes] != stem {
					return flatReconstruction{}, refusal(documentInput, "statement_stem_disagreement", pointer("requirements", rowIndex, "invariant"))
				}
			}
			if position == 0 {
				premises = row["sharedPremises"]
			} else if !reflect.DeepEqual(premises, row["sharedPremises"]) {
				return flatReconstruction{}, refusal(documentInput, "shared_premises_disagreement", pointer("requirements", rowIndex, "sharedPremises"))
			}
			values := row["fields"].(map[string]any)
			memberFields := make(map[string]any, len(flatFieldIDs)-len(owned))
			for _, name := range flatFieldIDs {
				if !owned[name] {
					memberFields[name] = values[name]
					continue
				}
				if !reflect.DeepEqual(profileValues[name], values[name]) {
					return flatReconstruction{}, refusal(documentInput, "profile_value_disagreement", pointer("requirements", rowIndex, "fields", name))
				}
			}
			members[position] = map[string]any{
				"requirementId":       row["requirementId"],
				"statementCompletion": completion,
				"fields":              memberFields,
			}
		}
		draftGroups[groupIndex] = map[string]any{
			"groupId":        group["groupId"],
			"profileId":      profileID,
			"statementStem":  stem,
			"sharedPremises": premises,
			"members":        members,
		}
	}

	draft := map[string]any{
		"schemaVersion":       json.Number(strconv.Itoa(requirementsourcecodec.SchemaVersion)),
		"kind":                requirementsourcecodec.DocumentKind,
		"sourceId":            record["sourceId"],
		"specPackagePath":     record["specPackagePath"],
		"sourceNonClaims":     record["sourceNonClaims"],
		"sourceNonClaimRefs":  record["sourceNonClaimRefs"],
		"nonClaimDefinitions": record["nonClaimDefinitions"],
		"vocabulary":          record["vocabulary"],
		"derivations":         record["derivations"],
		"scenarios":           record["scenarios"],
		"profiles":            draftProfiles,
		"groups":              draftGroups,
	}
	model, err := admitGroupedValue(draft, documentInput, locator.translate, locator.requirement)
	if err != nil {
		return flatReconstruction{}, err
	}
	return flatReconstruction{model: model, basisDigest: record["basisDigest"].(string), locator: locator}, nil
}

func (locator flatLocator) requirement(requirementID string) string {
	if index, exists := locator.rowByRequirement[requirementID]; exists {
		return pointer("requirements", index)
	}
	return "/requirements"
}

// translate maps a grouped codec pointer over the transcoded draft to the flat
// document. Unrecognized or placeholder positions fall back to their nearest
// flat owner, so the result is total and contains no caller-authored token
// beyond the codec's own safe tail segments.
func (locator flatLocator) translate(path string) string {
	if path == "" {
		return ""
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	switch segments[0] {
	case "groups":
		return locator.translateGroup(segments)
	case "profiles":
		return locator.translateProfile(segments)
	case "schemaVersion", "kind":
		return ""
	default:
		return path
	}
}

func (locator flatLocator) translateGroup(segments []string) string {
	groupIndex, ok := index(segments, 1, len(locator.groupRows))
	if !ok {
		return "/groups"
	}
	if len(segments) == 2 {
		return pointer("groups", groupIndex)
	}
	rows := locator.groupRows[groupIndex]
	switch segments[2] {
	case "groupId", "profileId":
		return pointer("groups", groupIndex, segments[2])
	case "statementStem":
		return pointer("groups", groupIndex, "statementStemBytes")
	case "sharedPremises":
		if len(rows) == 0 {
			return pointer("groups", groupIndex)
		}
		return joinTail(pointer("requirements", rows[0], "sharedPremises"), segments[3:])
	case "members":
	default:
		return pointer("groups", groupIndex)
	}
	memberIndex, ok := index(segments, 3, len(rows))
	if !ok {
		return pointer("groups", groupIndex, "requirementIds")
	}
	row := pointer("requirements", rows[memberIndex])
	if len(segments) == 4 {
		return row
	}
	switch segments[4] {
	case "requirementId":
		return row + "/requirementId"
	case "statementCompletion":
		return row + "/invariant"
	case "fields":
		return joinTail(row+"/fields", segments[5:])
	default:
		return row
	}
}

func (locator flatLocator) translateProfile(segments []string) string {
	profileIndex, ok := index(segments, 1, len(locator.profileRows))
	if !ok {
		return "/profiles"
	}
	if len(segments) == 2 {
		return pointer("profiles", profileIndex)
	}
	switch segments[2] {
	case "profileId":
		return pointer("profiles", profileIndex, "profileId")
	case "fields":
		if len(segments) == 3 {
			return pointer("profiles", profileIndex, "fieldIds")
		}
		return joinTail(pointer("requirements", locator.profileRows[profileIndex], "fields"), segments[3:])
	default:
		return pointer("profiles", profileIndex)
	}
}

func joinTail(base string, tail []string) string {
	if len(tail) == 0 {
		return base
	}
	return base + "/" + strings.Join(tail, "/")
}

func index(segments []string, position int, count int) (int, bool) {
	if len(segments) <= position {
		return 0, false
	}
	value, err := strconv.Atoi(segments[position])
	if err != nil || value < 0 || value >= count || strconv.Itoa(value) != segments[position] {
		return 0, false
	}
	return value, true
}

// compareOwnership admits value edits only. Requirement identity, group
// membership, profile assignment, field ownership and statement stems must
// equal the baseline that the flat document was exported from.
func compareOwnership(reconstruction flatReconstruction, baseline requirementsourcemodel.Model) error {
	model := reconstruction.model
	locator := reconstruction.locator
	if model.SourceID() != baseline.SourceID() {
		return refusal(documentInput, "source_identity_changed", "/sourceId")
	}
	if model.SpecPackagePath() != baseline.SpecPackagePath() {
		return refusal(documentInput, "source_identity_changed", "/specPackagePath")
	}
	got, want := model.Layout(), baseline.Layout()
	expected := make(map[string]requirementsourcemodel.Origin, len(want.Origins))
	for _, origin := range want.Origins {
		expected[origin.RequirementID] = origin
	}
	present := make(map[string]struct{}, len(got.Origins))
	for _, origin := range got.Origins {
		present[origin.RequirementID] = struct{}{}
	}
	for _, origin := range want.Origins {
		if _, exists := present[origin.RequirementID]; !exists {
			return refusal(documentInput, "requirement_set_changed", "/requirements")
		}
	}
	for _, origin := range got.Origins {
		prior, exists := expected[origin.RequirementID]
		row := locator.rowByRequirement[origin.RequirementID]
		slot := locator.coordinateOfRow[row]
		switch {
		case !exists:
			return refusal(documentInput, "requirement_set_changed", pointer("requirements", row))
		case origin.GroupID != prior.GroupID:
			return refusal(documentInput, "group_membership_changed", pointer("groups", slot[0], "requirementIds", slot[1]))
		case origin.ProfileID != prior.ProfileID:
			return refusal(documentInput, "group_profile_changed", pointer("groups", slot[0], "profileId"))
		case !reflect.DeepEqual(origin.FieldOwners, prior.FieldOwners):
			return refusal(documentInput, "profile_fields_changed", pointer("profiles", locator.profileByID[origin.ProfileID], "fieldIds"))
		}
	}
	stems := make(map[string]string, len(want.Groups))
	for _, group := range want.Groups {
		stems[group.GroupID] = group.StatementStem
	}
	for _, group := range got.Groups {
		if group.StatementStem != stems[group.GroupID] {
			return refusal(documentInput, "statement_stem_changed", pointer("groups", locator.groupByID[group.GroupID], "statementStemBytes"))
		}
	}
	return nil
}
