package migrationplan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

var phaseOrder = []string{
	"baseline",
	"parallel-proof",
	"parity-check",
	"retire-old-owner",
	"post-retirement-validation",
}

var migrationNonClaims = []string{
	"Migration plans do not edit files or delete old proof owners.",
	"Migration plans do not execute native witnesses.",
	"Migration plans do not authenticate parity evidence or decide proof freshness.",
	"Migration plans do not approve merge, rollout, or old-owner retirement.",
}

type sourceProofOwner struct {
	OwnerID          string
	OwnerKind        string
	Path             string
	RetirementPolicy string
}

type targetRef struct {
	Path       string
	TargetID   string
	TargetKind string
}

type parityEvidenceRef struct {
	EvidenceID    string
	EvidenceRef   string
	NonClaim      string
	SourceOwnerID string
	TargetID      string
}

type retirementCandidate struct {
	OwnerID    string
	Reason     string
	RemovalRef string
}

type followUpCommand struct {
	Command   string
	CommandID string
	NonClaim  string
	Owner     string
	Phase     string
}

type blockerItem struct {
	BlockerID        string
	NonClaim         string
	OwnerID          string
	Reason           string
	RequiredEvidence []string
}

type input struct {
	FollowUpCommands     []followUpCommand
	MigrationID          string
	NonClaims            []string
	ParityEvidenceRefs   []parityEvidenceRef
	RetainedOwners       []string
	RetirementCandidates []retirementCandidate
	SourceProofOwners    []sourceProofOwner
	TargetRefs           []targetRef
}

func Build(raw any) (map[string]any, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return nil, 1, err
	}
	plan, exitCode := build(input)
	return plan, exitCode, nil
}

func build(input input) (map[string]any, int) {
	blockers := migrationBlockers(input)
	admittedRetirementCandidates := []retirementCandidate{}
	if len(blockers) == 0 {
		admittedRetirementCandidates = input.RetirementCandidates
	}
	planState := "ready_for_caller_review"
	exitCode := 0
	if len(blockers) > 0 {
		planState = "blocked"
		exitCode = 1
	}
	nonClaims := sortedUniqueText(append(append([]string{}, migrationNonClaims...), input.NonClaims...), "migration plan nonClaims", false)
	return map[string]any{
		"blockers":             blockersToAny(blockers),
		"migrationId":          input.MigrationID,
		"nonClaims":            stringsToAny(nonClaims),
		"parityEvidenceRefs":   parityEvidenceToAny(input.ParityEvidenceRefs),
		"phases":               phasesToAny(buildPhases(input, admittedRetirementCandidates)),
		"planKind":             "proofkit.migration-plan",
		"planState":            planState,
		"retainedOwners":       stringsToAny(input.RetainedOwners),
		"retirementCandidates": retirementCandidatesToAny(input.RetirementCandidates),
		"schemaVersion":        1,
		"sourceProofOwners":    sourceOwnersToAny(input.SourceProofOwners),
		"targetProofkitRefs":   targetRefsToAny(input.TargetRefs),
	}, exitCode
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("migration plan input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"followUpCommands", "migrationId", "nonClaims", "parityEvidenceRefs", "retainedOwners", "retirementCandidates", "schemaVersion", "sourceProofOwners", "targetProofkitRefs"}, "migration plan input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("migration plan schemaVersion must be 1")
	}
	migrationID, err := admit.RuleID(record["migrationId"], "migration plan migrationId")
	if err != nil {
		return input{}, err
	}
	sourceOwners, err := sortedSourceProofOwners(record["sourceProofOwners"])
	if err != nil {
		return input{}, err
	}
	targetRefs, err := sortedTargetRefs(record["targetProofkitRefs"])
	if err != nil {
		return input{}, err
	}
	parityEvidenceRefs, err := sortedParityEvidenceRefs(record["parityEvidenceRefs"])
	if err != nil {
		return input{}, err
	}
	retirementCandidates, err := sortedRetirementCandidates(record["retirementCandidates"])
	if err != nil {
		return input{}, err
	}
	retainedOwners, err := sortedUniqueRuleIDs(record["retainedOwners"], "migration plan retainedOwners")
	if err != nil {
		return input{}, err
	}
	followUpCommands, err := sortedFollowUpCommands(record["followUpCommands"])
	if err != nil {
		return input{}, err
	}
	nonClaims, err := stringArray(record["nonClaims"], "migration plan nonClaims")
	if err != nil {
		return input{}, err
	}
	return input{
		FollowUpCommands:     followUpCommands,
		MigrationID:          migrationID,
		NonClaims:            nonClaims,
		ParityEvidenceRefs:   parityEvidenceRefs,
		RetainedOwners:       retainedOwners,
		RetirementCandidates: retirementCandidates,
		SourceProofOwners:    sourceOwners,
		TargetRefs:           targetRefs,
	}, nil
}

func buildPhases(input input, admittedRetirementCandidates []retirementCandidate) []map[string]any {
	phases := make([]map[string]any, 0, len(phaseOrder))
	for _, phase := range phaseOrder {
		phases = append(phases, map[string]any{
			"actions": actionsForPhase(phase, input, admittedRetirementCandidates),
			"phase":   phase,
		})
	}
	return phases
}

func actionsForPhase(phase string, input input, admittedRetirementCandidates []retirementCandidate) []any {
	phaseCommands := commandIDsForPhase(input.FollowUpCommands, phase)
	if phase == "baseline" {
		return []any{action("baseline", "Record the current caller-owned proof owners before changing proof infrastructure.", sourceOwnerPaths(input.SourceProofOwners), phaseCommands)}
	}
	if phase == "parallel-proof" {
		refs := append(sourceOwnerPaths(input.SourceProofOwners), targetRefPaths(input.TargetRefs)...)
		return []any{action("parallel-proof", "Keep old and target proofkit surfaces side by side until caller-owned parity evidence exists.", refs, phaseCommands)}
	}
	if phase == "parity-check" {
		return []any{action("parity-check", "Review caller-provided parity evidence without treating parity as correctness.", parityEvidencePaths(input.ParityEvidenceRefs), phaseCommands)}
	}
	if phase == "retire-old-owner" {
		actions := []any{}
		for _, candidate := range admittedRetirementCandidates {
			refs := []string{candidate.RemovalRef}
			for _, evidence := range input.ParityEvidenceRefs {
				if evidence.SourceOwnerID == candidate.OwnerID {
					refs = append(refs, evidence.EvidenceRef)
				}
			}
			actions = append(actions, action(
				"retire-"+candidate.OwnerID,
				fmt.Sprintf("Review retirement candidate %s: %s", candidate.OwnerID, candidate.Reason),
				refs,
				phaseCommands,
			))
		}
		return actions
	}
	return []any{action("post-retirement-validation", "Run caller-owned post-retirement validation after any old-owner removal.", targetRefPaths(input.TargetRefs), phaseCommands)}
}

func action(suffix string, instruction string, evidenceRefs []string, commandIDs []string) map[string]any {
	return map[string]any{
		"actionId":     "proofkit.migration-plan.action." + suffix,
		"commandIds":   stringsToAny(sortedUnique(evidenceOrCommandIDs(commandIDs))),
		"evidenceRefs": stringsToAny(sortedUnique(evidenceOrCommandIDs(evidenceRefs))),
		"instruction":  instruction,
		"nonClaim":     "Migration plan actions route caller-owned work only and do not approve edits, deletion, merge, rollout, or proof freshness.",
		"owner":        "consumer_repository",
	}
}

func migrationBlockers(input input) []blockerItem {
	sourceOwnerIDs := map[string]struct{}{}
	sourceOwnersByID := map[string]sourceProofOwner{}
	for _, owner := range input.SourceProofOwners {
		sourceOwnerIDs[owner.OwnerID] = struct{}{}
		sourceOwnersByID[owner.OwnerID] = owner
	}
	targetIDs := map[string]struct{}{}
	for _, target := range input.TargetRefs {
		targetIDs[target.TargetID] = struct{}{}
	}
	retainedOwnerIDs := stringSet(input.RetainedOwners)
	postRetirementCommands := []followUpCommand{}
	for _, command := range input.FollowUpCommands {
		if command.Phase == "post-retirement-validation" {
			postRetirementCommands = append(postRetirementCommands, command)
		}
	}
	blockers := []blockerItem{}
	for _, ownerID := range input.RetainedOwners {
		if _, ok := sourceOwnerIDs[ownerID]; !ok {
			blockers = append(blockers, blocker(ownerID, "retained owner must reference a source proof owner", []string{"sourceProofOwners.ownerId"}))
		}
	}
	for _, evidence := range input.ParityEvidenceRefs {
		if _, ok := sourceOwnerIDs[evidence.SourceOwnerID]; !ok {
			blockers = append(blockers, blocker(evidence.SourceOwnerID, "parity evidence must reference a source proof owner", []string{"sourceProofOwners.ownerId"}))
		}
		if _, ok := targetIDs[evidence.TargetID]; !ok {
			blockers = append(blockers, blocker(evidence.SourceOwnerID, "parity evidence must reference a target proofkit ref", []string{"targetProofkitRefs.targetId"}))
		}
	}
	validParityByOwner := map[string][]parityEvidenceRef{}
	for ownerID := range sourceOwnerIDs {
		validParityByOwner[ownerID] = []parityEvidenceRef{}
	}
	for _, evidence := range input.ParityEvidenceRefs {
		if _, sourceOK := sourceOwnerIDs[evidence.SourceOwnerID]; sourceOK {
			if _, targetOK := targetIDs[evidence.TargetID]; targetOK {
				validParityByOwner[evidence.SourceOwnerID] = append(validParityByOwner[evidence.SourceOwnerID], evidence)
			}
		}
	}
	for _, candidate := range input.RetirementCandidates {
		if _, ok := sourceOwnerIDs[candidate.OwnerID]; !ok {
			blockers = append(blockers, blocker(candidate.OwnerID, "retirement candidate must reference a source proof owner", []string{"sourceProofOwners.ownerId"}))
			continue
		}
		sourceOwner := sourceOwnersByID[candidate.OwnerID]
		if sourceOwner.RetirementPolicy == "retain" {
			blockers = append(blockers, blocker(candidate.OwnerID, "retirement candidate must not reference a retained source proof owner", []string{"sourceProofOwners.retirementPolicy"}))
		}
		if _, ok := retainedOwnerIDs[candidate.OwnerID]; ok {
			blockers = append(blockers, blocker(candidate.OwnerID, "retirement candidate must not be listed in retainedOwners", []string{"retainedOwners"}))
		}
		if len(validParityByOwner[candidate.OwnerID]) == 0 {
			blockers = append(blockers, blocker(candidate.OwnerID, "retirement candidate requires caller-provided parity evidence for a declared target", []string{"parityEvidenceRefs"}))
		}
		if len(postRetirementCommands) == 0 {
			blockers = append(blockers, blocker(candidate.OwnerID, "retirement candidate requires post-retirement validation commands", []string{"followUpCommands[phase=post-retirement-validation]"}))
		}
	}
	sort.Slice(blockers, func(left int, right int) bool {
		return blockers[left].BlockerID < blockers[right].BlockerID
	})
	return blockers
}

func blocker(ownerID string, reason string, requiredEvidence []string) blockerItem {
	return blockerItem{
		BlockerID:        "proofkit.migration-plan.blocker." + ownerID + "." + blockerReasonSlug(reason),
		NonClaim:         "Migration blockers are caller-review prompts and do not prove old-owner correctness or target readiness.",
		OwnerID:          ownerID,
		Reason:           reason,
		RequiredEvidence: requiredEvidence,
	}
}

func blockerReasonSlug(reason string) string {
	replaced := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(reason, "-")
	return strings.Trim(replaced, "-")
}

func sortedSourceProofOwners(raw any) ([]sourceProofOwner, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("migration plan sourceProofOwners must be an array")
	}
	result := []sourceProofOwner{}
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("migration plan source owner must be an object")
		}
		if err := admit.KnownKeys(record, []string{"ownerId", "ownerKind", "path", "retirementPolicy"}, "migration plan source owner"); err != nil {
			return nil, err
		}
		ownerID, err := admit.RuleID(record["ownerId"], "migration plan source ownerId")
		if err != nil {
			return nil, err
		}
		ownerPath, err := pathField(record["path"], "migration plan source owner path")
		if err != nil {
			return nil, err
		}
		ownerKind, err := enum(record["ownerKind"], []string{"local_script", "local_manifest", "local_doc", "local_test", "other"}, "migration plan source ownerKind")
		if err != nil {
			return nil, err
		}
		retirementPolicy, err := enum(record["retirementPolicy"], []string{"candidate", "retain"}, "migration plan source owner retirementPolicy")
		if err != nil {
			return nil, err
		}
		result = append(result, sourceProofOwner{OwnerID: ownerID, OwnerKind: ownerKind, Path: ownerPath, RetirementPolicy: retirementPolicy})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].OwnerID < result[right].OwnerID
	})
	if len(result) == 0 {
		return nil, fmt.Errorf("migration plan sourceProofOwners must not be empty")
	}
	return result, assertUnique(ownerIDs(result), "migration plan source owner ids")
}

func sortedTargetRefs(raw any) ([]targetRef, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("migration plan targetProofkitRefs must be an array")
	}
	result := []targetRef{}
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("migration plan target ref must be an object")
		}
		if err := admit.KnownKeys(record, []string{"path", "targetId", "targetKind"}, "migration plan target ref"); err != nil {
			return nil, err
		}
		targetID, err := admit.RuleID(record["targetId"], "migration plan targetId")
		if err != nil {
			return nil, err
		}
		targetPath, err := pathField(record["path"], "migration plan target path")
		if err != nil {
			return nil, err
		}
		targetKind, err := enum(record["targetKind"], []string{"proofkit_input", "proofkit_report", "proofkit_profile", "proofkit_view"}, "migration plan targetKind")
		if err != nil {
			return nil, err
		}
		result = append(result, targetRef{Path: targetPath, TargetID: targetID, TargetKind: targetKind})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].TargetID < result[right].TargetID
	})
	if len(result) == 0 {
		return nil, fmt.Errorf("migration plan targetProofkitRefs must not be empty")
	}
	return result, assertUnique(targetIDs(result), "migration plan target ids")
}

func sortedParityEvidenceRefs(raw any) ([]parityEvidenceRef, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("migration plan parityEvidenceRefs must be an array")
	}
	result := []parityEvidenceRef{}
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("migration plan parity evidence must be an object")
		}
		if err := admit.KnownKeys(record, []string{"evidenceId", "evidenceRef", "nonClaim", "sourceOwnerId", "targetId"}, "migration plan parity evidence"); err != nil {
			return nil, err
		}
		evidenceID, err := admit.RuleID(record["evidenceId"], "migration plan parity evidenceId")
		if err != nil {
			return nil, err
		}
		sourceOwnerID, err := admit.RuleID(record["sourceOwnerId"], "migration plan parity sourceOwnerId")
		if err != nil {
			return nil, err
		}
		targetID, err := admit.RuleID(record["targetId"], "migration plan parity targetId")
		if err != nil {
			return nil, err
		}
		evidenceRef, err := pathField(record["evidenceRef"], "migration plan parity evidenceRef")
		if err != nil {
			return nil, err
		}
		nonClaim, err := nonEmptyText(record["nonClaim"], "migration plan parity nonClaim")
		if err != nil {
			return nil, err
		}
		result = append(result, parityEvidenceRef{EvidenceID: evidenceID, EvidenceRef: evidenceRef, NonClaim: nonClaim, SourceOwnerID: sourceOwnerID, TargetID: targetID})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].EvidenceID < result[right].EvidenceID
	})
	return result, assertUnique(parityEvidenceIDs(result), "migration plan parity evidence ids")
}

func sortedRetirementCandidates(raw any) ([]retirementCandidate, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("migration plan retirementCandidates must be an array")
	}
	result := []retirementCandidate{}
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("migration plan retirement candidate must be an object")
		}
		if err := admit.KnownKeys(record, []string{"ownerId", "reason", "removalRef"}, "migration plan retirement candidate"); err != nil {
			return nil, err
		}
		ownerID, err := admit.RuleID(record["ownerId"], "migration plan retirement candidate ownerId")
		if err != nil {
			return nil, err
		}
		removalRef, err := pathField(record["removalRef"], "migration plan retirement candidate removalRef")
		if err != nil {
			return nil, err
		}
		reason, err := nonEmptyText(record["reason"], "migration plan retirement candidate reason")
		if err != nil {
			return nil, err
		}
		result = append(result, retirementCandidate{OwnerID: ownerID, Reason: reason, RemovalRef: removalRef})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].OwnerID < result[right].OwnerID
	})
	return result, assertUnique(retirementOwnerIDs(result), "migration plan retirement candidate owner ids")
}

func sortedFollowUpCommands(raw any) ([]followUpCommand, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("migration plan followUpCommands must be an array")
	}
	result := []followUpCommand{}
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("migration plan follow-up command must be an object")
		}
		if err := admit.KnownKeys(record, []string{"command", "commandId", "nonClaim", "owner", "phase"}, "migration plan follow-up command"); err != nil {
			return nil, err
		}
		commandID, err := admit.RuleID(record["commandId"], "migration plan commandId")
		if err != nil {
			return nil, err
		}
		command, err := admit.DisplayOnlyCommandText(record["command"], "migration plan command")
		if err != nil {
			return nil, err
		}
		phase, err := enum(record["phase"], phaseOrder, "migration plan command phase")
		if err != nil {
			return nil, err
		}
		owner, err := enum(record["owner"], []string{"consumer_repository"}, "migration plan command owner")
		if err != nil {
			return nil, err
		}
		nonClaim, err := nonEmptyText(record["nonClaim"], "migration plan command nonClaim")
		if err != nil {
			return nil, err
		}
		result = append(result, followUpCommand{Command: command, CommandID: commandID, NonClaim: nonClaim, Owner: owner, Phase: phase})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].CommandID < result[right].CommandID
	})
	return result, assertUnique(commandIDs(result), "migration plan command ids")
}

func sortedUniqueRuleIDs(raw any, context string) ([]string, error) {
	values, err := stringArray(raw, context)
	if err != nil {
		return nil, err
	}
	result := []string{}
	for _, value := range values {
		ruleID, err := admit.RuleID(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, ruleID)
	}
	sort.Strings(result)
	return result, assertUnique(result, context)
}

func sortedUniqueText(values []string, context string, allowEmpty bool) []string {
	normalized := []string{}
	for _, value := range values {
		normalized = append(normalized, strings.TrimSpace(value))
	}
	sort.Strings(normalized)
	if !allowEmpty && len(normalized) == 0 {
		return normalized
	}
	result := []string{}
	for _, value := range normalized {
		if value == "" {
			continue
		}
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func enum(raw any, allowed []string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, strings.Join(allowed, ", "))
	}
	for _, candidate := range allowed {
		if value == candidate {
			return value, nil
		}
	}
	return "", fmt.Errorf("%s must be one of: %s", context, strings.Join(allowed, ", "))
}

func nonEmptyText(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func pathField(raw any, context string) (string, error) {
	value, err := nonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
}

func stringArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := []string{}
	for _, value := range values {
		text, err := nonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	return result, nil
}

func assertUnique(values []string, context string) error {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return nil
}

func evidenceOrCommandIDs(values []string) []string {
	return append([]string{}, values...)
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := []string{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func stringsToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func sourceOwnerPaths(values []sourceProofOwner) []string {
	result := []string{}
	for _, value := range values {
		result = append(result, value.Path)
	}
	return result
}

func targetRefPaths(values []targetRef) []string {
	result := []string{}
	for _, value := range values {
		result = append(result, value.Path)
	}
	return result
}

func parityEvidencePaths(values []parityEvidenceRef) []string {
	result := []string{}
	for _, value := range values {
		result = append(result, value.EvidenceRef)
	}
	return result
}

func commandIDsForPhase(values []followUpCommand, phase string) []string {
	result := []string{}
	for _, value := range values {
		if value.Phase == phase {
			result = append(result, value.CommandID)
		}
	}
	return result
}

func blockersToAny(values []blockerItem) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{
			"blockerId":        value.BlockerID,
			"nonClaim":         value.NonClaim,
			"ownerId":          value.OwnerID,
			"reason":           value.Reason,
			"requiredEvidence": stringsToAny(value.RequiredEvidence),
		})
	}
	return result
}

func phasesToAny(values []map[string]any) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func sourceOwnersToAny(values []sourceProofOwner) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{
			"ownerId":          value.OwnerID,
			"ownerKind":        value.OwnerKind,
			"path":             value.Path,
			"retirementPolicy": value.RetirementPolicy,
		})
	}
	return result
}

func targetRefsToAny(values []targetRef) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{
			"path":       value.Path,
			"targetId":   value.TargetID,
			"targetKind": value.TargetKind,
		})
	}
	return result
}

func parityEvidenceToAny(values []parityEvidenceRef) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{
			"evidenceId":    value.EvidenceID,
			"evidenceRef":   value.EvidenceRef,
			"nonClaim":      value.NonClaim,
			"sourceOwnerId": value.SourceOwnerID,
			"targetId":      value.TargetID,
		})
	}
	return result
}

func retirementCandidatesToAny(values []retirementCandidate) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{
			"ownerId":    value.OwnerID,
			"reason":     value.Reason,
			"removalRef": value.RemovalRef,
		})
	}
	return result
}

func ownerIDs(values []sourceProofOwner) []string {
	result := []string{}
	for _, value := range values {
		result = append(result, value.OwnerID)
	}
	return result
}

func targetIDs(values []targetRef) []string {
	result := []string{}
	for _, value := range values {
		result = append(result, value.TargetID)
	}
	return result
}

func parityEvidenceIDs(values []parityEvidenceRef) []string {
	result := []string{}
	for _, value := range values {
		result = append(result, value.EvidenceID)
	}
	return result
}

func retirementOwnerIDs(values []retirementCandidate) []string {
	result := []string{}
	for _, value := range values {
		result = append(result, value.OwnerID)
	}
	return result
}

func commandIDs(values []followUpCommand) []string {
	result := []string{}
	for _, value := range values {
		result = append(result, value.CommandID)
	}
	return result
}

func stringSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
