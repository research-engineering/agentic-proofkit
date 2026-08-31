package changeworkflowplan

import (
	"fmt"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

var checkpointStates = map[string]struct{}{
	"not_started":      {},
	"ready_for_review": {},
	"review_findings":  {},
	"review_passed":    {},
}

var contextRefKinds = map[string]struct{}{
	"artifact":  {},
	"authority": {},
	"finding":   {},
	"witness":   {},
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, reject("proofkit.workflow.input_object", "change workflow input must be an object")
	}
	if err := knownKeys(record, []string{"checkpoint", "completedStageIds", "contextRefs", "governingAuthorityRefId", "requiredContextRefIds", "schemaVersion"}, "proofkit.workflow.input_fields"); err != nil {
		return admittedInput{}, err
	}
	for _, key := range []string{"checkpoint", "completedStageIds", "contextRefs", "governingAuthorityRefId", "requiredContextRefIds", "schemaVersion"} {
		if _, exists := record[key]; !exists {
			return admittedInput{}, reject("proofkit.workflow.input_fields", "change workflow input is missing a required field")
		}
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, reject("proofkit.workflow.schema_version", "change workflow schemaVersion must be 1")
	}
	completed, err := admitCompletedStages(record["completedStageIds"])
	if err != nil {
		return admittedInput{}, err
	}
	checkpointValue, err := admitCheckpoint(record["checkpoint"], len(completed) == len(stageTable))
	if err != nil {
		return admittedInput{}, err
	}
	contextRefs, err := admitContextRefs(record["contextRefs"])
	if err != nil {
		return admittedInput{}, err
	}
	governingAuthorityRefID, err := admitNullableRefID(record["governingAuthorityRefId"])
	if err != nil {
		return admittedInput{}, err
	}
	required, err := admitRefIDArray(record["requiredContextRefIds"], "required context refs", maxRequiredContextRefs)
	if err != nil {
		return admittedInput{}, err
	}
	input := admittedInput{
		Checkpoint:              checkpointValue,
		CompletedStageIDs:       completed,
		ContextRefs:             contextRefs,
		GoverningAuthorityRefID: governingAuthorityRefID,
		RequiredContextRefIDs:   required,
		SchemaVersion:           1,
	}
	if err := validateGlobalReferences(input); err != nil {
		return admittedInput{}, err
	}
	return input, nil
}

func admitCompletedStages(raw any) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) > len(stageTable) {
		return nil, reject("proofkit.workflow.stage_prefix", "completedStageIds must be a stage prefix")
	}
	result := make([]string, len(values))
	for index, rawValue := range values {
		value, ok := rawValue.(string)
		if !ok || value != stageTable[index].ID {
			return nil, reject("proofkit.workflow.stage_prefix", "completedStageIds must be a stage prefix")
		}
		result[index] = value
	}
	return result, nil
}

func admitCheckpoint(raw any, complete bool) (*checkpoint, error) {
	if complete {
		if raw != nil {
			return nil, reject("proofkit.workflow.complete_checkpoint", "a complete workflow requires a null checkpoint")
		}
		return nil, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, reject("proofkit.workflow.incomplete_checkpoint", "an incomplete workflow requires a checkpoint object")
	}
	state, err := admit.Enum(record["state"], checkpointStates, "change workflow checkpoint state")
	if err != nil {
		return nil, reject("proofkit.workflow.checkpoint_variant", "checkpoint state is invalid")
	}
	expectedKeys := map[string][]string{
		"not_started":      {"state"},
		"ready_for_review": {"state", "subjectDigest", "subjectRefId"},
		"review_findings":  {"assessmentSubjectDigest", "findingRefs", "state", "subjectDigest", "subjectRefId"},
		"review_passed":    {"assessmentSubjectDigest", "state", "subjectDigest", "subjectRefId"},
	}[state]
	if err := knownKeys(record, expectedKeys, "proofkit.workflow.checkpoint_fields"); err != nil {
		return nil, err
	}
	for _, key := range expectedKeys {
		if _, exists := record[key]; !exists {
			return nil, reject("proofkit.workflow.checkpoint_fields", "checkpoint variant is missing a required field")
		}
	}
	result := &checkpoint{State: state, FindingRefs: []string{}}
	if state == "not_started" {
		return result, nil
	}
	result.SubjectRefID, err = admitRefID(record["subjectRefId"])
	if err != nil {
		return nil, err
	}
	result.SubjectDigest, err = admitDigest(record["subjectDigest"])
	if err != nil {
		return nil, err
	}
	if state == "review_findings" || state == "review_passed" {
		result.AssessmentSubjectDigest, err = admitDigest(record["assessmentSubjectDigest"])
		if err != nil {
			return nil, err
		}
		if result.AssessmentSubjectDigest != result.SubjectDigest {
			return nil, reject("proofkit.workflow.assessment_digest_mismatch", "assessmentSubjectDigest must equal subjectDigest")
		}
	}
	if state == "review_findings" {
		result.FindingRefs, err = admitRefIDArray(record["findingRefs"], "finding refs", maxFindings)
		if err != nil {
			return nil, err
		}
		if len(result.FindingRefs) == 0 {
			return nil, reject("proofkit.workflow.finding_refs", "review_findings requires at least one finding ref")
		}
	}
	return result, nil
}

func admitContextRefs(raw any) ([]contextRef, error) {
	values, ok := raw.([]any)
	if !ok || len(values) > maxCandidateContextRefs {
		return nil, reject("proofkit.workflow.candidate_context_limit", "contextRefs exceeds the candidate limit")
	}
	result := make([]contextRef, 0, len(values))
	pathBytes := 0
	for _, rawValue := range values {
		record, ok := rawValue.(map[string]any)
		if !ok {
			return nil, reject("proofkit.workflow.context_ref_object", "contextRefs entries must be objects")
		}
		if err := knownKeys(record, []string{"artifactPath", "dependencyRefIds", "refId", "refKind", "subjectDigest"}, "proofkit.workflow.context_ref_fields"); err != nil {
			return nil, err
		}
		for _, key := range []string{"artifactPath", "dependencyRefIds", "refId", "refKind", "subjectDigest"} {
			if _, exists := record[key]; !exists {
				return nil, reject("proofkit.workflow.context_ref_fields", "context ref is missing a required field")
			}
		}
		refID, err := admitRefID(record["refId"])
		if err != nil {
			return nil, err
		}
		kind, err := admit.Enum(record["refKind"], contextRefKinds, "change workflow context ref kind")
		if err != nil {
			return nil, reject("proofkit.workflow.context_ref_kind", "context ref kind is invalid")
		}
		pathValue, err := admitDisplayPath(record["artifactPath"])
		if err != nil {
			return nil, err
		}
		digestValue, err := admitDigest(record["subjectDigest"])
		if err != nil {
			return nil, err
		}
		dependencies, err := admitRefIDArray(record["dependencyRefIds"], "dependency refs", maxDependenciesPerRef)
		if err != nil {
			return nil, err
		}
		pathBytes += len(pathValue)
		if pathBytes > maxCandidatePathBytes {
			return nil, reject("proofkit.workflow.candidate_path_bytes_exceeded", "candidate context paths exceed the aggregate byte limit")
		}
		result = append(result, contextRef{ArtifactPath: pathValue, DependencyRefIDs: dependencies, RefID: refID, RefKind: kind, SubjectDigest: digestValue})
	}
	for index := range result {
		if index > 0 && result[index-1].RefID >= result[index].RefID {
			return nil, reject("proofkit.workflow.context_ref_order", "contextRefs must be strictly sorted and unique by refId")
		}
	}
	return result, nil
}

func admitRefIDArray(raw any, label string, limit int) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) > limit {
		return nil, reject("proofkit.workflow.ref_array_bound", label+" exceed their bound")
	}
	result := make([]string, len(values))
	for index, rawValue := range values {
		value, err := admitRefID(rawValue)
		if err != nil {
			return nil, err
		}
		result[index] = value
		if index > 0 && result[index-1] >= result[index] {
			return nil, reject("proofkit.workflow.ref_array_order", label+" must be strictly sorted and unique")
		}
	}
	return result, nil
}

func admitRefID(raw any) (string, error) {
	value, err := admit.RuleID(raw, "change workflow reference id")
	if err != nil {
		return "", reject("proofkit.workflow.ref_id_limit_exceeded", "reference id is invalid")
	}
	return value, nil
}

func admitNullableRefID(raw any) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := admitRefID(raw)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func admitDigest(raw any) (string, error) {
	value, err := admit.SHA256Ref(raw, "change workflow subject digest")
	if err != nil {
		return "", reject("proofkit.workflow.subject_digest", "subject digest must be canonical lowercase sha256")
	}
	return value, nil
}

func admitDisplayPath(raw any) (string, error) {
	value, ok := raw.(string)
	if !ok || len(value) > maxPathBytes || !utf8.ValidString(value) || admit.ContainsSecretLikeValue(value) {
		return "", reject("proofkit.workflow.artifact_path", "artifact path is invalid")
	}
	for _, character := range value {
		if unicodepolicy.IsUnsafeScalar(character) {
			return "", reject("proofkit.workflow.artifact_path", "artifact path contains a display-unsafe scalar")
		}
	}
	pathValue, err := admit.SafeRepoRelativePath(value, "change workflow artifact path")
	if err != nil {
		return "", reject("proofkit.workflow.artifact_path", "artifact path must be a canonical repository-relative POSIX path")
	}
	return pathValue, nil
}

func validateGlobalReferences(input admittedInput) error {
	byID := make(map[string]contextRef, len(input.ContextRefs))
	for _, ref := range input.ContextRefs {
		byID[ref.RefID] = ref
	}
	for _, ref := range input.ContextRefs {
		for _, dependencyID := range ref.DependencyRefIDs {
			if _, ok := byID[dependencyID]; !ok {
				return reject("proofkit.workflow.context_dependency_missing", "a context dependency does not resolve")
			}
		}
	}
	for _, requiredID := range input.RequiredContextRefIDs {
		if _, ok := byID[requiredID]; !ok {
			return reject("proofkit.workflow.required_context_missing", "a required context ref does not resolve")
		}
	}
	if input.GoverningAuthorityRefID != nil {
		ref, ok := byID[*input.GoverningAuthorityRefID]
		if !ok || ref.RefKind != "authority" {
			return reject("proofkit.workflow.governing_authority", "governingAuthorityRefId must resolve an authority ref")
		}
	}
	if input.Checkpoint == nil || input.Checkpoint.State == "not_started" {
		return nil
	}
	subject, ok := byID[input.Checkpoint.SubjectRefID]
	if !ok || subject.RefKind != "artifact" || subject.SubjectDigest != input.Checkpoint.SubjectDigest {
		return reject("proofkit.workflow.subject_identity", "checkpoint subject must resolve an equal artifact digest")
	}
	for _, findingID := range input.Checkpoint.FindingRefs {
		finding, ok := byID[findingID]
		if !ok || finding.RefKind != "finding" {
			return reject("proofkit.workflow.finding_identity", "finding refs must resolve finding context refs")
		}
	}
	return nil
}

func knownKeys(record map[string]any, expected []string, ruleID string) error {
	if err := admit.KnownKeys(record, expected, "change workflow record"); err != nil {
		return reject(ruleID, "change workflow record has unsupported fields")
	}
	return nil
}

type ruleError struct {
	ruleID  string
	message string
}

func (err ruleError) Error() string { return err.ruleID + ": " + err.message }

func reject(ruleID string, message string) error {
	return ruleError{ruleID: ruleID, message: message}
}

// RuleID returns the stable failing rule without exposing rejected caller data.
func RuleID(err error) string {
	if typed, ok := err.(ruleError); ok {
		return typed.ruleID
	}
	return "proofkit.workflow.internal_error"
}

func cloneStrings(values []string) []string {
	return append([]string{}, values...)
}

func invalidState(message string) error {
	return fmt.Errorf("invalid admitted workflow state: %s", message)
}
