package commandoracle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
)

const (
	CounterfeitCorpusPath = "internal/tools/commandoracle/testdata/counterfeit-corpus.v1.json"
	maxCorpusBytes        = 1 << 20
)

type counterfeitCorpus struct {
	CorpusID      string            `json:"corpusId"`
	SchemaVersion int               `json:"schemaVersion"`
	Cases         []counterfeitCase `json:"cases"`
}

type counterfeitCase struct {
	CaseID           string `json:"caseId"`
	Coordinate       string `json:"coordinate"`
	EvidenceClass    string `json:"evidenceClass"`
	ExpectedDecision string `json:"expectedDecision"`
	MutationID       string `json:"mutationId"`
	PolicyID         string `json:"policyId"`
}

type counterfeitAxis struct {
	MutationID    string
	EvidenceClass string
}

var requiredCounterfeitAxes = []counterfeitAxis{
	{MutationID: "event-attribute-cross-test", EvidenceClass: "execution"},
	{MutationID: "event-attribute-duplicate", EvidenceClass: "execution"},
	{MutationID: "event-attribute-missing", EvidenceClass: "execution"},
	{MutationID: "event-descendant-skip", EvidenceClass: "execution"},
	{MutationID: "event-output-spoof", EvidenceClass: "execution"},
	{MutationID: "event-package-pass-before-tests", EvidenceClass: "execution"},
	{MutationID: "event-package-pass-missing", EvidenceClass: "execution"},
	{MutationID: "event-pass-before-run", EvidenceClass: "execution"},
	{MutationID: "event-pass-duplicate", EvidenceClass: "execution"},
	{MutationID: "event-pause-before-run", EvidenceClass: "execution"},
	{MutationID: "event-pause-duplicate", EvidenceClass: "execution"},
	{MutationID: "event-run-duplicate", EvidenceClass: "execution"},
	{MutationID: "event-selected-fail", EvidenceClass: "execution"},
	{MutationID: "event-selected-skip", EvidenceClass: "execution"},
	{MutationID: "event-unknown-action", EvidenceClass: "execution"},
	{MutationID: "join-correlated-command-identity", EvidenceClass: "joined"},
	{MutationID: "join-correlated-outcome-marker", EvidenceClass: "joined"},
	{MutationID: "join-correlated-selector-test", EvidenceClass: "joined"},
	{MutationID: "positive-candidate", EvidenceClass: "candidate"},
	{MutationID: "positive-execution-shared-test", EvidenceClass: "execution"},
	{MutationID: "positive-joined", EvidenceClass: "joined"},
	{MutationID: "record-execution-command-drift", EvidenceClass: "joined"},
	{MutationID: "source-correlated-identity", EvidenceClass: "joined"},
}

func ValidateCounterfeitCorpus(root string) (string, error) {
	content, err := artifactfile.ReadBounded(root, CounterfeitCorpusPath, maxCorpusBytes)
	if err != nil {
		return "", decision("corpus.file_missing")
	}
	if len(content) == 0 {
		return "", decision("corpus.resource_limit")
	}
	corpus, err := admitCorpus(content)
	if err != nil {
		return "", err
	}
	if err := validateCounterfeitCorpusClosure(corpus); err != nil {
		return "", err
	}
	positiveClasses := map[string]bool{"candidate": false, "execution": false, "joined": false}
	for _, item := range corpus.Cases {
		decisionID := evaluateCounterfeit(item)
		if decisionID != item.ExpectedDecision {
			return "", decision("corpus.expected_decision_mismatch")
		}
		if item.ExpectedDecision == "admit" {
			positiveClasses[item.EvidenceClass] = true
		}
	}
	for _, evidenceClass := range []string{"candidate", "execution", "joined"} {
		if !positiveClasses[evidenceClass] {
			return "", decision("corpus.positive_control_missing")
		}
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func admitCorpus(content []byte) (counterfeitCorpus, error) {
	raw, err := admission.DecodeJSON(bytes.NewReader(content), maxCorpusBytes)
	if err != nil {
		return counterfeitCorpus{}, decision("corpus.json_invalid")
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return counterfeitCorpus{}, decision("corpus.object_required")
	}
	if err := admit.KnownKeys(record, []string{"cases", "corpusId", "schemaVersion"}, "command oracle counterfeit corpus"); err != nil {
		return counterfeitCorpus{}, decision("corpus.unknown_field")
	}
	caseValues, ok := record["cases"].([]any)
	if !ok || len(caseValues) == 0 {
		return counterfeitCorpus{}, decision("corpus.cases_invalid")
	}
	for _, value := range caseValues {
		item, ok := value.(map[string]any)
		if !ok {
			return counterfeitCorpus{}, decision("corpus.case_object_required")
		}
		if err := admit.KnownKeys(item, []string{"caseId", "coordinate", "evidenceClass", "expectedDecision", "mutationId", "policyId"}, "command oracle counterfeit case"); err != nil {
			return counterfeitCorpus{}, decision("corpus.case_unknown_field")
		}
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return counterfeitCorpus{}, err
	}
	var corpus counterfeitCorpus
	if err := json.Unmarshal(encoded, &corpus); err != nil {
		return counterfeitCorpus{}, decision("corpus.case_type_invalid")
	}
	if corpus.SchemaVersion != 1 || corpus.CorpusID != "proofkit.command-oracle.counterfeit-corpus.v1" {
		return counterfeitCorpus{}, decision("corpus.identity_invalid")
	}
	for index, item := range corpus.Cases {
		if strings.TrimSpace(item.CaseID) == "" || strings.TrimSpace(item.EvidenceClass) == "" || strings.TrimSpace(item.ExpectedDecision) == "" || strings.TrimSpace(item.MutationID) == "" || strings.TrimSpace(item.PolicyID) == "" {
			return counterfeitCorpus{}, decision("corpus.case_field_empty")
		}
		if index > 0 && corpus.Cases[index-1].CaseID >= item.CaseID {
			return counterfeitCorpus{}, decision("corpus.case_order_invalid")
		}
	}
	return corpus, nil
}

func validateCounterfeitCorpusClosure(corpus counterfeitCorpus) error {
	allowedClasses := map[string]struct{}{"candidate": {}, "execution": {}, "joined": {}}
	requiredAxes := make(map[string]string, len(requiredCounterfeitAxes))
	for _, axis := range requiredCounterfeitAxes {
		requiredAxes[axis.MutationID] = axis.EvidenceClass
	}
	requiredCoordinates := map[string]struct{}{}
	for _, coordinate := range schemaCoordinates(reflect.TypeOf(Record{}), "record") {
		requiredCoordinates[coordinate] = struct{}{}
	}
	seenMutations := map[string]struct{}{}
	seenPolicies := map[string]struct{}{}
	for _, item := range corpus.Cases {
		if _, ok := allowedClasses[item.EvidenceClass]; !ok {
			return decision("corpus.evidence_class_invalid")
		}
		if _, duplicate := seenMutations[item.MutationID]; duplicate {
			return decision("corpus.mutation_duplicate")
		}
		if _, duplicate := seenPolicies[item.PolicyID]; duplicate {
			return decision("corpus.policy_duplicate")
		}
		seenMutations[item.MutationID] = struct{}{}
		seenPolicies[item.PolicyID] = struct{}{}
		if strings.HasPrefix(item.MutationID, "record-coordinate:") {
			coordinate := strings.TrimPrefix(item.MutationID, "record-coordinate:")
			if item.Coordinate != coordinate || item.EvidenceClass != "joined" {
				return decision("corpus.coordinate_identity_invalid")
			}
			if _, required := requiredCoordinates[coordinate]; !required {
				return decision("corpus.coordinate_unknown")
			}
			delete(requiredCoordinates, coordinate)
			continue
		}
		evidenceClass, required := requiredAxes[item.MutationID]
		if !required || item.Coordinate != "" || item.EvidenceClass != evidenceClass {
			return decision("corpus.policy_axis_invalid")
		}
		delete(requiredAxes, item.MutationID)
	}
	if len(requiredAxes) != 0 {
		return decision("corpus.policy_axis_missing")
	}
	if len(requiredCoordinates) != 0 {
		return decision("corpus.coordinate_missing")
	}
	return nil
}
