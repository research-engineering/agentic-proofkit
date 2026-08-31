// Package nativeevidenceguidance owns the repository-neutral evidence template.
package nativeevidenceguidance

import (
	"errors"
	"strings"
)

const (
	SchemaVersion = 1
	GuidanceID    = "proofkit.native-evidence-guidance.v1"

	SlotCount        = 22
	MaximumTextBytes = 16 * 1024
	MaximumTextLines = 48

	ApplicabilityAlways                = "always"
	ApplicabilityDeclaredInputChannels = "declared_input_channels"
	ApplicabilityEnvironmentOrNetwork  = "environment_or_network_access"
	ApplicabilityExternalProcess       = "external_process"
	ApplicabilityMutableArtifacts      = "mutable_artifacts"
)

var errInvalidGuidanceTable = errors.New("native evidence guidance table is invalid")

// Slot is one repository-owned decision required for executable native evidence.
type Slot struct {
	Order                    int    `json:"order"`
	SlotID                   string `json:"slotId"`
	ApplicabilityClass       string `json:"applicabilityClass"`
	Question                 string `json:"question"`
	RequiredConsumerDecision string `json:"requiredConsumerDecision"`
	CompletionCriterion      string `json:"completionCriterion"`
}

// Guidance is an immutable projection of the command-owned table.
type Guidance struct {
	SchemaVersion int      `json:"schemaVersion"`
	GuidanceID    string   `json:"guidanceId"`
	Slots         []Slot   `json:"slots"`
	NonClaims     []string `json:"nonClaims"`
}

// JSONValue returns a fresh stablejson-compatible projection.
func (guidance Guidance) JSONValue() map[string]any {
	slots := make([]any, 0, len(guidance.Slots))
	for _, slot := range guidance.Slots {
		slots = append(slots, map[string]any{
			"applicabilityClass":       slot.ApplicabilityClass,
			"completionCriterion":      slot.CompletionCriterion,
			"order":                    slot.Order,
			"question":                 slot.Question,
			"requiredConsumerDecision": slot.RequiredConsumerDecision,
			"slotId":                   slot.SlotID,
		})
	}
	nonClaims := make([]any, len(guidance.NonClaims))
	for index, value := range guidance.NonClaims {
		nonClaims[index] = value
	}
	return map[string]any{
		"guidanceId":    guidance.GuidanceID,
		"nonClaims":     nonClaims,
		"schemaVersion": guidance.SchemaVersion,
		"slots":         slots,
	}
}

// TextLine separates a command-owned label from its semantic plain-text value.
// Presentation adapters may style Label, but must preserve Value verbatim.
type TextLine struct {
	Label string
	Value string
}

// guidanceTable is the sole semantic owner of native-evidence guidance.
var guidanceTable = [...]Slot{
	{Order: 1, SlotID: "semantic_owner", ApplicabilityClass: ApplicabilityAlways, Question: "Who owns the invariant and its change authority?", RequiredConsumerDecision: "Select exactly one stable semantic owner and one change authority.", CompletionCriterion: "Both stable IDs are recorded and no second owner can independently change the same meaning."},
	{Order: 2, SlotID: "subject_identity_currentness", ApplicabilityClass: ApplicabilityAlways, Question: "Which exact subject is proved and when is it current?", RequiredConsumerDecision: "Select the subject identity, digest algorithm, and freshness rule.", CompletionCriterion: "The exact subject digest is bound and the freshness rule deterministically rejects a stale subject."},
	{Order: 3, SlotID: "execution_root_source_snapshot", ApplicabilityClass: ApplicabilityAlways, Question: "Which execution root and immutable source snapshot are admitted?", RequiredConsumerDecision: "Select one root and one immutable revision or complete source-digest set.", CompletionCriterion: "The witness binds the admitted root and revision or digests and rejects execution over a different snapshot."},
	{Order: 4, SlotID: "exact_argv", ApplicabilityClass: ApplicabilityExternalProcess, Question: "Which process invocation is admitted?", RequiredConsumerDecision: "Select one argv array without shell interpolation.", CompletionCriterion: "The executed argv equals the admitted array element-for-element and no shell parses it."},
	{Order: 5, SlotID: "stdin_input_bytes", ApplicabilityClass: ApplicabilityDeclaredInputChannels, Question: "Which stdin and input bytes are admitted?", RequiredConsumerDecision: "Select exact bytes or digests and byte bounds for every input channel.", CompletionCriterion: "The witness binds each input channel and rejects missing, substituted, or over-bound bytes."},
	{Order: 6, SlotID: "toolchain_environment", ApplicabilityClass: ApplicabilityAlways, Question: "Which toolchain and deterministic environment are fixed?", RequiredConsumerDecision: "Select exact tool versions, platform, locale, timezone, and dependency identities.", CompletionCriterion: "The witness records and validates every selected identity before execution."},
	{Order: 7, SlotID: "positive_control", ApplicabilityClass: ApplicabilityAlways, Question: "Which known-good subject proves the witness can succeed?", RequiredConsumerDecision: "Select one independently justified positive fixture and expected oracle result.", CompletionCriterion: "The fixture executes and produces the exact passing oracle result."},
	{Order: 8, SlotID: "near_miss_falsifier", ApplicabilityClass: ApplicabilityAlways, Question: "Which plausible wrong subject must fail?", RequiredConsumerDecision: "Select one independent near-miss mutation and expected failure rule.", CompletionCriterion: "The mutated subject executes and fails under the selected stable rule while the positive control still passes."},
	{Order: 9, SlotID: "oracle_rule", ApplicabilityClass: ApplicabilityAlways, Question: "Which executable oracle decides the outcome?", RequiredConsumerDecision: "Select one stable rule ID and deterministic observation mapping.", CompletionCriterion: "Every admitted observation maps to exactly one verdict and the near-miss activates the intended rule."},
	{Order: 10, SlotID: "input_work_bounds", ApplicabilityClass: ApplicabilityAlways, Question: "Which cardinality and work bounds prevent excess work?", RequiredConsumerDecision: "Select numeric bounds and the point at which they dominate semantic processing.", CompletionCriterion: "Boundary fixtures pass, one-over fixtures fail before expensive per-item work, and no partial output is written."},
	{Order: 11, SlotID: "environment_network_policy", ApplicabilityClass: ApplicabilityEnvironmentOrNetwork, Question: "Which environment variables and network accesses are allowed?", RequiredConsumerDecision: "Select explicit allow and deny inventories.", CompletionCriterion: "Allowed accesses are observed, one denied environment read and one denied network access fail under stable rules, and undeclared access is denied."},
	{Order: 12, SlotID: "resource_bounds", ApplicabilityClass: ApplicabilityExternalProcess, Question: "Which CPU, memory, disk, file-descriptor, and PID limits apply?", RequiredConsumerDecision: "Select numeric limits and cleanup obligations.", CompletionCriterion: "Boundary use succeeds, one-over use fails deterministically, and allocated resources are released."},
	{Order: 13, SlotID: "output_bounds", ApplicabilityClass: ApplicabilityAlways, Question: "Which stdout and stderr limits apply?", RequiredConsumerDecision: "Select exact byte caps and overflow behavior.", CompletionCriterion: "Boundary output succeeds and one-over output fails before any partial write."},
	{Order: 14, SlotID: "process_lifecycle", ApplicabilityClass: ApplicabilityExternalProcess, Question: "How are timeout and child processes contained?", RequiredConsumerDecision: "Select timeout, process-group termination, and detached-child policy.", CompletionCriterion: "Timeout terminates the process group, no detached child survives, and cleanup completion is observed before success."},
	{Order: 15, SlotID: "exit_mapping", ApplicabilityClass: ApplicabilityExternalProcess, Question: "How do native exit classes map to proof states?", RequiredConsumerDecision: "Select an exhaustive disjoint exit-class mapping.", CompletionCriterion: "Every native exit class maps to exactly one declared state and an unknown class fails closed."},
	{Order: 16, SlotID: "nondisclosure", ApplicabilityClass: ApplicabilityAlways, Question: "Which values must never reach visible sinks?", RequiredConsumerDecision: "Select the secret, control, and sentinel corpus and all report-visible sinks.", CompletionCriterion: "No corpus value or fragment appears in stdout, stderr, reports, receipts, logs, or generated records."},
	{Order: 17, SlotID: "cleanup_crash_inventory", ApplicabilityClass: ApplicabilityMutableArtifacts, Question: "Which outputs may remain after success, failure, or crash?", RequiredConsumerDecision: "Select exact terminal inventories plus rollback or recovery rules.", CompletionCriterion: "Each terminal mode leaves exactly its inventory and interrupted mutation is rolled back or recovered by the declared rule."},
	{Order: 18, SlotID: "receipt_identity", ApplicabilityClass: ApplicabilityAlways, Question: "Which identities must the receipt bind?", RequiredConsumerDecision: "Select command, argv, input, output, subject, and witness identities.", CompletionCriterion: "The receipt binds every selected identity by digest and any one-field substitution is rejected."},
	{Order: 19, SlotID: "currentness_trust", ApplicabilityClass: ApplicabilityAlways, Question: "Which currentness and trust class is admitted?", RequiredConsumerDecision: "Select a closed class and its evidence predicates.", CompletionCriterion: "The class is owner-admitted from evidence, stale or weaker evidence is rejected, and the witness does not escalate the class."},
	{Order: 20, SlotID: "escalation", ApplicabilityClass: ApplicabilityAlways, Question: "Which unknowns block and who resolves them?", RequiredConsumerDecision: "Select an owner, blocking condition, and required evidence for every unresolved state.", CompletionCriterion: "Each unresolved state blocks the pass path and names exactly one owner, condition, and evidence requirement."},
	{Order: 21, SlotID: "retirement", ApplicabilityClass: ApplicabilityAlways, Question: "When may this witness be replaced or removed?", RequiredConsumerDecision: "Select replacement identity, parity predicates, owner approval, and retirement gate.", CompletionCriterion: "Replacement parity passes on the exact subject, the owner approval is bound, and the retirement gate rejects premature removal."},
	{Order: 22, SlotID: "non_claims", ApplicabilityClass: ApplicabilityAlways, Question: "Which conclusions remain explicitly denied?", RequiredConsumerDecision: "Select the denied authority, scope, and readiness claims.", CompletionCriterion: "The exact non-claims remain in the report contract and no positive report language implies a denied claim."},
}

var guidanceNonClaims = [...]string{
	"The template does not generate, execute, approve, authenticate, or prove adequacy of a consuming repository's script, witness, oracle, receipt, policy, or cleanup implementation.",
}

// Build returns a fresh immutable-value projection of the fixed template.
func Build() (Guidance, error) {
	if err := validateGuidanceTable(); err != nil {
		return Guidance{}, err
	}
	return Guidance{
		SchemaVersion: SchemaVersion,
		GuidanceID:    GuidanceID,
		Slots:         append([]Slot(nil), guidanceTable[:]...),
		NonClaims:     append([]string(nil), guidanceNonClaims[:]...),
	}, nil
}

// RenderPlainText renders the fixed guidance in at most two lines per slot.
func RenderPlainText() (string, error) {
	lines, err := TextProjection()
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	for _, line := range lines {
		builder.WriteString(line.Label)
		builder.WriteString(": ")
		builder.WriteString(line.Value)
		builder.WriteByte('\n')
	}
	text := builder.String()
	if len(text) > MaximumTextBytes || strings.Count(text, "\n") > MaximumTextLines {
		return "", errInvalidGuidanceTable
	}
	return text, nil
}

// TextProjection returns a fresh structured projection for human rendering.
func TextProjection() ([]TextLine, error) {
	guidance, err := Build()
	if err != nil {
		return nil, err
	}
	lines := make([]TextLine, 0, len(guidance.Slots)*2+1)
	for _, slot := range guidance.Slots {
		lines = append(lines,
			TextLine{Label: slot.SlotID, Value: "applicability: " + slot.ApplicabilityClass + "; decision: " + slot.RequiredConsumerDecision},
			TextLine{Label: "completion", Value: slot.CompletionCriterion},
		)
	}
	lines = append(lines, TextLine{Label: "non-claim", Value: guidance.NonClaims[0]})
	return lines, nil
}

func validateGuidanceTable() error {
	if len(guidanceTable) != SlotCount || len(guidanceNonClaims) != 1 || guidanceNonClaims[0] == "" {
		return errInvalidGuidanceTable
	}
	seen := make(map[string]struct{}, len(guidanceTable))
	for index, slot := range guidanceTable {
		if slot.Order != index+1 || slot.SlotID == "" || !validApplicabilityClass(slot.ApplicabilityClass) || slot.Question == "" || slot.RequiredConsumerDecision == "" || slot.CompletionCriterion == "" {
			return errInvalidGuidanceTable
		}
		if _, duplicate := seen[slot.SlotID]; duplicate {
			return errInvalidGuidanceTable
		}
		seen[slot.SlotID] = struct{}{}
	}
	return nil
}

func validApplicabilityClass(value string) bool {
	switch value {
	case ApplicabilityAlways, ApplicabilityDeclaredInputChannels, ApplicabilityEnvironmentOrNetwork, ApplicabilityExternalProcess, ApplicabilityMutableArtifacts:
		return true
	default:
		return false
	}
}
