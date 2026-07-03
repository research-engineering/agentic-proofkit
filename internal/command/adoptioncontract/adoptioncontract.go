package adoptioncontract

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionworkflow"
	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/pilotadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/contractenv"
)

var modes = map[string]struct{}{
	"adoption":  {},
	"bootstrap": {},
	"guidance":  {},
	"pilot":     {},
	"workflow":  {},
}

var pilotVariants = map[string]struct{}{
	"all":           {},
	"first":         {},
	"stack-diverse": {},
}

type Options struct {
	AgentEnvelope           bool
	MaterializationManifest bool
	Mode                    string
	Pilot                   string
	Guidance                gradualadoption.GuidanceOptions
}

type aggregateEnvelope struct {
	EnvelopeID string
	Gradual    map[string]any
	NonClaims  []string
	Pilot      map[string]any
	Workflow   map[string]any
}

func Build(raw any, options Options) (any, int, error) {
	if err := validateOptions(options); err != nil {
		return nil, 1, err
	}
	envelope, err := admitAggregate(raw)
	if err != nil {
		return nil, 1, err
	}
	_ = envelope.EnvelopeID
	_ = envelope.NonClaims

	switch options.Mode {
	case "workflow":
		if options.AgentEnvelope {
			return adoptionworkflow.BuildEnvelopeFromContractEnvelope(workflowEnvelope(envelope))
		}
		return adoptionworkflow.BuildFromContractEnvelope(workflowEnvelope(envelope))
	case "adoption":
		return gradualadoption.BuildFromContractEnvelope(adoptionEnvelope(envelope))
	case "bootstrap":
		if options.AgentEnvelope {
			return gradualadoption.BuildBootstrapEnvelopeFromContractEnvelope(bootstrapEnvelope(envelope))
		}
		if options.MaterializationManifest {
			return gradualadoption.BuildBootstrapMaterializationManifestFromContractEnvelope(bootstrapEnvelope(envelope))
		}
		return gradualadoption.BuildBootstrapFromContractEnvelope(bootstrapEnvelope(envelope))
	case "guidance":
		if options.AgentEnvelope {
			return gradualadoption.BuildGuidanceEnvelopeFromContractEnvelope(guidanceEnvelope(envelope), options.Guidance)
		}
		return gradualadoption.BuildGuidanceFromContractEnvelope(guidanceEnvelope(envelope), options.Guidance)
	case "pilot":
		return buildPilot(envelope, options.Pilot)
	default:
		return nil, 1, fmt.Errorf("adoption contract envelope mode must be adoption, bootstrap, guidance, pilot, or workflow")
	}
}

func admitAggregate(raw any) (aggregateEnvelope, error) {
	record, err := contractenv.Object(raw, "proofkit.adoption-contract-envelope.v1", "adoption contract envelope", "envelopeId", "gradual", "nonClaims", "pilot", "workflow")
	if err != nil {
		return aggregateEnvelope{}, err
	}
	envelopeID, err := admit.RuleID(record["envelopeId"], "adoption contract envelope envelopeId")
	if err != nil {
		return aggregateEnvelope{}, err
	}
	workflow, err := contractenv.ObjectField(record, "workflow", "adoption contract envelope")
	if err != nil {
		return aggregateEnvelope{}, err
	}
	if err := admitChildEnvelope(workflow, "proofkit.adoption-workflow.v1", []string{"schema", "workflow"}, "adoption contract workflow envelope"); err != nil {
		return aggregateEnvelope{}, err
	}
	gradual, err := contractenv.ObjectField(record, "gradual", "adoption contract envelope")
	if err != nil {
		return aggregateEnvelope{}, err
	}
	if err := admitChildEnvelope(gradual, "proofkit.gradual-adoption-profile.v1", []string{"bootstrap", "guidance", "input", "schema"}, "adoption contract gradual envelope"); err != nil {
		return aggregateEnvelope{}, err
	}
	pilot, err := contractenv.ObjectField(record, "pilot", "adoption contract envelope")
	if err != nil {
		return aggregateEnvelope{}, err
	}
	if err := admitChildEnvelope(pilot, "proofkit.pilot-admission.v1", []string{"input", "schema", "stackDiverseInput"}, "adoption contract pilot envelope"); err != nil {
		return aggregateEnvelope{}, err
	}
	nonClaims, err := admit.SortedTextArray(record["nonClaims"], "adoption contract envelope nonClaims", true)
	if err != nil {
		return aggregateEnvelope{}, err
	}
	return aggregateEnvelope{
		EnvelopeID: envelopeID,
		Gradual:    gradual,
		NonClaims:  nonClaims,
		Pilot:      pilot,
		Workflow:   workflow,
	}, nil
}

func admitChildEnvelope(record map[string]any, expectedSchema string, keys []string, context string) error {
	if err := admit.KnownKeys(record, keys, context); err != nil {
		return err
	}
	if record["schema"] != expectedSchema {
		return fmt.Errorf("%s schema drift", context)
	}
	for _, key := range keys {
		if key == "schema" {
			continue
		}
		if _, ok := record[key].(map[string]any); !ok {
			return fmt.Errorf("%s must declare object %s", context, key)
		}
	}
	return nil
}

func validateOptions(options Options) error {
	if _, ok := modes[options.Mode]; !ok {
		return fmt.Errorf("adoption contract envelope mode must be adoption, bootstrap, guidance, pilot, or workflow")
	}
	pilot := options.Pilot
	if pilot == "" {
		pilot = "first"
	}
	if _, ok := pilotVariants[pilot]; !ok {
		return fmt.Errorf("--pilot requires first, stack-diverse, or all")
	}
	if options.AgentEnvelope && options.Mode != "workflow" && options.Mode != "bootstrap" && options.Mode != "guidance" {
		return fmt.Errorf("--agent-envelope is valid only for workflow, bootstrap, or guidance modes")
	}
	if options.MaterializationManifest && options.Mode != "bootstrap" {
		return fmt.Errorf("--materialization-manifest is valid only for bootstrap mode")
	}
	if options.AgentEnvelope && options.MaterializationManifest {
		return fmt.Errorf("--agent-envelope and --materialization-manifest are mutually exclusive")
	}
	if options.Pilot != "" && options.Mode != "pilot" {
		return fmt.Errorf("--pilot is valid only for pilot mode")
	}
	if hasGuidanceOverride(options.Guidance) && options.Mode != "guidance" {
		return fmt.Errorf("--guidance-mode, --checked-scope, and --touched-rule-id are valid only for guidance mode")
	}
	return nil
}

func workflowEnvelope(envelope aggregateEnvelope) map[string]any {
	return map[string]any{
		"schema":   "proofkit.adoption-workflow.v1",
		"workflow": envelope.Workflow["workflow"],
	}
}

func adoptionEnvelope(envelope aggregateEnvelope) map[string]any {
	return map[string]any{
		"schema": "proofkit.gradual-adoption-profile.v1",
		"input":  envelope.Gradual["input"],
	}
}

func bootstrapEnvelope(envelope aggregateEnvelope) map[string]any {
	return map[string]any{
		"bootstrap": envelope.Gradual["bootstrap"],
		"guidance":  envelope.Gradual["guidance"],
		"input":     envelope.Gradual["input"],
		"schema":    "proofkit.gradual-adoption-profile.v1",
	}
}

func guidanceEnvelope(envelope aggregateEnvelope) map[string]any {
	return map[string]any{
		"guidance": envelope.Gradual["guidance"],
		"input":    envelope.Gradual["input"],
		"schema":   "proofkit.gradual-adoption-profile.v1",
	}
}

func pilotEnvelope(envelope aggregateEnvelope, field string) map[string]any {
	return map[string]any{
		"schema": "proofkit.pilot-admission.v1",
		field:    envelope.Pilot[field],
	}
}

func buildPilot(envelope aggregateEnvelope, variant string) (any, int, error) {
	if variant == "" {
		variant = "first"
	}
	if variant == "all" {
		first, firstExitCode, err := pilotadmission.BuildFromContractEnvelope(pilotEnvelope(envelope, "input"), "input", pilotadmission.Options{})
		if err != nil {
			return nil, 1, err
		}
		stackDiverse, stackDiverseExitCode, err := pilotadmission.BuildFromContractEnvelope(pilotEnvelope(envelope, "stackDiverseInput"), "stackDiverseInput", pilotadmission.Options{
			RequireStackDiverseReleaseCandidate: true,
		})
		if err != nil {
			return nil, 1, err
		}
		exitCode := 0
		if firstExitCode != 0 || stackDiverseExitCode != 0 {
			exitCode = 1
		}
		return []any{first.JSONValue(), stackDiverse.JSONValue()}, exitCode, nil
	}
	field := "input"
	options := pilotadmission.Options{}
	if variant == "stack-diverse" {
		field = "stackDiverseInput"
		options.RequireStackDiverseReleaseCandidate = true
	}
	record, exitCode, err := pilotadmission.BuildFromContractEnvelope(pilotEnvelope(envelope, field), field, options)
	if err != nil {
		return nil, 1, err
	}
	return record.JSONValue(), exitCode, nil
}

func hasGuidanceOverride(options gradualadoption.GuidanceOptions) bool {
	return options.CheckedScope != "" || options.GuidanceMode != "" || len(options.TouchedRuleIDs) > 0
}
