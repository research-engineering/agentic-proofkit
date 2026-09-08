package workflowsmoke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementauthoringplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

// The installed help is the fixture producer; native owners validate its actual
// operands. The runner keeps launcher execution outside this proof owner.
func verifyAdoptionInputGuides(ctx context.Context, run Runner) (returnErr error) {
	root, err := os.MkdirTemp("", "proofkit-input-guide-")
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, os.RemoveAll(root)) }()
	help, err := invoke(ctx, run, "materialization input guide", unreadInvocation("adopt", "materialize", "plan", "--help"))
	if err != nil {
		return err
	}
	packet, prefix, err := installedGuideTemplate(help.Stdout, "adopt materialize plan")
	if err != nil {
		return err
	}
	if packet["sourcePlan"] != nil {
		return fmt.Errorf("installed guide must not fabricate a source plan")
	}
	planArgs := []string{"adopt", "plan", "--repo-root", "<root>", "--mode", "<intent>", "--format", "json"}
	if !hasGuideCommand(help.Stdout, prefix, planArgs) {
		return fmt.Errorf("installed guide lost its exact source-plan command")
	}
	planArgs[3], planArgs[5] = root, "fresh"
	sourcePlan, err := invoke(ctx, run, "guide source plan", unreadInvocation(planArgs...))
	if err != nil {
		return err
	}
	packet["sourcePlan"], err = admission.DecodeJSON(bytes.NewReader(sourcePlan.Stdout), defaultMaximumStdoutBytes)
	if err != nil {
		return err
	}
	input, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	for _, child := range []struct{ command, pointer, kind string }{
		{"requirement-source-admission", "/requirementSources/0", "proofkit.requirement-source-admission"},
		{"requirement-bindings", "/requirementProofBinding/record", "proofkit.requirement-proof-bindings"},
		{"test-evidence-inventory", "/testEvidenceInventory/record", "proofkit.test-evidence-inventory"},
	} {
		args := []string{child.command, "--input", "<packet>", "--input-pointer", child.pointer}
		if !hasGuideCommand(help.Stdout, prefix, args) {
			return fmt.Errorf("installed guide lost a child command or pointer")
		}
		args[2] = "-"
		result, err := invoke(ctx, run, "guide child input", bytesInvocation(input, args...))
		if err != nil {
			return err
		}
		value, err := admission.DecodeJSON(bytes.NewReader(result.Stdout), defaultMaximumStdoutBytes)
		if err != nil {
			return err
		}
		report, ok := value.(map[string]any)
		if !ok || report["reportKind"] != child.kind || report["state"] != "passed" {
			return fmt.Errorf("installed guide child must return its own passing report")
		}
	}
	expected, err := adoptionmaterialization.BuildPlan(ctx, packet, root)
	if err != nil {
		return fmt.Errorf("installed guide packet must pass native planning: %w", err)
	}
	if expected.JSONValue()["state"] != "ready" {
		return fmt.Errorf("installed guide packet must produce a ready native plan")
	}
	args := []string{"adopt", "materialize", "plan", "--input", "<packet>", "--repo-root", "<root>"}
	if !hasGuideCommand(help.Stdout, prefix, args) {
		return fmt.Errorf("installed guide lost the materialization plan command")
	}
	args[4], args[6] = "-", root
	result, err := invoke(ctx, run, "guide materialization plan", bytesInvocation(input, args...))
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(result, expected.JSONValue(), "guide materialization plan"); err != nil {
		return err
	}
	return verifyAuthoringInputGuide(ctx, run, packet, prefix)
}

func verifyAuthoringInputGuide(ctx context.Context, run Runner, materialization map[string]any, prefix string) error {
	help, err := invoke(ctx, run, "authoring input guide", unreadInvocation("requirement-authoring-plan", "--help"))
	if err != nil {
		return err
	}
	packet, authoringPrefix, err := installedGuideTemplate(help.Stdout, "requirement-authoring-plan")
	if err != nil {
		return err
	}
	args := []string{"requirement-authoring-plan", "--input", "<packet>"}
	if authoringPrefix != prefix || !hasGuideCommand(help.Stdout, prefix, args) || packet["mode"] != "retrospective_baseline" {
		return fmt.Errorf("installed authoring guide lost its carrier, mode or command")
	}
	sources, ok := materialization["requirementSources"].([]any)
	if !ok || len(sources) != 1 {
		return fmt.Errorf("installed connected template must have one source")
	}
	source, ok := sources[0].(map[string]any)
	if !ok {
		return fmt.Errorf("installed connected template source must be an object")
	}
	requirements, ok := source["requirements"].([]any)
	if !ok || len(requirements) != 1 {
		return fmt.Errorf("installed connected template must have one requirement")
	}
	updates, ok := packet["candidateUpdates"].([]any)
	if !ok || len(updates) != 1 {
		return fmt.Errorf("installed authoring template must have one candidate update")
	}
	update, ok := updates[0].(map[string]any)
	if !ok || packet["currentRequirementSource"] != nil || update["candidateRequirement"] != nil {
		return fmt.Errorf("installed authoring template must declare its two object operands")
	}
	emptySource := make(map[string]any, len(source))
	for key, value := range source {
		emptySource[key] = value
	}
	emptySource["requirements"] = []any{}
	packet["currentRequirementSource"], update["candidateRequirement"] = emptySource, requirements[0]
	expected, exitCode, err := requirementauthoringplan.Build(packet)
	if err != nil {
		return fmt.Errorf("installed authoring template must pass native admission: %w", err)
	}
	preview, ok := expected["nonAuthoritativeAdmissionPreview"].(map[string]any)
	if exitCode != 0 || !ok || preview["candidateOnly"] != true || preview["ownerReviewRequired"] != true {
		return fmt.Errorf("installed authoring template must preserve its source without granting approval")
	}
	previewBytes, err := json.Marshal(preview["requirementSourcePreview"])
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(Result{Stdout: previewBytes}, source, "guide authoring source preservation"); err != nil {
		return err
	}
	input, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	args[2] = "-"
	result, err := invoke(ctx, run, "guide authoring input", bytesInvocation(input, args...))
	if err != nil {
		return err
	}
	return verifyExactJSONObject(result, expected, "guide authoring input")
}

func installedGuideTemplate(help []byte, route string) (map[string]any, string, error) {
	_, invocation, ok := strings.Cut(string(help), "\nInstalled invocation:\n  ")
	line, _, _ := strings.Cut(invocation, "\n")
	index := strings.LastIndex(line, " "+route)
	if !ok || index <= 0 {
		return nil, "", fmt.Errorf("installed guide must identify its carrier")
	}
	sections := bytes.Split(help, []byte("```json\n"))
	if len(sections) != 2 {
		return nil, "", fmt.Errorf("installed guide must contain one connected JSON template")
	}
	input, _, closed := bytes.Cut(sections[1], []byte("\n```"))
	if !closed {
		return nil, "", fmt.Errorf("installed guide template must have a closing fence")
	}
	value, err := admission.DecodeJSON(bytes.NewReader(input), defaultMaximumStdoutBytes)
	if err != nil {
		return nil, "", err
	}
	packet, ok := value.(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("installed guide template must be an object")
	}
	return packet, line[:index], nil
}

func hasGuideCommand(help []byte, prefix string, args []string) bool {
	return bytes.Count(help, []byte("\n  "+prefix+" "+strings.Join(args, " ")+"\n")) == 1
}
