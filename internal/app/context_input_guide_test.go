package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestContextInputGuideIsLazyAndCarrierBound(t *testing.T) {
	_, help := receiptHelpTemplate(t, "requirement-context-compose")
	if len(help) > 10<<10 {
		t.Fatal("context guide exceeds its bounded help surface")
	}
	for _, carrier := range []struct{ profile, python string }{
		{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""}, {cliexec.ProfilePythonModule, "/example/python 3"},
	} {
		renderer, err := cliexec.AdmitLauncherProfile(carrier.profile, carrier.python)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, _ := commandDescriptorFor("requirement-context-compose")
		want := [][]string{
			{"requirement-spec-tree", "--input", "<packet>", "--input-pointer", "/tree"},
			{"requirement-context-compose", "--input", "<packet>", "--input-pointer", "/catalog", "--repo-root", "<root>"},
		}
		if got := guideCommands(t, commandUsageWithRenderer(descriptor, renderer), "Requirement context input guide:", renderer); !reflect.DeepEqual(got, want) {
			t.Fatalf("context guide commands differ: %v", got)
		}
	}
	for _, args := range [][]string{{"help"}, {"help", "families"}, {"native-evidence-guidance"}, {"changed-path-set", "--help"}, {"requirement-spec-tree", "--help"}} {
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if code != 0 || diagnostic != "" || strings.Contains(output, "Requirement context input guide:") {
			t.Fatal("context guide is not demand-loaded")
		}
	}
}

func TestContextGuideComposesActualChildInputs(t *testing.T) {
	packet, help := receiptHelpTemplate(t, "requirement-context-compose")
	root := t.TempDir()
	materialize := adoptionHelpPacket(t, root, "fresh")
	source := materialize["requirementSources"].([]any)[0].(map[string]any)
	admittedSource, err := requirementsourceadmission.Evaluate(source)
	if err != nil || admittedSource.ExitCode != 0 {
		t.Fatalf("source premise: %v", err)
	}
	sourcePath := admittedSource.Source.RequirementsPath()
	binding := materialize["requirementProofBinding"].(map[string]any)
	bindingRecord := binding["record"].(map[string]any)
	writeCLIJSONFixture(t, root, sourcePath, source)
	writeCLIJSONFixture(t, root, binding["path"].(string), binding["record"])
	catalog := packet["catalog"].(map[string]any)
	treePath := catalog["specTree"].(map[string]any)["path"].(string)
	commands := guideCommands(t, help, "Requirement context input guide:", cliexec.PathRenderer())
	operands := map[string]string{"<packet>": "-", "<root>": root}
	admitted := runAdoptionHelpCLI(t, adoptionHelpJSON(t, packet), fillGuideOperands(t, commands[0], operands)...)
	if admitted["state"] != "passed" {
		t.Fatal("tree example did not pass its owner")
	}
	writeCLIJSONFixture(t, root, treePath, packet["tree"])
	args := fillGuideOperands(t, commands[1], operands)
	composed := runAdoptionHelpCLI(t, adoptionHelpJSON(t, packet), args...)
	if _, err := requirementcontext.AdmitSnapshot(composed); err != nil {
		t.Fatal(err)
	}
	if composed["expectedDigestCoverage"] != "none" || composed["state"] != nil {
		t.Fatal("context identity or expected-digest boundary differs")
	}
	projections := composed["projections"].(map[string]any)
	canonicalSource, err := requirementsourceadmission.SourceValue(admittedSource.Source)
	if err != nil {
		t.Fatal(err)
	}
	if !equalCLIJSON(t, projections["requirementSources"].([]any)[0], canonicalSource) || !equalCLIJSON(t, projections["specTree"], packet["tree"]) {
		t.Fatal("composition lost source or tree input semantics")
	}
	if !equalCLIJSON(t, projections["proofBinding"], bindingRecord) {
		t.Fatal("composition lost the requested binding input")
	}
	bindingBytes, err := os.ReadFile(filepath.Join(root, binding["path"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	wantBindingSource := map[string]any{
		"kind": "proof_binding", "path": binding["path"], "sourceRef": "proof_binding:example.bindings",
		"currentDigest": fmt.Sprintf("sha256:%x", sha256.Sum256(bindingBytes)),
	}
	bindingSources := []any{}
	for _, raw := range composed["sources"].([]any) {
		if raw.(map[string]any)["kind"] == "proof_binding" {
			bindingSources = append(bindingSources, raw)
		}
	}
	if !equalCLIJSON(t, bindingSources, []any{wantBindingSource}) {
		t.Fatal("binding provenance does not match actual file bytes")
	}
	sourceEntry := catalog["requirementSources"].([]any)[0].(map[string]any)
	sourceBytes, err := os.ReadFile(filepath.Join(root, sourceEntry["path"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	sourceEntry["expectedSourceDigest"] = fmt.Sprintf("sha256:%x", sha256.Sum256(sourceBytes))
	if result := runAdoptionHelpCLI(t, adoptionHelpJSON(t, packet), args...); result["expectedDigestCoverage"] != "partial" {
		t.Fatal("actual expected bytes were not admitted")
	}
	for _, mutation := range []string{"node", "source", "digest", "report-instead-of-tree", "wrapper-instead-of-catalog"} {
		t.Run(mutation, func(t *testing.T) {
			changed := decodeCLIJSON(t, string(adoptionHelpJSON(t, packet))).(map[string]any)
			entry := changed["catalog"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)
			callArgs := append([]string{}, args...)
			wantDiagnostic := ""
			switch mutation {
			case "node":
				entry["nodeId"] = "example.other"
				wantDiagnostic = "source node does not match the specification tree"
			case "source":
				wrong := decodeCLIJSON(t, string(adoptionHelpJSON(t, source))).(map[string]any)
				wrong["sourceId"] = "example.other"
				writeCLIJSONFixture(t, root, sourcePath, wrong)
				delete(entry, "expectedSourceDigest")
				if report := runAdoptionHelpCLI(t, adoptionHelpJSON(t, wrong), "requirement-source-admission", "--input", "-"); report["state"] != "passed" {
					t.Fatal("source counterexample is not independently owner-valid")
				}
				wantDiagnostic = "source is not referenced by the specification tree"
				t.Cleanup(func() { writeCLIJSONFixture(t, root, sourcePath, source) })
			case "digest":
				entry["expectedSourceDigest"] = "sha256:" + strings.Repeat("0", 64)
				wantDiagnostic = "expected digest mismatch"
			case "report-instead-of-tree":
				writeCLIJSONFixture(t, root, treePath, admitted)
				wantDiagnostic = "admit specification tree"
				t.Cleanup(func() { writeCLIJSONFixture(t, root, treePath, packet["tree"]) })
			case "wrapper-instead-of-catalog":
				callArgs = []string{"requirement-context-compose", "--input", "-", "--repo-root", root}
				wantDiagnostic = "requirement context catalog"
			}
			code, output, diagnostic := executeAgentWorkflowCLI(t, callArgs, bytes.NewReader(adoptionHelpJSON(t, changed)), PresentationCapabilities{})
			if code != 1 || output != "" || !strings.Contains(diagnostic, wantDiagnostic) {
				t.Fatalf("invalid %s accepted: %d %q %q", mutation, code, output, diagnostic)
			}
		})
	}
	t.Run("known-node-wrong-relation", func(t *testing.T) {
		changed := decodeCLIJSON(t, string(adoptionHelpJSON(t, packet))).(map[string]any)
		tree := changed["tree"].(map[string]any)
		tree["nodes"] = append(tree["nodes"].([]any), map[string]any{
			"nodeId": "example.other", "nodeKind": "module_spec", "label": "Other scope",
			"displayOrder": json.Number("2"), "callerAnnotations": []any{},
			"sourceRefs": []any{map[string]any{
				"sourceRefId": "example.other.overview", "sourceRefKind": "source_id",
				"sourceRole": "overview", "sourceId": "example.requirements",
			}},
		})
		tree["edges"] = []any{map[string]any{"parentNodeId": "example.root", "childNodeId": "example.other"}}
		if report := runAdoptionHelpCLI(t, adoptionHelpJSON(t, tree), "requirement-spec-tree", "--input", "-"); report["state"] != "passed" {
			t.Fatal("relation counterexample tree must be owner-valid")
		}
		writeCLIJSONFixture(t, root, treePath, tree)
		runAdoptionHelpCLI(t, adoptionHelpJSON(t, changed), args...)
		changed["catalog"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["nodeId"] = "example.other"
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, bytes.NewReader(adoptionHelpJSON(t, changed)), PresentationCapabilities{})
		if code != 1 || output != "" || !strings.Contains(diagnostic, "source node does not match the specification tree") {
			t.Fatalf("known-but-unrelated node accepted: %d %q %q", code, output, diagnostic)
		}
	})
	t.Run("optional-binding-absent", func(t *testing.T) {
		changed := decodeCLIJSON(t, string(adoptionHelpJSON(t, packet))).(map[string]any)
		delete(changed["catalog"].(map[string]any), "proofBinding")
		value := runAdoptionHelpCLI(t, adoptionHelpJSON(t, changed), args...)
		if _, present := value["projections"].(map[string]any)["proofBinding"]; present {
			t.Fatal("absent optional binding became a fabricated projection")
		}
	})
}
