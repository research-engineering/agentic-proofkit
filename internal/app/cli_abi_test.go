package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIABIGoldenCorpus(t *testing.T) {
	specPath := filepath.Join(repoRoot(t), "docs/specs/proofkit-package-boundary/requirements.v1.json")
	specContent, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec fixture: %v", err)
	}
	cases := []struct {
		name             string
		args             []string
		stdin            string
		wantStatus       int
		wantStdoutJSON   bool
		wantStdout       string
		wantStdoutHas    []string
		wantStdoutNotHas []string
		wantStderr       string
		wantStderrHas    []string
	}{
		{
			name:          "unsupported command",
			args:          []string{"unknown-command"},
			wantStatus:    1,
			wantStderr:    "unsupported command: unknown-command\n",
			wantStdoutHas: []string{},
		},
		{
			name:          "help rejects input flags",
			args:          []string{"help", "--input", "-"},
			stdin:         `{}`,
			wantStatus:    1,
			wantStderr:    "help supports only --help or -h\n",
			wantStdoutHas: []string{},
		},
		{
			name:          "admission rejects duplicate keys without stdout",
			args:          []string{"self-check", "--input", "-"},
			stdin:         `{"token":1,"token":2}`,
			wantStatus:    1,
			wantStderrHas: []string{"duplicate object key"},
		},
		{
			name:           "self-check emits stable JSON report",
			args:           []string{"self-check", "--input", "-"},
			stdin:          `{"ok":true}`,
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdout: "{\n" +
				"  \"diagnostics\": [\n" +
				"    {\n" +
				"      \"key\": \"inputKind\",\n" +
				"      \"value\": \"object\"\n" +
				"    }\n" +
				"  ],\n" +
				"  \"nonClaims\": [\n" +
				"    \"Go self-check does not replace the full package gate.\",\n" +
				"    \"Go self-check does not execute native witnesses, read repository state, approve merge, or publish artifacts.\"\n" +
				"  ],\n" +
				"  \"reportId\": \"proofkit.go-runtime.self-check\",\n" +
				"  \"reportKind\": \"proofkit.go-runtime.self-check\",\n" +
				"  \"ruleResults\": [\n" +
				"    {\n" +
				"      \"diagnostics\": [],\n" +
				"      \"message\": \"Go bootstrap runtime parsed explicit JSON input and emitted a deterministic report.\",\n" +
				"      \"ruleId\": \"proofkit.go-runtime.self-check.explicit-input\",\n" +
				"      \"status\": \"passed\"\n" +
				"    }\n" +
				"  ],\n" +
				"  \"schemaVersion\": 1,\n" +
				"  \"state\": \"passed\",\n" +
				"  \"summary\": {\n" +
				"    \"inputKind\": \"object\"\n" +
				"  }\n" +
				"}\n",
		},
		{
			name:           "requirement source admission emits report JSON",
			args:           []string{"requirement-source-admission", "--input", "-"},
			stdin:          string(specContent),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"reportKind": "proofkit.requirement-source-admission"`,
				`"state": "passed"`,
			},
		},
		{
			name:           "requirement authoring plan emits candidate-only preview JSON",
			args:           []string{"requirement-authoring-plan", "--input", "-"},
			stdin:          cliRequirementAuthoringPlanInput(),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"planKind": "proofkit.requirement-authoring-plan"`,
				`"authority": "candidate_only"`,
				`"ownerReviewRequired": true`,
				`"state": "passed"`,
			},
		},
		{
			name:           "capability map code baseline emits candidate seeds JSON",
			args:           []string{"capability-map-admission", "--input", "-"},
			stdin:          cliCapabilityMapInput("code_baseline", true),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"reportKind": "proofkit.capability-map-admission"`,
				`"trustMode": "code_baseline"`,
				`"candidateRequirementSeeds"`,
				`"candidateProofBindingSeeds"`,
				`"state": "passed"`,
			},
		},
		{
			name:           "capability map baseline failed report keeps stdout JSON",
			args:           []string{"capability-map-admission", "--input", "-"},
			stdin:          cliCapabilityMapInput("code_baseline", false),
			wantStatus:     1,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"reportKind": "proofkit.capability-map-admission"`,
				`"state": "failed"`,
				`active scenario anchor in code_baseline mode`,
			},
		},
		{
			name:           "capability map audit mode emits owner action JSON",
			args:           []string{"capability-map-admission", "--input", "-"},
			stdin:          cliCapabilityMapInput("audit_from_code", false),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"trustMode": "audit_from_code"`,
				`"add_scenario_anchor"`,
				`"Treat code observations as untrusted hypotheses."`,
			},
		},
		{
			name:           "requirement spec tree emits passed report JSON",
			args:           []string{"requirement-spec-tree", "--input", "-"},
			stdin:          cliRequirementSpecTreeInput(),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"reportKind": "proofkit.requirement-spec-tree"`,
				`"state": "passed"`,
			},
		},
		{
			name:           "requirement spec tree failed report keeps stdout JSON",
			args:           []string{"requirement-spec-tree", "--input", "-"},
			stdin:          strings.Replace(cliRequirementSpecTreeInput(), `"edges":[{"parentNodeId":"meta","childNodeId":"module"}]`, `"edges":[{"parentNodeId":"meta","childNodeId":"module"},{"parentNodeId":"module","childNodeId":"meta"}]`, 1),
			wantStatus:     1,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"state": "failed"`,
				`"topology.root_has_parent:meta"`,
			},
		},
		{
			name:           "requirement spec tree input pointer selects nested payload",
			args:           []string{"requirement-spec-tree", "--input", "-", "--input-pointer", "/payload"},
			stdin:          `{"payload":` + cliRequirementSpecTreeInput() + `}`,
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"reportKind": "proofkit.requirement-spec-tree"`,
				`"state": "passed"`,
			},
		},
		{
			name:           "requirement spec tree view emits JSON projection",
			args:           []string{"requirement-spec-tree-view", "--input", "-"},
			stdin:          cliRequirementSpecTreeInput(),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"authority": "presentation_only"`,
				`"viewKind": "proofkit.requirement-spec-tree-view"`,
				`"nodeId": "module"`,
			},
		},
		{
			name:          "requirement spec tree view emits HTML with exports",
			args:          []string{"requirement-spec-tree-view", "--input", "-", "--format", "html"},
			stdin:         cliRequirementSpecTreeInput(),
			wantStatus:    0,
			wantStdoutHas: []string{"Requirement Spec Tree View", "Download Markdown", "data-proofkit-download", "Module spec"},
		},
		{
			name:           "requirement browser server plans spec tree view",
			args:           []string{"requirement-browser-server", "--input", "-", "--view", "spec-tree"},
			stdin:          cliRequirementSpecTreeInput(),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"planKind": "proofkit.requirement-browser-server-plan"`,
				`"renderedViewKind": "proofkit.requirement-spec-tree-view"`,
				`"view": "spec-tree"`,
			},
		},
		{
			name:           "json report CLI adapter source emits generated source bundle",
			args:           []string{"json-report-cli-adapter-source", "--language", "typescript"},
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"artifactKind": "proofkit.json-report-cli-adapter-source"`,
				`"language": "typescript"`,
				`"sourceSha256": "sha256:`,
				`"runProofkitJsonCommand"`,
			},
		},
		{
			name:          "json report CLI adapter source rejects input flags",
			args:          []string{"json-report-cli-adapter-source", "--input", "-"},
			stdin:         `{}`,
			wantStatus:    1,
			wantStderrHas: []string{"not valid for json-report-cli-adapter-source"},
		},
		{
			name:           "test evidence inventory emits passed report JSON",
			args:           []string{"test-evidence-inventory", "--input", "-"},
			stdin:          cliTestEvidenceInventory(),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"reportKind": "proofkit.test-evidence-inventory"`,
				`"state": "passed"`,
			},
		},
		{
			name:           "test evidence inventory emits normalized inventory JSON",
			args:           []string{"test-evidence-inventory", "--input", "-", "--normalized-inventory"},
			stdin:          cliTestEvidenceInventory(),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"normalizedKind": "proofkit.test-evidence-inventory.normalized"`,
				`"sourceAuthority": "caller_owned_inventory"`,
				`"inventory": {`,
				`"authority": "caller_owned_inventory"`,
				`"testId": "test.cli.semantic"`,
			},
		},
		{
			name:           "test evidence inventory emits proof-binding-derived normalized inventory JSON",
			args:           []string{"test-evidence-inventory", "--input", "-", "--projection", "proof-binding-derived", "--normalized-inventory"},
			stdin:          cliProofBindingDerivedInventoryInput(),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"normalizedKind": "proofkit.test-evidence-inventory.normalized"`,
				`"projectionKind": "proofkit.proof-binding-test-inventory"`,
				`"sourcePath": "internal/app/cli_falsification_test.go"`,
				`"testId": "test.proofkit.cli.req_proofkit_cli_001"`,
			},
		},
		{
			name:           "test evidence inventory emits discovery draft candidate JSON",
			args:           []string{"test-evidence-inventory", "--input", "-", "--projection", "discovery-draft"},
			stdin:          cliTestDiscoveryDraftInput(),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"reportKind": "proofkit.test-inventory-discovery-draft"`,
				`"authority": "caller_owned_test_discovery_candidate_inventory"`,
				`"candidateKind": "proofkit.test-inventory-discovery-draft.candidate-inventory"`,
				`"key": "candidateInventory"`,
				`"evidenceClass": "routing_smoke_nonclaim"`,
				`"candidate_only:test.cli.discovery.test_missing_auth"`,
			},
			wantStdoutNotHas: []string{
				`"evidenceClass": "semantic_falsifier"`,
			},
		},
		{
			name:           "test evidence inventory failed report keeps stdout JSON",
			args:           []string{"test-evidence-inventory", "--input", "-"},
			stdin:          cliTestEvidenceInventoryMissingAnchor(),
			wantStatus:     1,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"missing_semantic_anchor:test.cli.semantic"`,
				`"state": "failed"`,
			},
		},
		{
			name:           "test evidence inventory normalized mode fails closed",
			args:           []string{"test-evidence-inventory", "--input", "-", "--normalized-inventory"},
			stdin:          cliTestEvidenceInventoryMissingAnchor(),
			wantStatus:     1,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"reportKind": "proofkit.test-evidence-inventory"`,
				`"state": "failed"`,
			},
		},
		{
			name:           "requirement coverage view emits passed report JSON",
			args:           []string{"requirement-coverage-view", "--input", "-"},
			stdin:          cliCoverageInput(cliCoverageInventory()),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"viewKind": "proofkit.requirement-coverage-view"`,
				`"covered_by_semantic_falsifier"`,
				`"state": "passed"`,
			},
		},
		{
			name:           "requirement coverage input compose emits view input JSON",
			args:           []string{"requirement-coverage-input-compose", "--input", "-"},
			stdin:          cliCoverageInputComposeInput(),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"viewInputId": "proofkit.cli.coverage.compose.view"`,
				`"requirementProofBinding": null`,
				`"testEvidenceInventory": {`,
				`"proofkit.cli.coverage.command"`,
			},
		},
		{
			name:           "requirement impact input compose emits impact input JSON",
			args:           []string{"requirement-impact-input-compose", "--input", "-"},
			stdin:          cliImpactInputComposeInput(),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"changedRecordIds": [`,
				`"REQ-PROOFKIT-CLI-IMPACT-001"`,
				`"obligationCatalog": [`,
				`"proofkit.cli.impact::scenario"`,
			},
		},
		{
			name:           "workspace manifest facts emit registry and planning JSON",
			args:           []string{"workspace-manifest-facts", "--input", "-"},
			stdin:          cliWorkspaceManifestFactsInput(),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"reportKind": "proofkit.workspace-manifest-facts"`,
				`"knownPackageNames": [`,
				`"changedPackagePlanPackages": [`,
				`"workspaceDependencyEdges": [`,
			},
		},
		{
			name:           "requirement coverage view failed report keeps stdout JSON",
			args:           []string{"requirement-coverage-view", "--input", "-"},
			stdin:          cliCoverageInput("null"),
			wantStatus:     1,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"classificationId": "missing_semantic_test"`,
				`"missing_test_inventory:REQ-PROOFKIT-CLI-COVERAGE-001"`,
				`"state": "failed"`,
			},
		},
		{
			name:          "requirement coverage view emits HTML",
			args:          []string{"requirement-coverage-view", "--input", "-", "--format", "html"},
			stdin:         cliCoverageInput(cliCoverageInventory()),
			wantStatus:    0,
			wantStdoutHas: []string{"Requirement Coverage View", "Test evidence"},
		},
		{
			name:           "requirement coverage view emits agent envelope JSON",
			args:           []string{"requirement-coverage-view", "--input", "-", "--agent-envelope"},
			stdin:          cliCoverageInput(cliCoverageInventory()),
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"envelopeId": "proofkit.requirement-coverage-view.agent-envelope"`,
				`"stopReason": "caller_review_required"`,
			},
		},
		{
			name:           "input pointer selects nested payload",
			args:           []string{"requirement-source-admission", "--input", "-", "--input-pointer", "/payload"},
			stdin:          `{"payload":` + string(specContent) + `}`,
			wantStatus:     0,
			wantStdoutJSON: true,
			wantStdoutHas: []string{
				`"reportKind": "proofkit.requirement-source-admission"`,
				`"state": "passed"`,
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := Run(t.Context(), item.args, strings.NewReader(item.stdin), &stdout, &stderr)
			if status != item.wantStatus {
				t.Fatalf("status=%d want %d stdout=%s stderr=%s", status, item.wantStatus, stdout.String(), stderr.String())
			}
			if item.wantStderr != "" && stderr.String() != item.wantStderr {
				t.Fatalf("stderr=%q want %q", stderr.String(), item.wantStderr)
			}
			if item.wantStdout != "" && stdout.String() != item.wantStdout {
				t.Fatalf("stdout=%q want %q", stdout.String(), item.wantStdout)
			}
			for _, want := range item.wantStderrHas {
				if !strings.Contains(stderr.String(), want) {
					t.Fatalf("stderr %q does not contain %q", stderr.String(), want)
				}
			}
			for _, want := range item.wantStdoutHas {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("stdout does not contain %q:\n%s", want, stdout.String())
				}
			}
			for _, forbidden := range item.wantStdoutNotHas {
				if strings.Contains(stdout.String(), forbidden) {
					t.Fatalf("stdout contains forbidden %q:\n%s", forbidden, stdout.String())
				}
			}
			if item.wantStdoutJSON {
				var parsed map[string]any
				if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
					t.Fatalf("stdout must be JSON: %v\n%s", err, stdout.String())
				}
				if stderr.Len() != 0 {
					t.Fatalf("admitted JSON ABI must keep stderr empty: %s", stderr.String())
				}
			}
			if item.wantStatus != 0 && stdout.Len() != 0 && !item.wantStdoutJSON {
				t.Fatalf("failed ABI case must keep stdout empty: %s", stdout.String())
			}
		})
	}
}

func TestRequirementSpecTreeViewOutputPathAdmission(t *testing.T) {
	t.Chdir(t.TempDir())
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"requirement-spec-tree-view", "--input", "-", "--format", "markdown", "--output", "out/spec-tree.md"}, strings.NewReader(cliRequirementSpecTreeInput()), &stdout, &stderr)
	if status != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected output write result status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	content, err := os.ReadFile(filepath.Join("out", "spec-tree.md"))
	if err != nil {
		t.Fatalf("read written view: %v", err)
	}
	if !strings.Contains(string(content), "# Requirement Spec Tree View") || !strings.Contains(string(content), "Module spec") {
		t.Fatalf("written markdown view missing expected content:\n%s", string(content))
	}

	stdout.Reset()
	stderr.Reset()
	status = Run(t.Context(), []string{"requirement-spec-tree-view", "--input", "-", "--format", "json", "--output", "out/spec-tree.json"}, strings.NewReader(cliRequirementSpecTreeInput()), &stdout, &stderr)
	if status != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected JSON output write result status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	jsonContent, err := os.ReadFile(filepath.Join("out", "spec-tree.json"))
	if err != nil {
		t.Fatalf("read written JSON view: %v", err)
	}
	if !strings.Contains(string(jsonContent), `"viewKind": "proofkit.requirement-spec-tree-view"`) {
		t.Fatalf("written JSON view missing expected content:\n%s", string(jsonContent))
	}

	stdout.Reset()
	stderr.Reset()
	status = Run(t.Context(), []string{"requirement-spec-tree-view", "--input", "-", "--format", "markdown", "--output", "../spec-tree.md"}, strings.NewReader(cliRequirementSpecTreeInput()), &stdout, &stderr)
	if status != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("unsafe output args produced status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}

	outside := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside target: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join("out", "symlink.md")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	status = Run(t.Context(), []string{"requirement-spec-tree-view", "--input", "-", "--format", "markdown", "--output", "out/symlink.md"}, strings.NewReader(cliRequirementSpecTreeInput()), &stdout, &stderr)
	if status != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "must not be a symlink") {
		t.Fatalf("symlink output produced status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	outsideContent, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("read outside target: %v", err)
	}
	if string(outsideContent) != "outside" {
		t.Fatalf("output followed symlink and mutated outside target: %q", string(outsideContent))
	}

	parentTarget := filepath.Join(t.TempDir(), "parent-target")
	if err := os.Mkdir(parentTarget, 0o755); err != nil {
		t.Fatalf("create parent target: %v", err)
	}
	if err := os.Symlink(parentTarget, "linked-out"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	status = Run(t.Context(), []string{"requirement-spec-tree-view", "--input", "-", "--format", "markdown", "--output", "linked-out/spec-tree.md"}, strings.NewReader(cliRequirementSpecTreeInput()), &stdout, &stderr)
	if status != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "parent must not contain a symlink") {
		t.Fatalf("parent symlink output produced status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(parentTarget, "spec-tree.md")); !os.IsNotExist(err) {
		t.Fatalf("output followed parent symlink; stat err=%v", err)
	}
}

func TestRequirementBrowserServerSpecTreeCLIABI(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"requirement-browser-server", "--input", "-", "--view", "spec-tree"}, strings.NewReader(cliRequirementSpecTreeInput()), &stdout, &stderr)
	if status != 0 || stderr.Len() != 0 {
		t.Fatalf("status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("stdout must be JSON: %v\n%s", err, stdout.String())
	}
	if parsed["planKind"] != "proofkit.requirement-browser-server-plan" || parsed["renderedViewKind"] != "proofkit.requirement-spec-tree-view" || parsed["view"] != "spec-tree" {
		t.Fatalf("unexpected spec-tree browser plan: %#v", parsed)
	}
	if _, ok := parsed["htmlByteLength"].(float64); !ok {
		t.Fatalf("browser plan must expose rendered HTML byte length: %#v", parsed)
	}
}

func TestAdoptionDoctorCLIABI(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		stdin      string
		wantStatus int
		want       []string
	}{
		{
			name:       "report",
			args:       []string{"adoption-doctor", "--input", "-"},
			wantStatus: 0,
			want: []string{
				`"command": "go test ./internal/app"`,
				`"reportKind": "proofkit.adoption-doctor"`,
				`"routeCommands"`,
				`"state": "passed"`,
			},
		},
		{
			name:       "agent envelope",
			args:       []string{"adoption-doctor", "--input", "-", "--agent-envelope"},
			wantStatus: 0,
			want: []string{
				`"command": "go test ./internal/app"`,
				`"envelopeId": "proofkit.cli.adoption-doctor.agent-envelope"`,
				`"sourceReport"`,
			},
		},
		{
			name:       "missing owner route fails enforcement",
			args:       []string{"adoption-doctor", "--input", "-"},
			stdin:      cliAdoptionDoctorMissingRoutesInput(),
			wantStatus: 1,
			want: []string{
				`"kind": "missing_owner_route"`,
				`"route": "blocked_missing_owner_route"`,
				`"state": "failed"`,
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			stdin := item.stdin
			if stdin == "" {
				stdin = cliAdoptionDoctorInput()
			}
			status := Run(t.Context(), item.args, strings.NewReader(stdin), &stdout, &stderr)
			if status != item.wantStatus {
				t.Fatalf("status=%d want %d stdout=%s stderr=%s", status, item.wantStatus, stdout.String(), stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("admitted adoption-doctor CLI must keep stderr empty: %s", stderr.String())
			}
			var parsed map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
				t.Fatalf("stdout must be JSON: %v\n%s", err, stdout.String())
			}
			for _, want := range item.want {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("stdout does not contain %q:\n%s", want, stdout.String())
				}
			}
		})
	}
}

func TestAdoptionContractEnvelopeCLIABI(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		stdin      string
		wantStatus int
		wantStderr string
		assertJSON func(t *testing.T, value any)
	}{
		{
			name:       "workflow mode emits child workflow plan",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "workflow"},
			wantStatus: 0,
			assertJSON: func(t *testing.T, value any) {
				object := jsonObject(t, value)
				assertStringField(t, object, "planKind", "proofkit.adoption-workflow-plan")
				assertStringField(t, object, "workflowId", "proofkit.cli.workflow")
			},
		},
		{
			name:       "workflow agent envelope emits child envelope",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "workflow", "--agent-envelope"},
			wantStatus: 0,
			assertJSON: func(t *testing.T, value any) {
				object := jsonObject(t, value)
				assertStringField(t, object, "envelopeId", "proofkit-adoption-workflow.agent-envelope")
				assertStringField(t, jsonObjectField(t, object, "sourceReport"), "reportKind", "proofkit.adoption-workflow-plan")
			},
		},
		{
			name:       "adoption mode emits gradual adoption report",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "adoption"},
			wantStatus: 0,
			assertJSON: func(t *testing.T, value any) {
				object := jsonObject(t, value)
				assertStringField(t, object, "reportKind", "proofkit.gradual-adoption")
				assertStringField(t, object, "state", "passed")
			},
		},
		{
			name:       "bootstrap materialization emits manifest",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "bootstrap", "--materialization-manifest"},
			wantStatus: 0,
			assertJSON: func(t *testing.T, value any) {
				object := jsonObject(t, value)
				assertStringField(t, object, "manifestKind", "proofkit.gradual-adoption-bootstrap-materialization-manifest")
				source := jsonObjectField(t, object, "sourceReport")
				assertStringField(t, source, "reportKind", "proofkit.gradual-adoption-bootstrap")
				assertStringField(t, source, "state", "passed")
				assertManifestGuidanceCommands(t, object)
			},
		},
		{
			name:       "guidance override emits guidance report",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "guidance", "--guidance-mode", "warn", "--checked-scope", "all"},
			wantStatus: 0,
			assertJSON: func(t *testing.T, value any) {
				object := jsonObject(t, value)
				assertStringField(t, object, "reportKind", "proofkit.gradual-adoption-guidance")
				summary := jsonObjectField(t, object, "summary")
				assertStringField(t, summary, "guidanceMode", "warn")
				assertStringField(t, summary, "checkedScope", "all")
			},
		},
		{
			name:       "guidance agent envelope emits child envelope",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "guidance", "--agent-envelope", "--guidance-mode", "warn", "--checked-scope", "none"},
			wantStatus: 0,
			assertJSON: func(t *testing.T, value any) {
				object := jsonObject(t, value)
				assertStringField(t, object, "envelopeId", "proofkit.cli.guidance.agent-envelope")
				assertStringField(t, jsonObjectField(t, object, "sourceReport"), "reportKind", "proofkit.gradual-adoption-guidance")
			},
		},
		{
			name:       "pilot first emits pilot report",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "pilot", "--pilot", "first"},
			wantStatus: 0,
			assertJSON: func(t *testing.T, value any) {
				object := jsonObject(t, value)
				assertStringField(t, object, "reportId", "proofkit.cli.pilot.first")
				assertStringField(t, object, "reportKind", "proofkit.pilot-admission")
			},
		},
		{
			name:       "pilot stack diverse emits stack-diverse report",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "pilot", "--pilot", "stack-diverse"},
			wantStatus: 0,
			assertJSON: func(t *testing.T, value any) {
				object := jsonObject(t, value)
				assertStringField(t, object, "reportId", "proofkit.cli.pilot.stack-diverse")
				assertNumberField(t, jsonObjectField(t, object, "summary"), "stackDiversityDimensionCount", 5)
			},
		},
		{
			name:       "pilot all emits both pilot reports",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "pilot", "--pilot", "all"},
			wantStatus: 0,
			assertJSON: func(t *testing.T, value any) {
				items := jsonArray(t, value)
				if len(items) != 2 {
					t.Fatalf("pilot all item count=%d want 2: %#v", len(items), value)
				}
				assertStringField(t, jsonObject(t, items[0]), "reportId", "proofkit.cli.pilot.first")
				assertStringField(t, jsonObject(t, items[1]), "reportId", "proofkit.cli.pilot.stack-diverse")
			},
		},
		{
			name:       "agent envelope invalid aggregate emits repair packet",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "workflow", "--agent-envelope"},
			stdin:      cliInvalidAdoptionContractEnvelopeInput(),
			wantStatus: 1,
			assertJSON: func(t *testing.T, value any) {
				object := jsonObject(t, value)
				assertStringField(t, object, "envelopeId", "proofkit.agent-envelope.invalid-input")
				if len(jsonArrayField(t, object, "blockedPreconditions")) == 0 {
					t.Fatalf("invalid aggregate envelope must expose blocked preconditions: %#v", object)
				}
			},
		},
		{
			name:       "input pointer is rejected",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--input-pointer", "/workflow", "--mode", "workflow"},
			wantStatus: 1,
			wantStderr: "unsupported argument for adoption-contract-envelope: --input-pointer\n",
		},
		{
			name:       "agent envelope rejected outside envelope-capable modes",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "adoption", "--agent-envelope"},
			wantStatus: 1,
			wantStderr: "--agent-envelope is valid only for workflow, bootstrap, or guidance modes\n",
		},
		{
			name:       "pilot flag rejected outside pilot mode",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "workflow", "--pilot", "first"},
			wantStatus: 1,
			wantStderr: "--pilot is valid only for pilot mode\n",
		},
		{
			name:       "guidance flags rejected outside guidance mode",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "bootstrap", "--guidance-mode", "warn"},
			wantStatus: 1,
			wantStderr: "--guidance-mode, --checked-scope, and --touched-rule-id are valid only for guidance mode\n",
		},
		{
			name:       "invalid guidance mode rejected",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "guidance", "--guidance-mode", "audit"},
			wantStatus: 1,
			wantStderr: "--guidance-mode requires observe, warn, enforce-touched, or enforce-all\n",
		},
		{
			name:       "invalid checked scope rejected",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "guidance", "--checked-scope", "partial"},
			wantStatus: 1,
			wantStderr: "--checked-scope requires none, touched, or all\n",
		},
		{
			name:       "invalid guidance mode scope pair rejected",
			args:       []string{"adoption-contract-envelope", "--input", "-", "--mode", "guidance", "--guidance-mode", "enforce-all", "--checked-scope", "touched"},
			wantStatus: 1,
			assertJSON: func(t *testing.T, value any) {
				object := jsonObject(t, value)
				assertStringField(t, object, "state", "failed")
				encoded, err := json.Marshal(object)
				if err != nil {
					t.Fatalf("marshal object: %v", err)
				}
				if !strings.Contains(string(encoded), "enforce-all requires checkedScope all") {
					t.Fatalf("output=%s, want mode/scope failure", encoded)
				}
			},
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			stdin := item.stdin
			if stdin == "" {
				stdin = cliAdoptionContractEnvelopeInput()
			}
			status := Run(t.Context(), item.args, strings.NewReader(stdin), &stdout, &stderr)
			if status != item.wantStatus {
				t.Fatalf("status=%d want %d stdout=%s stderr=%s", status, item.wantStatus, stdout.String(), stderr.String())
			}
			if item.wantStderr != "" && stderr.String() != item.wantStderr {
				t.Fatalf("stderr=%q want %q", stderr.String(), item.wantStderr)
			}
			if item.wantStderr == "" && stderr.Len() != 0 {
				t.Fatalf("stderr must be empty: %s", stderr.String())
			}
			if item.wantStderr != "" && stdout.Len() != 0 {
				t.Fatalf("stdout must be empty for argument failure: %s", stdout.String())
			}
			if item.assertJSON != nil {
				var parsed any
				if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
					t.Fatalf("stdout must be JSON: %v\n%s", err, stdout.String())
				}
				item.assertJSON(t, parsed)
			}
		})
	}
}

func assertManifestGuidanceCommands(t *testing.T, manifest map[string]any) {
	t.Helper()
	files := jsonArrayField(t, manifest, "files")
	for _, rawFile := range files {
		file := jsonObject(t, rawFile)
		if file["payloadKey"] != "adoptionGuidance" {
			continue
		}
		content, ok := file["content"].(string)
		if !ok {
			t.Fatalf("adoption guidance content must be a JSON string: %#v", file)
		}
		var guidance map[string]any
		if err := json.Unmarshal([]byte(content), &guidance); err != nil {
			t.Fatalf("adoption guidance payload must be JSON: %v\n%s", err, content)
		}
		commands := stringListFromAny(t, jsonObjectField(t, guidance, "agentGuidance")["commands"])
		if !stringListContains(commands, "go test ./internal/command/gradualadoption") {
			t.Fatalf("caller-provided bootstrap command was not preserved: %#v", commands)
		}
		if !stringListContains(commands, "agentic-proofkit gradual-adoption --input proofkit/profile.json") {
			t.Fatalf("generated bootstrap command missing: %#v", commands)
		}
		return
	}
	t.Fatalf("materialization manifest missing adoptionGuidance payload: %#v", manifest)
}

func jsonObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value must be a JSON object: %#v", value)
	}
	return object
}

func jsonArray(t *testing.T, value any) []any {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("value must be a JSON array: %#v", value)
	}
	return items
}

func jsonObjectField(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	return jsonObject(t, object[key])
}

func jsonArrayField(t *testing.T, object map[string]any, key string) []any {
	t.Helper()
	return jsonArray(t, object[key])
}

func assertStringField(t *testing.T, object map[string]any, key string, want string) {
	t.Helper()
	if got, ok := object[key].(string); !ok || got != want {
		t.Fatalf("%s=%#v want %q", key, object[key], want)
	}
}

func assertNumberField(t *testing.T, object map[string]any, key string, want float64) {
	t.Helper()
	if got, ok := object[key].(float64); !ok || got != want {
		t.Fatalf("%s=%#v want %v", key, object[key], want)
	}
}

func TestRequirementImpactInputComposeCLIOutputFeedsImpact(t *testing.T) {
	composed := runCLI(t, []string{"requirement-impact-input-compose", "--input", "-"}, cliImpactInputComposeInput())
	if !json.Valid(composed) {
		t.Fatalf("composed impact input is not JSON: %s", composed)
	}
	if !bytes.Contains(composed, []byte(`"changedRecordIds": [`)) || !bytes.Contains(composed, []byte(`"REQ-PROOFKIT-CLI-IMPACT-001"`)) {
		t.Fatalf("composed impact input did not route changed requirement: %s", composed)
	}
	report := runCLI(t, []string{"impact", "--input", "-"}, string(composed))
	if !bytes.Contains(report, []byte(`"impactState": "ok"`)) || !bytes.Contains(report, []byte(`"REQ-PROOFKIT-CLI-IMPACT-001"`)) {
		t.Fatalf("impact did not accept composed input as passed route: %s", report)
	}
}

func cliAdoptionContractEnvelopeInput() string {
	payload := map[string]any{
		"schema":     "proofkit.adoption-contract-envelope.v1",
		"envelopeId": "proofkit.cli.adoption.aggregate",
		"workflow": map[string]any{
			"schema":   "proofkit.adoption-workflow.v1",
			"workflow": cliAdoptionWorkflowInput(),
		},
		"gradual": map[string]any{
			"schema":    "proofkit.gradual-adoption-profile.v1",
			"input":     cliGradualAdoptionInput(),
			"bootstrap": cliBootstrapContract(),
			"guidance":  cliGuidanceContract(),
		},
		"pilot": map[string]any{
			"schema":            "proofkit.pilot-admission.v1",
			"input":             cliPilotInput("proofkit.cli.pilot.first", false),
			"stackDiverseInput": cliPilotInput("proofkit.cli.pilot.stack-diverse", true),
		},
		"nonClaims": []any{"CLI aggregate fixture does not execute native witnesses."},
	}
	content, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(content)
}

func cliInvalidAdoptionContractEnvelopeInput() string {
	payload := map[string]any{
		"schema":     "proofkit.adoption-contract-envelope.v1",
		"envelopeId": "proofkit.cli.adoption.aggregate",
		"workflow": map[string]any{
			"schema":   "proofkit.wrong-workflow.v1",
			"workflow": map[string]any{},
		},
		"gradual": map[string]any{
			"schema":    "proofkit.gradual-adoption-profile.v1",
			"input":     map[string]any{},
			"bootstrap": map[string]any{},
			"guidance":  map[string]any{},
		},
		"pilot": map[string]any{
			"schema":            "proofkit.pilot-admission.v1",
			"input":             map[string]any{},
			"stackDiverseInput": map[string]any{},
		},
		"nonClaims": []any{},
	}
	content, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(content)
}

func cliAdoptionWorkflowInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"workflowId":    "proofkit.cli.workflow",
		"scenario":      "release_channel",
		"presetId":      nil,
		"inputRefs": []any{
			map[string]any{"inputKind": "release_authority", "path": "proofkit/release-authority.v1.json", "refId": "proofkit.release-authority"},
			map[string]any{"inputKind": "registry_consumer", "path": "proofkit/registry-consumer.v1.json", "refId": "proofkit.registry-consumer"},
		},
		"nonClaims": []any{"CLI workflow fixture does not execute generated commands."},
	}
}

func cliGradualAdoptionInput() map[string]any {
	return map[string]any{
		"schemaVersion":     json.Number("1"),
		"adoptionId":        "proofkit.cli.adoption",
		"adoptionMode":      "non_blocking",
		"packageVersionRef": "agentic-proofkit@local",
		"rolloutClaim":      false,
		"nonClaims":         []any{"CLI gradual adoption fixture does not prove rollout readiness."},
		"repository": map[string]any{
			"customRuleBoundary": "profile_only",
			"primaryLanguages":   []any{"go"},
			"profilePath":        "proofkit/profile.json",
			"repositoryClass":    "go_cli",
			"repositoryId":       "proofkit.cli.repo",
			"verifierCodeCopied": false,
		},
		"module": map[string]any{
			"moduleId":       "proofkit.cli.module",
			"requirementIds": []any{"REQ-PROOFKIT-CLI-ADOPTION-001"},
			"specPath":       "docs/specs/cli-adoption/requirements.v1.json",
		},
		"proofBinding": map[string]any{
			"bindingFormat":     "requirement_to_witness",
			"bindingPath":       "proofkit/proof-bindings.json",
			"requirementIds":    []any{"REQ-PROOFKIT-CLI-ADOPTION-001"},
			"witnessCommandIds": []any{"proofkit.cli.command"},
		},
		"nativeWitnesses": cliNativeWitnesses(),
		"agentReport": map[string]any{
			"artifactPath":   "artifacts/proofkit/gradual-adoption.json",
			"outputMode":     "non_blocking",
			"reportKind":     "proofkit.gradual-adoption",
			"routeQuestions": []any{"what changed", "what proves it", "who owns it"},
			"schemaId":       "proofkit.gradual-adoption-profile.v1",
		},
		"budget": cliAdoptionBudget(),
		"rollback": map[string]any{
			"disableCommand": "remove proofkit gradual-adoption report from non-blocking CI",
			"owner":          "repo-maintainers",
			"versionPin":     "agentic-proofkit@previous",
		},
	}
}

func cliBootstrapContract() map[string]any {
	return map[string]any{
		"bootstrapId": "proofkit.cli.bootstrap",
		"defaultMode": "observe",
		"paths": map[string]any{
			"adoptionGuidancePath":       "proofkit/guidance.json",
			"adoptionProfilePath":        "proofkit/profile.json",
			"adoptionReportArtifactPath": "artifacts/proofkit/adoption.json",
			"guidanceReportArtifactPath": "artifacts/proofkit/guidance.json",
			"witnessPlanInputPath":       "proofkit/witness-plan.json",
		},
		"scopeEvidence": map[string]any{
			"checkedScope":   "none",
			"touchedRuleIds": []any{},
		},
		"commands":  []any{"go test ./internal/command/gradualadoption"},
		"nonClaims": []any{"CLI bootstrap fixture does not prove rollout readiness."},
	}
}

func cliGuidanceContract() map[string]any {
	return map[string]any{
		"guidanceId":  "proofkit.cli.guidance",
		"defaultMode": "observe",
		"scopeEvidence": map[string]any{
			"checkedScope":   "none",
			"touchedRuleIds": []any{},
		},
		"ownerRoute": map[string]any{
			"evidencePaths":     []any{"artifacts/proofkit/source.json"},
			"primaryOwner":      "repo-maintainers",
			"proofBindingPaths": []any{"proofkit/proof-bindings.json"},
			"specPaths":         []any{"docs/specs/cli-adoption/requirements.v1.json"},
		},
		"agentGuidance": map[string]any{
			"artifactPath":                     "artifacts/proofkit/guidance.json",
			"blockedPreconditions":             []any{},
			"callerSuggestedAutofixCandidates": []any{},
			"commands":                         []any{},
			"minimalAdoptionPath":              []any{"Keep proofkit adoption non-blocking until owner review."},
			"proofBindingsMissing":             []any{},
			"reportKind":                       "proofkit.gradual-adoption-guidance",
			"requiredNextActions":              []any{},
			"routeQuestions":                   []any{"what changed", "what proves it", "who owns it"},
			"schemaId":                         "proofkit.gradual-adoption-guidance.v1",
		},
		"modernization": map[string]any{
			"candidateBoundaries":         []any{},
			"promoteOnlyAfterOwnerReview": true,
		},
		"nonClaims": []any{"CLI guidance fixture does not prove rollout readiness."},
	}
}

func cliNativeWitnesses() map[string]any {
	return map[string]any{
		"vocabulary": map[string]any{
			"artifactKinds":      []any{"json"},
			"credentialClasses":  []any{"none"},
			"environmentClasses": []any{"local-go"},
			"environmentClassPolicies": []any{map[string]any{
				"cachePolicies":     []any{"read-only"},
				"credentialClasses": []any{"none"},
				"environmentClass":  "local-go",
				"networkPolicies":   []any{"none"},
			}},
			"parallelGroups": []any{"local-go"},
		},
		"commands": []any{map[string]any{
			"schemaVersion":     json.Number("1"),
			"id":                "proofkit.cli.command",
			"argv":              []any{"go", "test", "./..."},
			"cachePolicy":       "read-only",
			"credentialClass":   "none",
			"cwd":               ".",
			"environment":       map[string]any{"allowlist": []any{}, "classes": []any{"local-go"}, "inherit": "none"},
			"exitCodePolicy":    map[string]any{"kind": "zero", "successCodes": []any{json.Number("0")}},
			"expectedArtifacts": []any{},
			"networkPolicy":     "none",
			"parallelGroup":     "local-go",
			"timeoutMs":         json.Number("60000"),
		}},
	}
}

func cliAdoptionBudget() map[string]any {
	return map[string]any{
		"copiedVerifierFileCount": json.Number("0"),
		"customRuleCount":         json.Number("0"),
		"maxAddedSeconds":         json.Number("10"),
		"maxCustomRuleCount":      json.Number("0"),
		"maxProfileLines":         json.Number("80"),
		"maxSetupMinutes":         json.Number("20"),
		"profileLines":            json.Number("42"),
	}
}

func cliPilotInput(pilotID string, stackDiverse bool) map[string]any {
	input := map[string]any{
		"schemaVersion": json.Number("1"),
		"pilotId":       pilotID,
		"profile": map[string]any{
			"commandMatcherBridge":      "none",
			"customRuleBoundary":        "profile_only",
			"primaryLanguages":          []any{"go"},
			"repositoryClass":           "go_cli",
			"repositoryId":              "proofkit.cli",
			"structuredWitnessCommands": true,
			"verifierCodeCopied":        false,
		},
		"blockingRequirements": map[string]any{
			"dispositionPolicy":              "all_blocking_requirements_must_be_witnessed_or_explicitly_deferred",
			"explicitlyDeferredRequirements": json.Number("0"),
			"requirements": []any{map[string]any{
				"evidence":      "docs/specs/proofkit/requirements.v1.json",
				"owner":         "proofkit",
				"requirementId": "REQ-PROOFKIT-001",
				"status":        "witness_backed",
			}},
			"totalBlockingRequirements": json.Number("1"),
			"unmappedRequirements":      json.Number("0"),
			"witnessBackedRequirements": json.Number("1"),
		},
		"agentReportRoutes": []any{map[string]any{
			"artifactPath":       "artifacts/proofkit/report.json",
			"command":            "agentic-proofkit render",
			"expectedUpdatePath": "docs/specs/proofkit/requirements.v1.json",
			"reportKind":         "proofkit.report",
			"schemaId":           "proofkit.schema",
			"taskType":           "proofkit.review",
		}},
		"cacheScheduler": map[string]any{
			"cacheKeyInputs":                []any{"go.mod"},
			"destructiveConcurrencyAllowed": false,
			"invalidationInputs":            []any{"go.sum"},
			"maxParallelGroups":             json.Number("1"),
			"parallelGroups":                []any{"local"},
			"schedulerPolicy":               "bounded_parallel_groups",
		},
		"timingBudget": map[string]any{
			"maxAddedSeconds":          json.Number("5"),
			"measuredSeparately":       true,
			"reportArtifactPath":       "artifacts/proofkit/timing.json",
			"trackedFixtureAsBaseline": false,
		},
		"infrastructureBudget": map[string]any{
			"copiedVerifierFileCount":    json.Number("0"),
			"customRuleCount":            json.Number("0"),
			"customRules":                []any{},
			"manualTruthSurfaceCount":    json.Number("0"),
			"manualUpdateStepCount":      json.Number("0"),
			"maxCustomRuleCount":         json.Number("0"),
			"maxManualTruthSurfaceCount": json.Number("0"),
			"maxManualUpdateStepCount":   json.Number("0"),
			"maxProfileLines":            json.Number("100"),
			"profileLines":               json.Number("20"),
		},
		"falsePositiveBudget": map[string]any{
			"dispositionOwner":             "proofkit",
			"enforcementMode":              "non_blocking",
			"maxAllowedFalsePositiveCount": json.Number("0"),
			"sampleWindowRuns":             json.Number("1"),
		},
		"rollback": map[string]any{
			"owner":           "proofkit",
			"rollbackCommand": "agentic-proofkit previous-version",
			"versionPin":      "package.json",
		},
		"impactDemos":         []any{cliImpactDemo("proofkit.cli.impact.demo", false)},
		"cacheNegativeChecks": []any{},
		"nonClaims":           []any{"CLI pilot fixture does not claim rollout readiness."},
		"packageVersionRef":   "package.json",
		"pilotMode":           "non_blocking",
		"rolloutClaim":        false,
	}
	if stackDiverse {
		input["stackDiversity"] = cliStackDiversity()
		input["cacheNegativeChecks"] = cliCacheNegativeChecks()
		input["impactDemos"] = []any{cliImpactDemo("proofkit.cli.impact.demo.stack", true)}
	}
	return input
}

func cliStackDiversity() map[string]any {
	dimensions := []any{}
	for _, dimension := range []string{"docs_spec_layout", "generated_artifact_policy", "language_runtime_test_shape", "proof_environment_classes", "repository_topology"} {
		dimensions = append(dimensions, map[string]any{
			"baseline":  "baseline-" + dimension,
			"candidate": "candidate-" + dimension,
			"dimension": dimension,
			"evidence":  "docs/evidence/" + dimension + ".md",
		})
	}
	return map[string]any{"baselinePilotId": "proofkit.cli.pilot.first", "dimensions": dimensions}
}

func cliCacheNegativeChecks() []any {
	checks := []any{}
	for _, inputClass := range []string{"package_version", "profile", "schema", "source"} {
		checks = append(checks, map[string]any{
			"checkId":                     "proofkit.cache." + inputClass,
			"evidence":                    "Cache invalidates on " + inputClass + " changes.",
			"expectedOutcome":             "invalidate_output",
			"invalidatedInputClass":       inputClass,
			"liveOrCredentialedCacheable": false,
		})
	}
	return checks
}

func cliImpactDemo(demoID string, stackDiverse bool) map[string]any {
	impactInput := map[string]any{
		"schemaVersion":              json.Number("1"),
		"baseCommit":                 "base",
		"baseRef":                    "main",
		"changedBindingRecordIds":    []any{},
		"changedPaths":               []any{"docs/specs/proofkit/requirements.v1.json"},
		"changedRecordIds":           []any{"REQ-PROOFKIT-001"},
		"changedWitnessPathCoverage": []any{},
		"generatedArtifactRules":     []any{},
		"headCommit":                 nil,
		"headRef":                    "feature/proofkit",
		"ignoredProofLikePaths":      []any{},
		"obligationCatalog": []any{map[string]any{
			"blockingStatus":             "blocking",
			"commands":                   []any{"go test ./..."},
			"preconditioned":             false,
			"proofContractState":         "witness_backed",
			"recordId":                   "REQ-PROOFKIT-001",
			"requiredEnvironmentClasses": []any{"local-go"},
			"scenarioId":                 "proofkit.scenario",
			"surfaceId":                  "proofkit.surface",
		}},
		"preexistingFailures":         []any{},
		"proofLikePaths":              []any{},
		"unboundProofChangeRationale": "No unbound proof-like path changed.",
	}
	if stackDiverse {
		impactInput["changedBindingRecordIds"] = []any{"REQ-PROOFKIT-001"}
		impactInput["changedPaths"] = []any{"docs/specs/proofkit/requirements.v1.json", "internal/proofkit/witness_test.go"}
		impactInput["changedWitnessPathCoverage"] = []any{
			map[string]any{"path": "internal/proofkit/witness_test.go", "recordIds": []any{"REQ-PROOFKIT-001"}},
		}
	}
	return map[string]any{
		"demoId":                  demoID,
		"generatedMirrorPaths":    []any{"docs/generated/requirements.md"},
		"sourceOwnedChangedPaths": []any{"docs/specs/proofkit/requirements.v1.json"},
		"impactInput":             impactInput,
	}
}

func cliTestEvidenceInventory() string {
	return `{"schemaVersion":1,"inventoryId":"proofkit.cli.inventory","authority":"caller_owned_inventory","entries":[{"testId":"test.cli.semantic","selector":"go test ./internal/app -run TestCLI","sourcePath":"internal/app/cli_abi_test.go","ownerId":"proofkit.cli","evidenceClass":"semantic_falsifier","requirementRefs":["REQ-PROOFKIT-CLI-001"],"ownerInvariantRefs":[],"commandRefs":["proofkit.cli.command"],"witnessRefs":["proofkit.cli.witness"],"falsifier":{"falsifierId":"falsifier.cli.semantic","negativeCaseId":"case.cli.semantic","wrongImplementationClassId":"wrong.cli.semantic","dominanceGroup":"cli.semantic","supersedes":[]},"oracle":{"oracleId":"oracle.cli.semantic","oracleKind":"negative_exit_and_diagnostic","assertionSummary":"The CLI emits a failed report on invalid semantic coverage."},"nonClaims":[]}],"nonClaims":["CLI ABI fixture does not execute native tests."]}`
}

func cliRequirementSpecTreeInput() string {
	return `{"schemaVersion":1,"treeId":"proofkit.cli.spec_tree","rootNodeId":"meta","callerNonClaims":["CLI spec tree fixture is display-only."],"nodes":[{"nodeId":"meta","nodeKind":"meta_spec","label":"Meta spec","displayOrder":1,"sourceRefs":[{"sourceRefId":"source.meta","sourceRole":"requirements","sourceRefKind":"source_id","sourceId":"spec.meta"}],"callerNonClaims":[]},{"nodeId":"module","nodeKind":"module_spec","label":"Module spec","displayOrder":1,"sourceRefs":[{"sourceRefId":"source.module","sourceRole":"requirements","sourceRefKind":"path_digest","sourcePath":"docs/specs/module/requirements.v1.json","recordedSourceDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","currentSourceDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","digestAlgorithm":"sha256"}],"callerNonClaims":[]}],"edges":[{"parentNodeId":"meta","childNodeId":"module"}],"overlays":[{"overlayId":"overlay.module.source","overlayKind":"source","targetNodeId":"module","refKind":"source_ref","refId":"source.module","label":"Module source","callerNonClaims":[]}]}`
}

func cliRequirementAuthoringPlanInput() string {
	return `{"schemaVersion":1,"authoringPlanId":"proofkit.cli.requirement-authoring-plan","mode":"pull_request_design","currentRequirementSource":{"schemaVersion":1,"sourceId":"proofkit.cli.authoring.requirements","specPackagePath":"docs/specs/proofkit-cli-authoring","overviewPath":"docs/specs/proofkit-cli-authoring/overview.md","requirementsPath":"docs/specs/proofkit-cli-authoring/requirements.v1.json","requirements":[{"requirementId":"REQ-PROOFKIT-CLI-AUTHORING-000","ownerId":"proofkit.cli.authoring","invariant":"CLI authoring fixture source remains admissible.","claimLevel":"blocking","riskClass":"medium","proofBindingRefs":["proofkit/requirement-bindings.json"],"nonClaimRefs":[],"nonClaims":["CLI authoring fixture does not execute witnesses."],"lifecycle":{"state":"active","replacementRequirementIds":[],"evidenceRefs":[]},"deferral":null,"updatePolicy":{"reviewOwnerId":"proofkit.cli.authoring","requiresImpactDeclaration":true,"requiresProofBindingReview":true}}],"nonClaims":["CLI authoring fixture source does not own native witnesses."]},"authoringRefs":[{"refId":"proofkit.cli.authoring.design","kind":"design_doc","path":"docs/designs/cli-authoring.md","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","summary":"The CLI fixture design proposes one durable candidate invariant.","nonClaims":["CLI authoring fixture ref is label-only."]}],"candidateUpdates":[{"candidateId":"proofkit.cli.authoring.candidate","operation":"add","requirementId":"REQ-PROOFKIT-CLI-AUTHORING-001","sourceRefIds":["proofkit.cli.authoring.design"],"rationale":"The design introduces a durable candidate invariant.","ownerQuestions":["Should this candidate become stable repository truth?"],"declaredProofObligations":[{"obligationId":"proofkit.cli.authoring.proof-binding","kind":"proof_binding","ownerId":"proofkit.cli.authoring","description":"Bind the candidate requirement to a semantic falsifier.","blocking":true,"evidenceRefs":["proofkit/requirement-bindings.json"]}],"candidateRequirement":{"requirementId":"REQ-PROOFKIT-CLI-AUTHORING-001","ownerId":"proofkit.cli.authoring","invariant":"CLI authoring plans preserve candidate-only source previews.","claimLevel":"blocking","riskClass":"high","proofBindingRefs":["proofkit/requirement-bindings.json"],"nonClaimRefs":[],"nonClaims":["CLI authoring candidate does not approve materialization."],"lifecycle":{"state":"active","replacementRequirementIds":[],"evidenceRefs":[]},"deferral":null,"updatePolicy":{"reviewOwnerId":"proofkit.cli.authoring","requiresImpactDeclaration":true,"requiresProofBindingReview":true}}}],"nonClaims":["CLI authoring fixture does not approve requirement promotion."]}`
}

func cliCapabilityMapInput(trustMode string, includeAnchor bool) string {
	anchors := `[]`
	if includeAnchor {
		anchors = `[{"scenarioId":"sample.backend.auth.missing_header_fails_closed","selector":"service/tests/auth_test.py::test_missing_header_fails_closed","sourcePath":"service/tests/auth_test.py","commandRefs":["sample.pytest.auth"],"status":"candidate","positiveWitness":false,"falsificationWitness":true,"nonClaims":["CLI capability anchor fixture does not execute tests."]}]`
	}
	return `{"schemaVersion":1,"mapId":"proofkit.cli.capability_map","authority":"caller_owned_observation","trustMode":"` + trustMode + `","repository":{"repositoryId":"sample_repo","primaryLanguages":["python","typescript"],"nonClaims":["CLI capability repository fixture is caller-owned."]},"proofScope":{"scopeId":"sample.backend.auth.scope","dirtyState":"clean","baseRef":"origin/main","headRef":"HEAD","nonClaims":["CLI capability scope fixture does not prove checkout freshness."]},"capabilities":[{"capabilityId":"sample.backend.auth","ownerId":"sample.backend","summary":"Authentication requests resolve authorization headers and fail closed when they are absent.","sourcePaths":["service/src/auth","service/tests/auth_test.py"],"riskClasses":["runtime","security"],"scenarioShapes":[{"scenarioId":"sample.backend.auth.missing_header_fails_closed","candidateRequirementId":"REQ-SAMPLE-AUTH-001","summary":"Requests without authentication headers fail closed before protected backend state is accessed.","requiredEvidence":["negative_test"],"ownerQuestions":["Should anonymous health checks bypass this invariant?"],"nonClaims":["CLI capability scenario fixture does not claim every auth edge case."]}],"nonClaims":["CLI capability fixture does not claim production auth readiness."]}],"scenarioAnchors":` + anchors + `,"requiredVerification":[{"commandId":"sample.pytest.auth","command":"uv run pytest service/tests/auth_test.py","environmentClass":"local_python","reason":"Auth failure mode needs an executable negative witness.","nonClaims":["CLI capability command fixture does not prove test freshness."]}],"nonClaims":["CLI capability map fixture is not merge evidence."]}`
}

func cliTestEvidenceInventoryMissingAnchor() string {
	input := cliTestEvidenceInventory()
	input = strings.Replace(input, `"requirementRefs":["REQ-PROOFKIT-CLI-001"]`, `"requirementRefs":[]`, 1)
	return input
}

func cliProofBindingDerivedInventoryInput() string {
	return `{"schemaVersion":1,"inventoryId":"proofkit.cli.derived.inventory","commandRefPolicy":{"prefix":"proofkit_cli"},"requirementSource":{"requirements":[{"requirementId":"REQ-PROOFKIT-CLI-001","ownerId":"proofkit.cli"}]},"compactProofContract":{"schema_version":1,"authority_state":"canonical","contract_id":"proofkit.cli.compact","contract_kind":"requirement_proof_binding","normalization_profile":"proofkit.compact.v1","non_claims":["CLI compact fixture does not execute witnesses."],"surface_columns":["surface_id","required_environment_classes","preconditioned_environment_classes"],"surfaces":[["proofkit.cli",["local-go"],[]]],"witness_columns":["selector","environment_classes","verify_commands","resolution_order_index"],"binding_columns":["requirement_id","surface_id","scenario_id","invariant_role","owned_invariant","proof_contract_state","blocking_status","required_environment_classes","positive_witness","falsification_witness","verify_commands","mutation_resistance_state"],"bindings":[["REQ-PROOFKIT-CLI-001","proofkit.cli","proofkit.cli::scenario","contract","proofkit.cli.invariant","witness_backed","blocking",["local-go"],["internal/app/cli_positive_test.go::TestAcceptsCLIContract",["local-go"],["go test"],0],["internal/app/cli_falsification_test.go::TestRejectsCLIRegression",["local-go"],["go test"],1],["go test"],"no_known_advisory_gap"]]},"nonClaims":["CLI projection fixture does not execute native tests."]}`
}

func cliTestDiscoveryDraftInput() string {
	return `{"schemaVersion":1,"draftId":"proofkit.cli.discovery_draft","authority":"caller_owned_test_discovery","repository":{"repositoryId":"proofkit.cli","nonClaims":["CLI discovery fixture does not scan the repository."]},"runner":{"runnerId":"proofkit.cli.go","runnerKind":"go_test","commandRef":"proofkit.cli.go.test","environmentClass":"local-go","nonClaims":["CLI discovery fixture does not execute go test."]},"discoveredTests":[{"testId":"test.cli.discovery.test_missing_auth","sourcePath":"internal/app/cli_abi_test.go","selector":"internal/app/cli_abi_test.go::TestMissingAuth","title":"TestMissingAuth","ownerId":"proofkit.cli.discovery","candidateRequirementRefs":["REQ-PROOFKIT-CLI-DISCOVERY-001"],"ownerInvariantRefs":[],"oracleSignals":["assertion_present"],"selectorSignals":["structured_selector"],"nonClaims":["CLI discovery test fact is caller-owned."]}],"nonClaims":["CLI discovery draft fixture is candidate-only."]}`
}

func cliCoverageInventory() string {
	return `{"schemaVersion":1,"inventoryId":"proofkit.cli.coverage.inventory","authority":"caller_owned_inventory","entries":[{"testId":"test.cli.coverage.semantic","selector":"go test ./internal/app -run TestCoverage","sourcePath":"internal/app/cli_abi_test.go","ownerId":"proofkit.cli.coverage","evidenceClass":"semantic_falsifier","requirementRefs":["REQ-PROOFKIT-CLI-COVERAGE-001"],"ownerInvariantRefs":[],"commandRefs":["proofkit.cli.coverage.command"],"witnessRefs":["proofkit.cli.coverage.witness"],"falsifier":{"falsifierId":"falsifier.cli.coverage","negativeCaseId":"case.cli.coverage","wrongImplementationClassId":"wrong.cli.coverage","dominanceGroup":"cli.coverage","supersedes":[]},"oracle":{"oracleId":"oracle.cli.coverage","oracleKind":"negative_exit_and_diagnostic","assertionSummary":"Missing inventory leaves coverage failed."},"nonClaims":[]}],"nonClaims":["CLI coverage inventory fixture does not execute native tests."]}`
}

func cliCoverageInput(inventory string) string {
	return `{"schemaVersion":1,"viewInputId":"proofkit.cli.coverage.view","requirementSource":{"schemaVersion":1,"sourceId":"proofkit.cli.coverage.source","specPackagePath":"docs/specs/proofkit-cli-coverage","overviewPath":"docs/specs/proofkit-cli-coverage/overview.md","requirementsPath":"docs/specs/proofkit-cli-coverage/requirements.v1.json","requirements":[{"requirementId":"REQ-PROOFKIT-CLI-COVERAGE-001","ownerId":"proofkit.cli.coverage","invariant":"CLI coverage view preserves report ABI.","claimLevel":"blocking","riskClass":"high","proofBindingRefs":["proofkit/requirement-bindings.json"],"nonClaimRefs":[],"nonClaims":["CLI coverage fixture does not execute tests."],"lifecycle":{"state":"active","replacementRequirementIds":[],"evidenceRefs":[]},"deferral":null,"updatePolicy":{"reviewOwnerId":"proofkit.cli.coverage","requiresImpactDeclaration":true,"requiresProofBindingReview":true}}],"nonClaims":["CLI coverage fixture source does not own native tests."]},"requirementProofBinding":{"schemaVersion":1,"bindingId":"proofkit.cli.coverage.binding","requirements":[{"requirementId":"REQ-PROOFKIT-CLI-COVERAGE-001","ownerId":"proofkit.cli.coverage","specPath":"docs/specs/proofkit-cli-coverage/requirements.v1.json","claimLevel":"blocking","proofState":"witness_backed","nonClaims":["CLI coverage fixture binding does not execute witnesses."]}],"bindings":[{"requirementId":"REQ-PROOFKIT-CLI-COVERAGE-001","scenarioId":"proofkit.cli.coverage.scenario","witnessId":"proofkit.cli.coverage.witness","witnessKind":"contract","witnessPath":"internal/app/cli_abi_test.go","commandIds":["proofkit.cli.coverage.command"],"environmentClasses":["local-go"]}],"witnessCommands":[{"commandId":"proofkit.cli.coverage.command","command":"go test ./internal/app","environmentClass":"local-go"}],"selection":{"changedPaths":[],"ownerIds":[],"requirementIds":[]},"nonClaims":["CLI coverage fixture binding does not prove command pass evidence."]},"compactProofContract":null,"ownerInvariantRegistry":null,"coverageUniverse":{"schemaVersion":1,"universeId":"proofkit.cli.coverage.universe","authority":"caller_owned_inventory","completenessDeclaration":"selected_owner_surfaces","ownerIds":["proofkit.cli.coverage"],"codeSurfaces":[{"surfaceId":"proofkit.cli.coverage.code","ownerId":"proofkit.cli.coverage","path":"internal/app"}],"specSurfaces":[{"surfaceId":"proofkit.cli.coverage.spec","ownerId":"proofkit.cli.coverage","path":"docs/specs/proofkit-cli-coverage/requirements.v1.json"}],"testSurfaces":[{"surfaceId":"proofkit.cli.coverage.test","ownerId":"proofkit.cli.coverage","path":"internal/app/cli_abi_test.go"}],"commandRefs":["proofkit.cli.coverage.command"],"nonClaims":["CLI coverage universe is selected-owner scope only."]},"testEvidenceInventory":` + inventory + `,"localEnvironmentPolicy":null,"options":{"scope":"graph"}}`
}

func cliCoverageInputComposeInput() string {
	return `{"schemaVersion":1,"composerInputId":"proofkit.cli.coverage.compose","viewInputId":"proofkit.cli.coverage.compose.view","selectedOwnerIds":["proofkit.cli.coverage"],"requirementSource":{"schemaVersion":1,"sourceId":"proofkit.cli.coverage.source","specPackagePath":"docs/specs/proofkit-cli-coverage","overviewPath":"docs/specs/proofkit-cli-coverage/overview.md","requirementsPath":"docs/specs/proofkit-cli-coverage/requirements.v1.json","requirements":[{"requirementId":"REQ-PROOFKIT-CLI-COVERAGE-001","ownerId":"proofkit.cli.coverage","invariant":"CLI coverage input composition preserves direct view input ABI.","claimLevel":"blocking","riskClass":"high","proofBindingRefs":["proofkit/requirement-bindings.json"],"nonClaimRefs":[],"nonClaims":["CLI coverage composer fixture does not execute tests."],"lifecycle":{"state":"active","replacementRequirementIds":[],"evidenceRefs":[]},"deferral":null,"updatePolicy":{"reviewOwnerId":"proofkit.cli.coverage","requiresImpactDeclaration":true,"requiresProofBindingReview":true}}],"nonClaims":["CLI coverage composer fixture source does not own native tests."]},"compactProofContract":{"schema_version":1,"authority_state":"canonical","contract_id":"proofkit.cli.coverage.compact","contract_kind":"requirement_proof_binding","normalization_profile":"proofkit.compact.v1","non_claims":["CLI compact fixture does not execute witnesses."],"surface_columns":["surface_id","required_environment_classes","preconditioned_environment_classes"],"surfaces":[["proofkit.cli.coverage",["local-go"],[]]],"witness_columns":["selector","environment_classes","verify_commands","resolution_order_index"],"binding_columns":["requirement_id","surface_id","scenario_id","invariant_role","owned_invariant","proof_contract_state","blocking_status","required_environment_classes","positive_witness","falsification_witness","verify_commands","mutation_resistance_state"],"bindings":[["REQ-PROOFKIT-CLI-COVERAGE-001","proofkit.cli.coverage","proofkit.cli.coverage::scenario","contract","proofkit.cli.coverage.invariant","witness_backed","blocking",["local-go"],["internal/app/cli_abi_test.go::positive",["local-go"],["go test ./internal/app"],0],["internal/app/cli_abi_test.go::falsification",["local-go"],["go test ./internal/app"],1],["go test ./internal/app"],"no_known_advisory_gap"]]},"normalizedTestEvidenceInventory":{"schemaVersion":1,"normalizedInventoryId":"proofkit.cli.coverage.inventory.normalized","normalizedKind":"proofkit.test-evidence-inventory.normalized","sourceAuthority":"caller_owned_inventory","sourceCount":0,"sourceColumns":["source_id","path","sha256","role","non_claims"],"sources":[],"entrySources":[],"inputPaths":[],"inventory":` + cliCoverageInventory() + `,"nonClaims":["CLI normalized inventory fixture does not execute tests."]},"coverageUniverse":{"schemaVersion":1,"universeId":"proofkit.cli.coverage.compose.universe","authority":"caller_owned_inventory","completenessDeclaration":"selected_owner_surfaces","ownerIds":["proofkit.cli.coverage"],"codeSurfaces":[{"surfaceId":"proofkit.cli.coverage.code","ownerId":"proofkit.cli.coverage","path":"internal/app"}],"specSurfaces":[{"surfaceId":"proofkit.cli.coverage.spec","ownerId":"proofkit.cli.coverage","path":"docs/specs/proofkit-cli-coverage/requirements.v1.json"}],"testSurfaces":[],"commandRefs":[],"nonClaims":["CLI coverage composer universe is selected-owner scope only."]},"ownerInvariantRegistry":null,"localEnvironmentPolicy":{"authority":"caller_provided","localEnvironmentClasses":["local-go"]},"options":{"scope":"graph"}}`
}

func cliImpactInputComposeInput() string {
	return `{"schemaVersion":1,"composerInputId":"proofkit.cli.impact.compose","baseRef":"main","baseCommit":"base-sha","headRef":"feature/impact","headCommit":null,"changedPathSources":[{"sourceId":"git_diff","paths":["docs/specs/proofkit-cli-impact/requirements.v1.json"]}],"baseRequirementSources":[{"schemaVersion":1,"sourceId":"proofkit.cli.impact.source","specPackagePath":"docs/specs/proofkit-cli-impact","overviewPath":"docs/specs/proofkit-cli-impact/overview.md","requirementsPath":"docs/specs/proofkit-cli-impact/requirements.v1.json","requirements":[{"requirementId":"REQ-PROOFKIT-CLI-IMPACT-001","ownerId":"proofkit.cli.impact","invariant":"CLI impact input composition preserves baseline impact routing.","claimLevel":"blocking","riskClass":"high","proofBindingRefs":["proofkit/requirement-bindings.json"],"nonClaimRefs":[],"nonClaims":["CLI impact composer fixture does not execute tests."],"lifecycle":{"state":"active","replacementRequirementIds":[],"evidenceRefs":[]},"deferral":null,"updatePolicy":{"reviewOwnerId":"proofkit.cli.impact","requiresImpactDeclaration":true,"requiresProofBindingReview":true}}],"nonClaims":["CLI impact composer base source does not own native tests."]}],"currentRequirementSources":[{"schemaVersion":1,"sourceId":"proofkit.cli.impact.source","specPackagePath":"docs/specs/proofkit-cli-impact","overviewPath":"docs/specs/proofkit-cli-impact/overview.md","requirementsPath":"docs/specs/proofkit-cli-impact/requirements.v1.json","requirements":[{"requirementId":"REQ-PROOFKIT-CLI-IMPACT-001","ownerId":"proofkit.cli.impact","invariant":"CLI impact input composition preserves changed requirement routing.","claimLevel":"blocking","riskClass":"high","proofBindingRefs":["proofkit/requirement-bindings.json"],"nonClaimRefs":[],"nonClaims":["CLI impact composer fixture does not execute tests."],"lifecycle":{"state":"active","replacementRequirementIds":[],"evidenceRefs":[]},"deferral":null,"updatePolicy":{"reviewOwnerId":"proofkit.cli.impact","requiresImpactDeclaration":true,"requiresProofBindingReview":true}}],"nonClaims":["CLI impact composer current source does not own native tests."]}],"baseCompactProofContract":{"schema_version":1,"authority_state":"canonical","contract_id":"proofkit.cli.impact.compact","contract_kind":"requirement_proof_binding","normalization_profile":"proofkit.compact.v1","non_claims":["CLI impact compact fixture does not execute witnesses."],"surface_columns":["surface_id","required_environment_classes","preconditioned_environment_classes"],"surfaces":[["proofkit.cli.impact",["local-go"],[]]],"witness_columns":["selector","environment_classes","verify_commands","resolution_order_index"],"binding_columns":["requirement_id","surface_id","scenario_id","invariant_role","owned_invariant","proof_contract_state","blocking_status","required_environment_classes","positive_witness","falsification_witness","verify_commands","mutation_resistance_state"],"bindings":[["REQ-PROOFKIT-CLI-IMPACT-001","proofkit.cli.impact","proofkit.cli.impact::scenario","contract","proofkit.cli.impact.invariant","witness_backed","blocking",["local-go"],["internal/app/cli_abi_test.go::positive_impact",["local-go"],["go test ./internal/app"],0],["internal/app/cli_abi_test.go::negative_impact",["local-go"],["go test ./internal/app"],1],["go test ./internal/app"],"no_known_advisory_gap"]]},"currentCompactProofContract":{"schema_version":1,"authority_state":"canonical","contract_id":"proofkit.cli.impact.compact","contract_kind":"requirement_proof_binding","normalization_profile":"proofkit.compact.v1","non_claims":["CLI impact compact fixture does not execute witnesses."],"surface_columns":["surface_id","required_environment_classes","preconditioned_environment_classes"],"surfaces":[["proofkit.cli.impact",["local-go"],[]]],"witness_columns":["selector","environment_classes","verify_commands","resolution_order_index"],"binding_columns":["requirement_id","surface_id","scenario_id","invariant_role","owned_invariant","proof_contract_state","blocking_status","required_environment_classes","positive_witness","falsification_witness","verify_commands","mutation_resistance_state"],"bindings":[["REQ-PROOFKIT-CLI-IMPACT-001","proofkit.cli.impact","proofkit.cli.impact::scenario","contract","proofkit.cli.impact.invariant","witness_backed","blocking",["local-go"],["internal/app/cli_abi_test.go::positive_impact",["local-go"],["go test ./internal/app"],0],["internal/app/cli_abi_test.go::negative_impact",["local-go"],["go test ./internal/app"],1],["go test ./internal/app"],"no_known_advisory_gap"]]},"proofBindingSourcePaths":["proofkit/requirement-bindings.json"],"localEnvironmentPolicy":{"localEnvironmentClasses":["local-go"]},"proofLikePathPolicy":{"ignoredProofLikePaths":[],"nonClaims":["CLI impact proof-like policy fixture does not prove proof adequacy."],"proofLikePathPatterns":[]},"generatedArtifactPolicyState":{"source":"generated_artifact_verifier","state":"complete","uncoveredGeneratedPaths":[]},"generatedArtifactRules":[],"preexistingFailures":[],"nonClaims":["CLI impact input composition fixture does not execute native tests."]}`
}

func cliWorkspaceManifestFactsInput() string {
	return `{"schemaVersion":1,"projectionId":"proofkit.cli.workspace.manifest_facts","dependencyFields":["dependencies","devDependencies"],"root":{"manifestPath":"package.json","manifest":{"name":"root","scripts":{"check":"npm run check"},"dependencies":{"@scope/api":"workspace:*"},"devDependencies":{}}},"packages":[{"manifestPath":"packages/api/package.json","packageDir":"packages/api","dirName":"api","manifest":{"name":"@scope/api","scripts":{"test":"go test ./packages/api"},"dependencies":{"@scope/core":"workspace:*"},"devDependencies":{}}},{"manifestPath":"packages/core/package.json","packageDir":"packages/core","dirName":"core","manifest":{"name":"@scope/core","scripts":{"test":"go test ./packages/core"},"dependencies":{},"devDependencies":{}}}],"nonClaims":["CLI workspace manifest fixture does not read files."]}`
}

func cliAdoptionDoctorInput() string {
	return `{"schemaVersion":1,"doctorId":"proofkit.cli.adoption-doctor","mode":"observe","checkedScope":"none","touchedRuleIds":[],"ownerRoutes":[{"routeId":"proofkit.cli.adoption-route","owner":"proofkit.cli","specPaths":["docs/specs/proofkit-consumer-infra-retirement/requirements.v1.json"],"proofBindingPaths":["proofkit/requirement-bindings.json"],"nativeWitnessRefs":["internal/app/cli_abi_test.go"],"commands":["go test ./internal/app"],"touchedRuleIds":[],"nonClaims":["CLI ABI fixture route is caller-provided."]}],"modernization":{"candidateBoundaries":[]},"childReports":[],"blockedPreconditions":[],"nonClaims":["CLI ABI fixture does not execute native witnesses."]}`
}

func cliAdoptionDoctorMissingRoutesInput() string {
	return `{"schemaVersion":1,"doctorId":"proofkit.cli.adoption-doctor","mode":"enforce-all","checkedScope":"all","touchedRuleIds":[],"ownerRoutes":[],"modernization":{"candidateBoundaries":[]},"childReports":[],"blockedPreconditions":[],"nonClaims":["CLI ABI fixture does not execute native witnesses."]}`
}
