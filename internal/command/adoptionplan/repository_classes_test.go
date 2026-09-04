package adoptionplan

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/capabilitymapadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
)

type expectedTask struct {
	commandID   string
	instruction string
	order       int
	outputKind  string
	owner       string
	taskID      string
}

var exactTasksByIntent = map[string][]expectedTask{
	IntentFresh: {
		{taskID: "proofkit.adoption-plan.author-product-contract", order: 1, owner: "consuming_repository_owner", outputKind: "candidate_behavior_statements", instruction: "Ask the consuming repository owner for observable outcomes, supported scenarios, guarantees, limits, edge cases, stable identifiers, owners, risk classes, and explicit non-claims. Do not infer product meaning from inventory filenames."},
		{taskID: "proofkit.adoption-plan.materialize-requirement-source", order: 2, owner: "consuming_repository_owner", commandID: "requirement-source-admission", outputKind: "candidate_requirement_source", instruction: "Materialize only owner-approved statements as a candidate requirement source, then admit that source before creating bindings or claiming coverage."},
		{taskID: "proofkit.adoption-plan.design-native-evidence", order: 3, owner: "consuming_repository_owner", commandID: "native-evidence-guidance", outputKind: "repository_specific_evidence_design", instruction: "For every admitted invariant, design a falsifier and native witness by resolving the referenced evidence-guidance slots under consuming-repository authority."},
	},
	IntentCodeBaseline: {
		{taskID: "proofkit.adoption-plan.materialize-capability-observations", order: 1, owner: "consuming_repository_owner", outputKind: "caller_owned_capability_map", instruction: "Use the inventory only as non-semantic routing context. Ask the repository owner to select an explicit bounded code, test, and documentation scope, including a module root when root entries are opaque; materialize current behavior only from that scope as caller-declared baseline candidates, and keep every statement candidate-only until owner review and source admission."},
		{taskID: "proofkit.adoption-plan.admit-capability-observations", order: 2, owner: "consuming_repository_owner", commandID: "capability-map-admission", outputKind: "candidate_requirement_and_binding_seeds", instruction: "Run capability-map-admission with the plan's exact capabilityMapTrustMode; preserve unresolved owner questions and do not promote candidate seeds."},
		{taskID: "proofkit.adoption-plan.review-and-author-requirements", order: 3, owner: "consuming_repository_owner", commandID: "requirement-authoring-plan", outputKind: "owner_reviewed_requirement_candidates", instruction: "Require the consuming repository owner to accept, reject, or rewrite each candidate meaning before materializing stable requirement-source changes."},
		{taskID: "proofkit.adoption-plan.design-native-evidence", order: 4, owner: "consuming_repository_owner", commandID: "native-evidence-guidance", outputKind: "repository_specific_evidence_design", instruction: "For every owner-approved invariant, design a falsifier and native witness by resolving the referenced evidence-guidance slots under consuming-repository authority."},
	},
	IntentAuditFromCode: {
		{taskID: "proofkit.adoption-plan.materialize-capability-observations", order: 1, owner: "consuming_repository_owner", outputKind: "caller_owned_capability_map", instruction: "Use the inventory only as non-semantic routing context. Ask the repository owner to select an explicit bounded code, test, and documentation scope, including a module root when root entries are opaque; inspect only that scope and materialize caller-owned capability observations without treating observed behavior as product truth."},
		{taskID: "proofkit.adoption-plan.admit-capability-observations", order: 2, owner: "consuming_repository_owner", commandID: "capability-map-admission", outputKind: "candidate_requirement_and_binding_seeds", instruction: "Run capability-map-admission with the plan's exact capabilityMapTrustMode; preserve unresolved owner questions and do not promote candidate seeds."},
		{taskID: "proofkit.adoption-plan.review-and-author-requirements", order: 3, owner: "consuming_repository_owner", commandID: "requirement-authoring-plan", outputKind: "owner_reviewed_requirement_candidates", instruction: "Require the consuming repository owner to accept, reject, or rewrite each candidate meaning before materializing stable requirement-source changes."},
		{taskID: "proofkit.adoption-plan.design-native-evidence", order: 4, owner: "consuming_repository_owner", commandID: "native-evidence-guidance", outputKind: "repository_specific_evidence_design", instruction: "For every owner-approved invariant, design a falsifier and native witness by resolving the referenced evidence-guidance slots under consuming-repository authority."},
	},
}

func TestPlanKeepsRepositoryClassesObservationalAndStackNeutral(t *testing.T) {
	repositoryClasses := []struct {
		name      string
		files     map[string]string
		wantPaths []string
		wantRoles []string
	}{
		{name: "python", files: map[string]string{"pyproject.toml": "[project]\nname = \"pilot\"\n", "requirements.txt": "example==1.0.0\n", "uv.lock": "version = 1\n"}, wantPaths: []string{"pyproject.toml", "requirements.txt", "uv.lock"}, wantRoles: []string{"ecosystem_manifest", "dependency_declaration", "dependency_lock"}},
		{name: "typescript", files: map[string]string{"package.json": "{\"name\":\"pilot\"}\n", "tsconfig.json": "{}\n"}, wantPaths: []string{"package.json", "tsconfig.json"}, wantRoles: []string{"ecosystem_manifest", "build_configuration"}},
		{name: "go", files: map[string]string{"go.mod": "module example.test/pilot\n", "go.sum": "example.test/mod v1.0.0 h1:value\n"}, wantPaths: []string{"go.mod", "go.sum"}, wantRoles: []string{"ecosystem_manifest", "dependency_lock"}},
		{name: "mixed", files: map[string]string{"package.json": "{\"name\":\"pilot\"}\n", "pyproject.toml": "[project]\nname = \"pilot\"\n"}, wantPaths: []string{"package.json", "pyproject.toml"}, wantRoles: []string{"ecosystem_manifest", "ecosystem_manifest"}},
		{name: "documentation only", files: map[string]string{"AGENTS.md": "# Instructions\n", "README.md": "# Pilot\n"}, wantPaths: []string{"AGENTS.md", "README.md"}, wantRoles: []string{"agent_instructions", "human_overview"}},
	}
	stacks := []string{"", "python_service"}
	intents := []string{IntentAuditFromCode, IntentCodeBaseline, IntentFresh}

	for _, repositoryClass := range repositoryClasses {
		t.Run(repositoryClass.name, func(t *testing.T) {
			root := t.TempDir()
			for path, content := range repositoryClass.files {
				if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0o600); err != nil {
					t.Fatalf("write %s: %v", path, err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "consumer-private-file"), []byte("opaque\n"), 0o600); err != nil {
				t.Fatalf("write unknown file: %v", err)
			}

			inventory, err := repositoryinventory.Scan(context.Background(), root)
			if err != nil {
				t.Fatalf("repositoryinventory.Scan() error = %v", err)
			}
			gotPaths := make([]string, 0, len(inventory.Entries))
			gotRoles := make([]string, 0, len(inventory.Entries))
			for _, entry := range inventory.Entries {
				gotPaths = append(gotPaths, entry.Path)
				gotRoles = append(gotRoles, entry.Role)
			}
			if !slices.Equal(gotPaths, repositoryClass.wantPaths) || !slices.Equal(gotRoles, repositoryClass.wantRoles) || inventory.Omissions.UnrecognizedCount != 1 {
				t.Fatalf("inventory paths/roles/count = %v/%v/%d, want %v/%v/1", gotPaths, gotRoles, inventory.Omissions.UnrecognizedCount, repositoryClass.wantPaths, repositoryClass.wantRoles)
			}

			for _, intent := range intents {
				for _, stack := range stacks {
					plan, err := Build(intent, inventory, stack)
					if err != nil {
						t.Fatalf("Build(%s, %q) error = %v", intent, stack, err)
					}
					if !reflect.DeepEqual(projectTasks(plan.Packet.Tasks), exactTasksByIntent[intent]) {
						t.Fatalf("Build(%s, %q) tasks = %#v, want %#v", intent, stack, projectTasks(plan.Packet.Tasks), exactTasksByIntent[intent])
					}
					assertExactTrustDeclaration(t, plan, intent)
					if stack == "" && plan.StackHint != nil {
						t.Fatalf("Build(%s) inferred stack hint %#v", intent, plan.StackHint)
					}
					if stack != "" && (plan.StackHint == nil || plan.StackHint.PresetID != stack) {
						t.Fatalf("Build(%s, %q) stack hint = %#v", intent, stack, plan.StackHint)
					}
					assertNoSemanticRequirementPayload(t, plan.JSONValue())
				}
			}
		})
	}
}

func projectTasks(tasks []Task) []expectedTask {
	result := make([]expectedTask, 0, len(tasks))
	for _, task := range tasks {
		commandID := ""
		if task.CommandID != nil {
			commandID = *task.CommandID
		}
		result = append(result, expectedTask{
			commandID: commandID, instruction: task.Instruction, order: task.Order,
			outputKind: task.OutputKind, owner: task.Owner, taskID: task.TaskID,
		})
	}
	return result
}

func assertExactTrustDeclaration(t *testing.T, plan Plan, intent string) {
	t.Helper()
	wantClass := map[string]string{
		IntentFresh:         "owner_intent_required",
		IntentCodeBaseline:  "caller_declared_code_baseline",
		IntentAuditFromCode: "untrusted_code_observation",
	}[intent]
	if plan.TrustDeclaration.Class != wantClass {
		t.Fatalf("Build(%s) trust class = %q, want %q", intent, plan.TrustDeclaration.Class, wantClass)
	}
	if intent == IntentFresh {
		if plan.TrustDeclaration.CapabilityMapTrustMode != nil {
			t.Fatalf("Build(%s) capability trust mode = %#v, want nil", intent, plan.TrustDeclaration.CapabilityMapTrustMode)
		}
		return
	}
	wantMode := map[string]string{
		IntentCodeBaseline:  capabilitymapadmission.TrustModeCodeBaseline,
		IntentAuditFromCode: capabilitymapadmission.TrustModeAuditFromCode,
	}[intent]
	if plan.TrustDeclaration.CapabilityMapTrustMode == nil || *plan.TrustDeclaration.CapabilityMapTrustMode != wantMode {
		t.Fatalf("Build(%s) capability trust mode = %#v, want %q", intent, plan.TrustDeclaration.CapabilityMapTrustMode, wantMode)
	}
}
