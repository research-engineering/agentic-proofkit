package admit

import "testing"

func TestPathPrivacyRejectsEmbeddedUnambiguousSignatures(t *testing.T) {
	selected := 0
	for _, fixture := range ReportVisibleRedactionFixtures() {
		switch fixture.Name {
		case "github_pat", "github_ghp", "slack_token", "gitlab_token", "jwt_like", "openai_key":
		default:
			continue
		}
		selected++
		value := "inputs/prefix" + fixture.Input + "suffix.json"
		if !ContainsSecretLikePathValue(value) {
			t.Fatalf("embedded %s signature was not recognized", fixture.Name)
		}
		if _, err := SafeRepoRelativePath(value, "input path"); err == nil {
			t.Fatalf("embedded %s signature reached canonical path admission", fixture.Name)
		}
		if _, err := NonEmptyPathText(value, "path text"); err == nil {
			t.Fatalf("embedded %s signature reached report-visible path text", fixture.Name)
		}
	}
	if selected != 6 {
		t.Fatalf("signature fixture count=%d, want 6", selected)
	}
	for _, value := range []string{"inputs/task-requirements.json", "inputs/task-validation.json", "docs/risk-assessment.md"} {
		if _, err := MaterializedInputPath(value, "prepared input"); err != nil {
			t.Fatalf("ordinary path rejected: %v", err)
		}
		if _, err := NonEmptyPathText(value, "path text"); err != nil {
			t.Fatal(err)
		}
		if _, err := NonEmptyText(value, "scalar text"); err == nil {
			t.Fatal("path admission accidentally weakened the independent scalar policy")
		}
	}
}

func TestMaterializedInputPathDoesNotAdmitStdin(t *testing.T) {
	if _, err := MaterializedInputPath("-", "prepared input"); err == nil {
		t.Fatal("prepared file became stdin")
	}
	if _, err := SafeRepoRelativePath("-", "ordinary target"); err != nil {
		t.Fatal("ordinary path policy was unnecessarily tightened")
	}
}
