package trustedpublisher

import (
	"strings"
	"testing"
)

func TestAdmitRequiresExpectedImmutableTuple(t *testing.T) {
	expected := Expected{
		Environment: "npm-production",
		Job:         "publish",
		ProjectName: "agentic-proofkit",
		Provider:    "npm",
		Registry:    "https://registry.npmjs.org",
		Repository:  "research-engineering/agentic-proofkit",
		WorkflowRef: "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/tags/v1.2.3",
	}
	identity := Identity{
		Environment: "npm-production",
		Job:         "publish",
		ProjectName: "agentic-proofkit",
		Provider:    "npm",
		Registry:    "https://registry.npmjs.org",
		Repository:  "research-engineering/agentic-proofkit",
		WorkflowRef: "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/tags/v1.2.3",
	}
	admitted, err := Admit(identity, expected, "npm")
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	if admitted != identity {
		t.Fatalf("Admit() = %#v, want %#v", admitted, identity)
	}
}

func TestAdmitRejectsMissingWrongAndSecretShapedFields(t *testing.T) {
	expected := Expected{
		Environment: "pypi",
		Job:         "publish-pypi",
		ProjectName: "agentic-proofkit",
		Provider:    "pypi",
		Registry:    "https://pypi.org",
		Repository:  "research-engineering/agentic-proofkit",
		WorkflowRef: "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/tags/v1.2.3",
	}
	valid := Identity{
		Environment: "pypi",
		Job:         "publish-pypi",
		ProjectName: "agentic-proofkit",
		Provider:    "pypi",
		Registry:    "https://pypi.org",
		Repository:  "research-engineering/agentic-proofkit",
		WorkflowRef: "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/tags/v1.2.3",
	}
	cases := []struct {
		name   string
		mutate func(*Identity)
		want   string
	}{
		{name: "missing workflow ref", mutate: func(identity *Identity) { identity.WorkflowRef = "" }, want: "workflowRef"},
		{name: "wrong environment", mutate: func(identity *Identity) { identity.Environment = "release" }, want: "environment"},
		{name: "wrong workflow", mutate: func(identity *Identity) {
			identity.WorkflowRef = "research-engineering/agentic-proofkit/.github/workflows/other.yml@refs/tags/v1.2.3"
		}, want: "workflowRef"},
		{name: "branch ref", mutate: func(identity *Identity) {
			identity.WorkflowRef = "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/heads/main"
		}, want: "workflowRef"},
		{name: "secret-shaped project", mutate: func(identity *Identity) { identity.ProjectName = "token=abcdefghijk" }, want: "secret-like"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			identity := valid
			item.mutate(&identity)
			_, err := Admit(identity, expected, "pypi")
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Admit() error = %v, want %q", err, item.want)
			}
		})
	}
}

func TestPublicationModeAdmission(t *testing.T) {
	cases := []struct {
		mode        string
		wantRequire bool
	}{
		{mode: PublishedByWorkflow, wantRequire: true},
		{mode: Mixed, wantRequire: true},
		{mode: ExistingByteMatch, wantRequire: false},
	}
	for _, item := range cases {
		t.Run(item.mode, func(t *testing.T) {
			requires, err := PublicationModeRequiresIdentity(item.mode, "publicationMode")
			if err != nil {
				t.Fatalf("PublicationModeRequiresIdentity() error = %v", err)
			}
			if requires != item.wantRequire {
				t.Fatalf("requires=%v, want %v", requires, item.wantRequire)
			}
		})
	}
	if _, err := PublicationModeRequiresIdentity("published-by-workflow", "publicationMode"); err == nil {
		t.Fatalf("PublicationModeRequiresIdentity() accepted unknown publication mode")
	}
}

func TestRepositorySlugFromGitHubURL(t *testing.T) {
	cases := []string{
		"git+https://github.com/research-engineering/agentic-proofkit.git",
		"https://github.com/research-engineering/agentic-proofkit",
		"git@github.com:research-engineering/agentic-proofkit.git",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			slug, err := RepositorySlugFromGitHubURL(raw)
			if err != nil {
				t.Fatalf("RepositorySlugFromGitHubURL() error = %v", err)
			}
			if slug != "research-engineering/agentic-proofkit" {
				t.Fatalf("slug=%q, want research-engineering/agentic-proofkit", slug)
			}
		})
	}
	if _, err := RepositorySlugFromGitHubURL("https://example.test/research-engineering/agentic-proofkit"); err == nil {
		t.Fatalf("RepositorySlugFromGitHubURL() accepted non-GitHub URL")
	}
}
