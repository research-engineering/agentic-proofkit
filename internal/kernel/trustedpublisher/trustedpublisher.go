package trustedpublisher

import (
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

type Identity struct {
	Environment string `json:"environment"`
	Job         string `json:"job"`
	ProjectName string `json:"projectName"`
	Provider    string `json:"provider"`
	Registry    string `json:"registry"`
	Repository  string `json:"repository"`
	WorkflowRef string `json:"workflowRef"`
}

type Expected struct {
	Environment string
	Job         string
	ProjectName string
	Provider    string
	Registry    string
	Repository  string
	WorkflowRef string
}

const (
	ExistingByteMatch   = "existing_byte_match"
	Mixed               = "mixed"
	PublishedByWorkflow = "published_by_workflow"
)

func AdmitPublicationMode(raw string, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	switch value {
	case ExistingByteMatch, Mixed, PublishedByWorkflow:
		return value, nil
	default:
		return "", fmt.Errorf("%s must be existing_byte_match, mixed, or published_by_workflow", context)
	}
}

func PublicationModeRequiresIdentity(raw string, context string) (bool, error) {
	mode, err := AdmitPublicationMode(raw, context)
	if err != nil {
		return false, err
	}
	return mode == PublishedByWorkflow || mode == Mixed, nil
}

func Admit(identity Identity, expected Expected, context string) (Identity, error) {
	normalized := Identity{}
	fields := []struct {
		name  string
		raw   string
		write func(string)
		want  string
	}{
		{name: "environment", raw: identity.Environment, write: func(value string) { normalized.Environment = value }, want: expected.Environment},
		{name: "job", raw: identity.Job, write: func(value string) { normalized.Job = value }, want: expected.Job},
		{name: "projectName", raw: identity.ProjectName, write: func(value string) { normalized.ProjectName = value }, want: expected.ProjectName},
		{name: "provider", raw: identity.Provider, write: func(value string) { normalized.Provider = value }, want: expected.Provider},
		{name: "registry", raw: identity.Registry, write: func(value string) { normalized.Registry = value }, want: expected.Registry},
		{name: "repository", raw: identity.Repository, write: func(value string) { normalized.Repository = value }, want: expected.Repository},
		{name: "workflowRef", raw: identity.WorkflowRef, write: func(value string) { normalized.WorkflowRef = value }, want: ""},
	}
	for _, field := range fields {
		value, err := admit.NonEmptyText(field.raw, fmt.Sprintf("%s trustedPublisher.%s", context, field.name))
		if err != nil {
			return Identity{}, err
		}
		if field.want != "" && value != field.want {
			return Identity{}, fmt.Errorf("%s trustedPublisher.%s = %q, want %q", context, field.name, value, field.want)
		}
		field.write(value)
	}
	if expected.WorkflowRef == "" {
		return Identity{}, fmt.Errorf("%s trustedPublisher expected workflowRef is empty", context)
	}
	if normalized.WorkflowRef != expected.WorkflowRef {
		return Identity{}, fmt.Errorf("%s trustedPublisher.workflowRef = %q, want %q", context, normalized.WorkflowRef, expected.WorkflowRef)
	}
	return normalized, nil
}

func FromEnv(prefix string, expected Expected, getenv func(string) string) (Identity, error) {
	return Admit(Identity{
		Environment: getenv(prefix + "_ENVIRONMENT"),
		Job:         getenv(prefix + "_JOB"),
		ProjectName: getenv(prefix + "_PROJECT"),
		Provider:    getenv(prefix + "_PROVIDER"),
		Registry:    getenv(prefix + "_REGISTRY"),
		Repository:  getenv(prefix + "_REPOSITORY"),
		WorkflowRef: getenv(prefix + "_WORKFLOW_REF"),
	}, expected, prefix)
}

func RepositorySlugFromGitHubURL(rawURL string) (string, error) {
	value, err := admit.NonEmptyText(rawURL, "repository.url")
	if err != nil {
		return "", err
	}
	value = strings.TrimPrefix(value, "git+")
	value = strings.TrimSuffix(value, ".git")
	value = strings.TrimPrefix(value, "https://github.com/")
	value = strings.TrimPrefix(value, "git@github.com:")
	if strings.Count(value, "/") != 1 || strings.Contains(value, "://") || strings.Contains(value, "@") {
		return "", fmt.Errorf("repository.url must identify one GitHub owner/repository slug")
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if _, err := admit.RuleID(strings.ReplaceAll(part, "-", "_"), "repository slug component"); err != nil {
			return "", fmt.Errorf("repository.url must identify a stable GitHub owner/repository slug")
		}
	}
	return value, nil
}
