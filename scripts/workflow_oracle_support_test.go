package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type githubWorkflow struct {
	Name        string               `yaml:"name"`
	Env         map[string]any       `yaml:"env"`
	Concurrency *githubConcurrency   `yaml:"concurrency"`
	Defaults    *githubDefaults      `yaml:"defaults"`
	Jobs        map[string]githubJob `yaml:"jobs"`
	On          map[string]any       `yaml:"on"`
	Permissions any                  `yaml:"permissions"`
}

type githubConcurrency struct {
	Group            any `yaml:"group"`
	CancelInProgress any `yaml:"cancel-in-progress"`

	groupPresent            bool `yaml:"-"`
	cancelInProgressPresent bool `yaml:"-"`
}

type githubDefaults struct {
	Run *githubRunDefaults `yaml:"run"`
}

type githubRunDefaults struct {
	Shell            any `yaml:"shell"`
	WorkingDirectory any `yaml:"working-directory"`
}

type githubJob struct {
	ContinueOnError any             `yaml:"continue-on-error,omitempty"`
	Defaults        *githubDefaults `yaml:"defaults,omitempty"`
	Env             map[string]any  `yaml:"env"`
	Environment     any             `yaml:"environment,omitempty"`
	If              string          `yaml:"if,omitempty"`
	Name            string          `yaml:"name"`
	Needs           any             `yaml:"needs"`
	Permissions     any             `yaml:"permissions"`
	RunsOn          any             `yaml:"runs-on"`
	Steps           []githubStep    `yaml:"steps"`
	TimeoutMinutes  any             `yaml:"timeout-minutes,omitempty"`
	Uses            string          `yaml:"uses,omitempty"`

	continueOnErrorPresent bool `yaml:"-"`
	defaultsPresent        bool `yaml:"-"`
	environmentPresent     bool `yaml:"-"`
	ifPresent              bool `yaml:"-"`
	timeoutMinutesPresent  bool `yaml:"-"`
	usesPresent            bool `yaml:"-"`
}

type githubStep struct {
	ContinueOnError  any            `yaml:"continue-on-error,omitempty"`
	Env              map[string]any `yaml:"env"`
	ID               string         `yaml:"id,omitempty"`
	If               string         `yaml:"if,omitempty"`
	Name             string         `yaml:"name"`
	Run              string         `yaml:"run,omitempty"`
	Shell            any            `yaml:"shell,omitempty"`
	TimeoutMinutes   any            `yaml:"timeout-minutes,omitempty"`
	Uses             string         `yaml:"uses,omitempty"`
	With             map[string]any `yaml:"with,omitempty"`
	WorkingDirectory any            `yaml:"working-directory,omitempty"`

	continueOnErrorPresent  bool `yaml:"-"`
	idPresent               bool `yaml:"-"`
	shellPresent            bool `yaml:"-"`
	timeoutMinutesPresent   bool `yaml:"-"`
	workingDirectoryPresent bool `yaml:"-"`
	ifPresent               bool `yaml:"-"`
	runPresent              bool `yaml:"-"`
	usesPresent             bool `yaml:"-"`
	withPresent             bool `yaml:"-"`
}

type plainGithubJob githubJob

type plainGithubConcurrency githubConcurrency

func (concurrency *githubConcurrency) UnmarshalYAML(node *yaml.Node) error {
	var decoded plainGithubConcurrency
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*concurrency = githubConcurrency(decoded)
	concurrency.groupPresent = yamlMappingHasKey(node, "group")
	concurrency.cancelInProgressPresent = yamlMappingHasKey(node, "cancel-in-progress")
	return nil
}

func (job *githubJob) UnmarshalYAML(node *yaml.Node) error {
	var decoded plainGithubJob
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*job = githubJob(decoded)
	job.continueOnErrorPresent = yamlMappingHasKey(node, "continue-on-error")
	job.defaultsPresent = yamlMappingHasKey(node, "defaults")
	job.environmentPresent = yamlMappingHasKey(node, "environment")
	job.ifPresent = yamlMappingHasKey(node, "if")
	job.timeoutMinutesPresent = yamlMappingHasKey(node, "timeout-minutes")
	job.usesPresent = yamlMappingHasKey(node, "uses")
	return nil
}

type plainGithubStep githubStep

func (step *githubStep) UnmarshalYAML(node *yaml.Node) error {
	var decoded plainGithubStep
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*step = githubStep(decoded)
	step.continueOnErrorPresent = yamlMappingHasKey(node, "continue-on-error")
	step.idPresent = yamlMappingHasKey(node, "id")
	step.ifPresent = yamlMappingHasKey(node, "if")
	step.runPresent = yamlMappingHasKey(node, "run")
	step.shellPresent = yamlMappingHasKey(node, "shell")
	step.timeoutMinutesPresent = yamlMappingHasKey(node, "timeout-minutes")
	step.usesPresent = yamlMappingHasKey(node, "uses")
	step.withPresent = yamlMappingHasKey(node, "with")
	step.workingDirectoryPresent = yamlMappingHasKey(node, "working-directory")
	return nil
}

func yamlMappingHasKey(node *yaml.Node, key string) bool {
	if node.Kind != yaml.MappingNode {
		return false
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return true
		}
	}
	return false
}

func permissionWrites(raw any) bool {
	switch value := raw.(type) {
	case nil:
		return false
	case string:
		return strings.Contains(strings.ToLower(value), "write")
	case map[string]any:
		for _, permission := range value {
			if text, ok := permission.(string); ok && strings.EqualFold(strings.TrimSpace(text), "write") {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func permissionDeclaredReadOnly(raw any) bool {
	switch value := raw.(type) {
	case string:
		normalized := strings.ToLower(strings.TrimSpace(value))
		return normalized == "read-all" || normalized == "read"
	case map[string]any:
		if len(value) == 0 {
			return false
		}
		for _, permission := range value {
			text, ok := permission.(string)
			if !ok {
				return false
			}
			normalized := strings.ToLower(strings.TrimSpace(text))
			if normalized != "read" && normalized != "none" {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func readWorkflowForTest(t *testing.T, path string) githubWorkflow {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read workflow %s: %v", path, err)
	}
	if err := validateWorkflowClosedKeys(path, raw); err != nil {
		t.Fatalf("validate closed workflow %s: %v", path, err)
	}
	var workflow githubWorkflow
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("parse workflow %s: %v", path, err)
	}
	return workflow
}

func validateWorkflowClosedKeys(path string, raw []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("parse workflow YAML: %w", err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return fmt.Errorf("workflow YAML must contain exactly one document mapping")
	}
	workflow := document.Content[0]
	if err := validateClosedYAMLMapping(
		fmt.Sprintf("workflow %q", path),
		workflow,
		"name",
		"on",
		"permissions",
		"concurrency",
		"defaults",
		"env",
		"jobs",
	); err != nil {
		return err
	}
	if err := validateOptionalNestedMapping(
		fmt.Sprintf("workflow %q concurrency", path),
		yamlMappingValue(workflow, "concurrency"),
		"group",
		"cancel-in-progress",
	); err != nil {
		return err
	}
	if err := validateDefaultsMapping(
		fmt.Sprintf("workflow %q defaults", path),
		yamlMappingValue(workflow, "defaults"),
	); err != nil {
		return err
	}

	jobs := yamlMappingValue(workflow, "jobs")
	if jobs == nil {
		return fmt.Errorf("workflow %q must declare jobs", path)
	}
	if jobs.Kind != yaml.MappingNode {
		return fmt.Errorf("workflow %q jobs must be a mapping", path)
	}
	if err := validateDynamicYAMLMappingKeys(fmt.Sprintf("workflow %q jobs", path), jobs); err != nil {
		return err
	}
	seenReleaseEnvironments := make(map[string]struct{})
	for index := 0; index+1 < len(jobs.Content); index += 2 {
		jobID := jobs.Content[index].Value
		job := jobs.Content[index+1]
		if err := validateClosedYAMLMapping(
			fmt.Sprintf("workflow %q job %q", path, jobID),
			job,
			"name",
			"needs",
			"if",
			"runs-on",
			"timeout-minutes",
			"permissions",
			"env",
			"steps",
			"environment",
		); err != nil {
			return err
		}
		if environment := yamlMappingValue(job, "environment"); environment != nil {
			if err := validateOwnedReleaseEnvironment(path, jobID, environment); err != nil {
				return err
			}
			seenReleaseEnvironments[jobID] = struct{}{}
		}
		if yamlMappingValue(job, "environment") == nil && workflowAllowsReleaseEnvironments(path) &&
			(jobID == "publish" || jobID == "publish-pypi") {
			return fmt.Errorf("workflow %q job %q must declare its exact owner environment", path, jobID)
		}
		if job.Kind != yaml.MappingNode {
			return fmt.Errorf("workflow %q job %q must be a mapping", path, jobID)
		}
		if yamlMappingValue(job, "environment") != nil &&
			!workflowAllowsReleaseEnvironments(path) {
			return fmt.Errorf("workflow %q job %q contains unowned key %q", path, jobID, "environment")
		}
		steps := yamlMappingValue(job, "steps")
		if steps == nil {
			return fmt.Errorf("workflow %q job %q must declare steps", path, jobID)
		}
		if steps.Kind != yaml.SequenceNode {
			return fmt.Errorf("workflow %q job %q steps must be a sequence", path, jobID)
		}
		for stepIndex, step := range steps.Content {
			if err := validateClosedYAMLMapping(
				fmt.Sprintf("workflow %q job %q step %d", path, jobID, stepIndex),
				step,
				"name",
				"id",
				"if",
				"run",
				"uses",
				"with",
				"env",
			); err != nil {
				return err
			}
		}
	}
	if workflowAllowsReleaseEnvironments(path) && len(seenReleaseEnvironments) != 2 {
		return fmt.Errorf(
			"workflow %q release environment inventory=%v, want exact publish and publish-pypi",
			path,
			seenReleaseEnvironments,
		)
	}
	return nil
}

func workflowAllowsReleaseEnvironments(path string) bool {
	actual, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	expected, err := filepath.Abs(filepath.Join("..", ".github", "workflows", "release.yml"))
	return err == nil && actual == expected
}

func validateOwnedReleaseEnvironment(path string, jobID string, environment *yaml.Node) error {
	if !workflowAllowsReleaseEnvironments(path) {
		return fmt.Errorf("workflow %q job %q contains unowned key %q", path, jobID, "environment")
	}
	switch jobID {
	case "publish":
		if environment.Kind != yaml.ScalarNode ||
			environment.Tag != "!!str" ||
			environment.Value != "npm-production" {
			return fmt.Errorf(
				"workflow %q job %q environment must equal exact scalar npm-production",
				path,
				jobID,
			)
		}
	case "publish-pypi":
		if err := validateClosedYAMLMapping(
			fmt.Sprintf("workflow %q job %q environment", path, jobID),
			environment,
			"name",
			"url",
		); err != nil {
			return err
		}
		name := yamlMappingValue(environment, "name")
		url := yamlMappingValue(environment, "url")
		if name == nil || name.Kind != yaml.ScalarNode || name.Tag != "!!str" || name.Value != "pypi" ||
			url == nil || url.Kind != yaml.ScalarNode || url.Tag != "!!str" ||
			url.Value != "https://pypi.org/p/agentic-proofkit" {
			return fmt.Errorf(
				"workflow %q job %q environment must equal exact pypi owner mapping",
				path,
				jobID,
			)
		}
	default:
		return fmt.Errorf("workflow %q job %q contains unowned key %q", path, jobID, "environment")
	}
	return nil
}

func validateDefaultsMapping(label string, defaults *yaml.Node) error {
	if defaults == nil || defaults.Kind == yaml.ScalarNode && defaults.Tag == "!!null" {
		return nil
	}
	if err := validateClosedYAMLMapping(label, defaults, "run"); err != nil {
		return err
	}
	return validateOptionalNestedMapping(
		label+" run",
		yamlMappingValue(defaults, "run"),
		"shell",
		"working-directory",
	)
}

func validateOptionalNestedMapping(label string, node *yaml.Node, allowed ...string) error {
	if node == nil || node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		return nil
	}
	return validateClosedYAMLMapping(label, node, allowed...)
}

func validateClosedYAMLMapping(label string, node *yaml.Node, allowed ...string) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("%s must be a mapping", label)
	}
	allowedKeys := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedKeys[key] = struct{}{}
	}
	seen := make(map[string]struct{}, len(node.Content)/2)
	for index := 0; index+1 < len(node.Content); index += 2 {
		keyNode := node.Content[index]
		if keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" {
			return fmt.Errorf("%s contains a non-string key", label)
		}
		key := keyNode.Value
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("%s contains duplicate key %q", label, key)
		}
		seen[key] = struct{}{}
		if _, admitted := allowedKeys[key]; !admitted {
			return fmt.Errorf("%s contains unowned key %q", label, key)
		}
	}
	return nil
}

func validateDynamicYAMLMappingKeys(label string, node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("%s must be a mapping", label)
	}
	seen := make(map[string]struct{}, len(node.Content)/2)
	for index := 0; index+1 < len(node.Content); index += 2 {
		keyNode := node.Content[index]
		if keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" {
			return fmt.Errorf("%s contains a non-string key", label)
		}
		key := keyNode.Value
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("%s contains duplicate key %q", label, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func yamlMappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}

func cloneWorkflow(t *testing.T, workflow githubWorkflow) githubWorkflow {
	t.Helper()
	content, err := yaml.Marshal(workflow)
	if err != nil {
		t.Fatal(err)
	}
	var cloned githubWorkflow
	if err := yaml.Unmarshal(content, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func withString(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, ok := values[key].(string)
	if !ok {
		return ""
	}
	return value
}

func normalizedExpression(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.TrimPrefix(normalized, "${{")
	normalized = strings.TrimSuffix(normalized, "}}")
	return strings.TrimSpace(normalized)
}

func canonicalWorkflowExpression(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "${{") && strings.HasSuffix(value, "}}") {
		value = strings.TrimSpace(value[3 : len(value)-2])
	}
	var output strings.Builder
	quote := rune(0)
	escaped := false
	for _, character := range value {
		if quote != 0 {
			output.WriteRune(character)
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' && quote == '"' {
				escaped = true
				continue
			}
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			output.WriteRune(character)
			continue
		}
		if character == ' ' || character == '\t' || character == '\n' || character == '\r' {
			continue
		}
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		output.WriteRune(character)
	}
	if quote != 0 {
		return ""
	}
	return output.String()
}

func uniqueStepIndex(steps []githubStep, name string) (int, error) {
	found := -1
	for index, step := range steps {
		if step.Name != name {
			continue
		}
		if found >= 0 {
			return -1, fmt.Errorf("step %q must be unique", name)
		}
		found = index
	}
	return found, nil
}
