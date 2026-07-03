package main

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const mergeSatisfyingProducerEnv = "PROOFKIT_MERGE_SATISFYING_PRODUCER"

type packageGateWorkflowExpectation struct {
	label                              string
	jobID                              string
	stepName                           string
	runCommand                         string
	mustFollowSteps                    []workflowStepExpectation
	mustPrecedeStepNames               []string
	requireReadOnlyWorkflowPermissions bool
	requiredNeeds                      map[string][]string
	requiredTriggers                   []workflowTriggerExpectation
}

type workflowStepExpectation struct {
	name       string
	runCommand string
}

type workflowTriggerExpectation struct {
	event string
	path  []string
	value string
}

type githubWorkflow struct {
	Env         map[string]any       `yaml:"env"`
	Jobs        map[string]githubJob `yaml:"jobs"`
	On          map[string]any       `yaml:"on"`
	Permissions any                  `yaml:"permissions"`
}

type githubJob struct {
	ContinueOnError any            `yaml:"continue-on-error"`
	Env             map[string]any `yaml:"env"`
	If              string         `yaml:"if"`
	Needs           any            `yaml:"needs"`
	Permissions     any            `yaml:"permissions"`
	Steps           []githubStep   `yaml:"steps"`
}

type githubStep struct {
	ContinueOnError any            `yaml:"continue-on-error"`
	Env             map[string]any `yaml:"env"`
	If              string         `yaml:"if"`
	Name            string         `yaml:"name"`
	Run             string         `yaml:"run"`
	Uses            string         `yaml:"uses"`
}

func assertPackageGateWorkflowFile(t *testing.T, path string, expectation packageGateWorkflowExpectation) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := validatePackageGateWorkflow(raw, expectation); err != nil {
		t.Fatalf("%s package gate workflow: %v", expectation.label, err)
	}
}

func validatePackageGateWorkflow(raw []byte, expectation packageGateWorkflowExpectation) error {
	var workflow githubWorkflow
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		return fmt.Errorf("parse workflow YAML: %w", err)
	}
	if len(workflow.Jobs) == 0 {
		return fmt.Errorf("workflow must declare jobs")
	}
	if err := validateTriggers(workflow.On, expectation.requiredTriggers); err != nil {
		return err
	}
	if err := validateRequiredNeeds(workflow.Jobs, expectation.requiredNeeds); err != nil {
		return err
	}
	if hasForbiddenProducerOptIn(workflow) {
		return fmt.Errorf("workflow must not set %s in env or run commands", mergeSatisfyingProducerEnv)
	}
	if expectation.requireReadOnlyWorkflowPermissions && !permissionDeclaredReadOnly(workflow.Permissions) {
		return fmt.Errorf("workflow-level permissions must be explicitly read-only for package-gate evidence")
	}
	if permissionWrites(workflow.Permissions) {
		return fmt.Errorf("workflow-level permissions must not grant write scopes to package-gate evidence")
	}
	job, ok := workflow.Jobs[expectation.jobID]
	if !ok {
		return fmt.Errorf("job %q not found", expectation.jobID)
	}
	if disabledExpression(job.If) {
		return fmt.Errorf("job %q is disabled by if expression", expectation.jobID)
	}
	if truthy(job.ContinueOnError) {
		return fmt.Errorf("job %q must not continue on package-gate errors", expectation.jobID)
	}
	if needs := needsList(job.Needs); len(needs) > 0 {
		for _, need := range needs {
			if _, ok := workflow.Jobs[need]; !ok {
				return fmt.Errorf("job %q needs unknown job %q", expectation.jobID, need)
			}
		}
	}
	if permissionWrites(job.Permissions) {
		return fmt.Errorf("job %q permissions must not grant write scopes to package-gate evidence", expectation.jobID)
	}
	gateIndex := -1
	for index, step := range job.Steps {
		if step.Name != expectation.stepName {
			continue
		}
		if gateIndex >= 0 {
			return fmt.Errorf("job %q has duplicate package gate step %q", expectation.jobID, expectation.stepName)
		}
		gateIndex = index
		if disabledExpression(step.If) {
			return fmt.Errorf("step %q is disabled by if expression", expectation.stepName)
		}
		if truthy(step.ContinueOnError) {
			return fmt.Errorf("step %q must not continue on package-gate errors", expectation.stepName)
		}
		if step.Uses != "" {
			return fmt.Errorf("step %q must be a run step, got uses=%q", expectation.stepName, step.Uses)
		}
		if singleLineRun(step.Run) != expectation.runCommand {
			return fmt.Errorf("step %q run=%q, want %q", expectation.stepName, singleLineRun(step.Run), expectation.runCommand)
		}
	}
	if gateIndex < 0 {
		return fmt.Errorf("step %q not found in job %q", expectation.stepName, expectation.jobID)
	}
	for _, priorExpectation := range expectation.mustFollowSteps {
		priorStep := priorExpectation.name
		priorIndex, err := uniqueStepIndex(job.Steps, priorStep)
		if err != nil {
			return err
		}
		if priorIndex < 0 {
			return fmt.Errorf("required prior step %q not found in job %q", priorStep, expectation.jobID)
		}
		if priorIndex >= gateIndex {
			return fmt.Errorf("package gate step %q must follow %q", expectation.stepName, priorStep)
		}
		prior := job.Steps[priorIndex]
		if disabledExpression(prior.If) {
			return fmt.Errorf("required prior step %q is disabled by if expression", priorStep)
		}
		if truthy(prior.ContinueOnError) {
			return fmt.Errorf("required prior step %q must not continue on package-gate errors", priorStep)
		}
		if priorExpectation.runCommand != "" {
			if prior.Uses != "" {
				return fmt.Errorf("required prior step %q must be a run step, got uses=%q", priorStep, prior.Uses)
			}
			if singleLineRun(prior.Run) != priorExpectation.runCommand {
				return fmt.Errorf("required prior step %q run=%q, want %q", priorStep, singleLineRun(prior.Run), priorExpectation.runCommand)
			}
		}
	}
	for _, laterStep := range expectation.mustPrecedeStepNames {
		laterIndex, err := uniqueStepIndex(job.Steps, laterStep)
		if err != nil {
			return err
		}
		if laterIndex < 0 {
			return fmt.Errorf("required later step %q not found in job %q", laterStep, expectation.jobID)
		}
		if laterIndex <= gateIndex {
			return fmt.Errorf("package gate step %q must precede %q", expectation.stepName, laterStep)
		}
		later := job.Steps[laterIndex]
		if disabledExpression(later.If) {
			return fmt.Errorf("required later step %q is disabled by if expression", laterStep)
		}
		if truthy(later.ContinueOnError) {
			return fmt.Errorf("required later step %q must not continue on package-gate errors", laterStep)
		}
		if usesAlwaysStatusCheck(later.If) && !requiresPriorStepSuccess(later.If) {
			return fmt.Errorf("required later step %q uses always() and must explicitly require success()", laterStep)
		}
	}
	return nil
}

func validateTriggers(on map[string]any, expectations []workflowTriggerExpectation) error {
	for _, expectation := range expectations {
		eventValue, ok := on[expectation.event]
		if !ok {
			return fmt.Errorf("workflow trigger %q not found", expectation.event)
		}
		if len(expectation.path) == 0 && expectation.value == "" {
			continue
		}
		value := nestedValue(eventValue, expectation.path)
		if expectation.value == "" {
			if value == nil {
				return fmt.Errorf("workflow trigger %q path %q not found", expectation.event, strings.Join(expectation.path, "."))
			}
			continue
		}
		values := stringValues(value)
		if !containsString(values, expectation.value) {
			return fmt.Errorf("workflow trigger %q path %q=%#v, want %q", expectation.event, strings.Join(expectation.path, "."), values, expectation.value)
		}
	}
	return nil
}

func validateRequiredNeeds(jobs map[string]githubJob, required map[string][]string) error {
	for jobID, expectedNeeds := range required {
		job, ok := jobs[jobID]
		if !ok {
			return fmt.Errorf("required workflow job %q not found", jobID)
		}
		if disabledExpression(job.If) {
			return fmt.Errorf("required workflow job %q is disabled by if expression", jobID)
		}
		actualNeeds := needsList(job.Needs)
		for _, expectedNeed := range expectedNeeds {
			if !containsString(actualNeeds, expectedNeed) {
				return fmt.Errorf("workflow job %q needs=%#v, want dependency on %q", jobID, actualNeeds, expectedNeed)
			}
			if _, ok := jobs[expectedNeed]; !ok {
				return fmt.Errorf("workflow job %q needs unknown job %q", jobID, expectedNeed)
			}
			if usesAlwaysStatusCheck(job.If) && !requiresSuccessfulNeed(job.If, expectedNeed) {
				return fmt.Errorf("workflow job %q uses always() and must explicitly require needs.%s.result == 'success'", jobID, expectedNeed)
			}
		}
	}
	return nil
}

func hasForbiddenProducerOptIn(workflow githubWorkflow) bool {
	if envContainsKey(workflow.Env, mergeSatisfyingProducerEnv) {
		return true
	}
	for _, job := range workflow.Jobs {
		if envContainsKey(job.Env, mergeSatisfyingProducerEnv) {
			return true
		}
		for _, step := range job.Steps {
			if envContainsKey(step.Env, mergeSatisfyingProducerEnv) {
				return true
			}
			if strings.Contains(step.Run, mergeSatisfyingProducerEnv) {
				return true
			}
		}
	}
	return false
}

func envContainsKey(env map[string]any, key string) bool {
	for name := range env {
		if strings.EqualFold(name, key) {
			return true
		}
	}
	return false
}

func disabledExpression(value string) bool {
	normalized := normalizedExpression(value)
	return normalized == "false" || normalized == "0"
}

func usesAlwaysStatusCheck(value string) bool {
	return strings.Contains(removeExpressionWhitespace(normalizedExpression(value)), "always()")
}

func requiresSuccessfulNeed(value string, need string) bool {
	normalized := removeExpressionWhitespace(normalizedExpression(value))
	token := "needs." + need + ".result=='success'"
	return statusGuardExpressionAdmitted(normalized) &&
		(hasConjunct(normalized, token) || hasAllowedOptionalNeedGuard(normalized, need, token))
}

func requiresPriorStepSuccess(value string) bool {
	normalized := removeExpressionWhitespace(normalizedExpression(value))
	return statusGuardExpressionAdmitted(normalized) && hasConjunct(normalized, "success()")
}

func statusGuardExpressionAdmitted(normalized string) bool {
	withoutAllowedDisjunctions := normalized
	for _, guard := range allowedStatusDisjunctions() {
		withoutAllowedDisjunctions = strings.ReplaceAll(withoutAllowedDisjunctions, guard, "")
	}
	if strings.Contains(withoutAllowedDisjunctions, "||") ||
		strings.Contains(normalized, "failure()") ||
		strings.Contains(normalized, "cancelled()") {
		return false
	}
	return true
}

func allowedStatusDisjunctions() []string {
	return []string{
		"(github.event_name=='push'||inputs.mode=='publish')",
		"(vars.proofkit_enable_pypi_publish!='true'||needs.publish-pypi.result=='success')",
		"(vars.proofkit_enable_github_attestations!='true'||github.event.repository.private==true||needs.release-attestations.result=='success')",
	}
}

func hasAllowedOptionalNeedGuard(normalized string, need string, token string) bool {
	switch need {
	case "publish-pypi":
		return strings.Contains(normalized, "(vars.proofkit_enable_pypi_publish!='true'||"+token+")")
	case "release-attestations":
		return strings.Contains(normalized, "(vars.proofkit_enable_github_attestations!='true'||github.event.repository.private==true||"+token+")")
	default:
		return false
	}
}

func hasConjunct(normalized string, token string) bool {
	return normalized == token ||
		strings.HasPrefix(normalized, token+"&&") ||
		strings.Contains(normalized, "&&"+token+"&&") ||
		strings.HasSuffix(normalized, "&&"+token)
}

func removeExpressionWhitespace(value string) string {
	return strings.Join(strings.Fields(value), "")
}

func needsList(raw any) []string {
	switch value := raw.(type) {
	case nil:
		return nil
	case string:
		return []string{value}
	case []any:
		result := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		sort.Strings(result)
		return result
	default:
		return nil
	}
}

func nestedValue(raw any, path []string) any {
	value := raw
	for _, key := range path {
		record, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = record[key]
	}
	return value
}

func stringValues(raw any) []string {
	switch value := raw.(type) {
	case nil:
		return nil
	case string:
		return []string{value}
	case []any:
		result := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		sort.Strings(result)
		return result
	default:
		return nil
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
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

func truthy(raw any) bool {
	switch value := raw.(type) {
	case bool:
		return value
	case string:
		return normalizedExpression(value) == "true"
	default:
		return false
	}
}

func normalizedExpression(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.TrimPrefix(normalized, "${{")
	normalized = strings.TrimSuffix(normalized, "}}")
	return strings.TrimSpace(normalized)
}

func singleLineRun(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.ContainsAny(trimmed, "\n\r") {
		return trimmed
	}
	return trimmed
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

func TestPackageGateWorkflowOracleRejectsDisabledAndShadowedEvidence(t *testing.T) {
	expectation := packageGateWorkflowExpectation{
		label:                "fixture",
		jobID:                "gate",
		stepName:             "Run package gate",
		runCommand:           "npm run check",
		mustPrecedeStepNames: []string{"Upload evidence"},
		requiredTriggers:     []workflowTriggerExpectation{{event: "pull_request"}},
	}
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "missing trigger",
			yaml: `
on:
  push:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "workflow trigger \"pull_request\" not found",
		},
		{
			name: "disabled job",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    if: ${{ false }}
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "job \"gate\" is disabled",
		},
		{
			name: "continue on error job",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    continue-on-error: true
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "must not continue",
		},
		{
			name: "disabled step",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        if: false
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "step \"Run package gate\" is disabled",
		},
		{
			name: "continue on error step",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        continue-on-error: true
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "must not continue",
		},
		{
			name: "continue on error expression variant",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        continue-on-error: ${{true}}
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "must not continue",
		},
		{
			name: "wrong command contains package gate text",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: echo npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "want \"npm run check\"",
		},
		{
			name: "compound command",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: npm run check || true
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "want \"npm run check\"",
		},
		{
			name: "multiline command masquerading as package gate",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: |
          npm run
          check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "want \"npm run check\"",
		},
		{
			name: "shadowed gate in wrong job",
			yaml: `
on:
  pull_request:
jobs:
  shadow:
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        run: echo upload
  gate:
    steps:
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "step \"Run package gate\" not found in job \"gate\"",
		},
		{
			name: "producer opt-in env",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        env:
          PROOFKIT_MERGE_SATISFYING_PRODUCER: "true"
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "must not set PROOFKIT_MERGE_SATISFYING_PRODUCER",
		},
		{
			name: "evidence before gate",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Upload evidence
        run: echo upload
      - name: Run package gate
        run: npm run check
`,
			wantErr: "must precede",
		},
		{
			name: "later evidence continues on error",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        continue-on-error: true
        run: echo upload
`,
			wantErr: "required later step \"Upload evidence\" must not continue",
		},
		{
			name: "later evidence always without success",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        if: ${{ always() }}
        run: echo upload
`,
			wantErr: "required later step \"Upload evidence\" uses always()",
		},
		{
			name: "later evidence success bypass",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        if: ${{ always() && (success() || true) }}
        run: echo upload
`,
			wantErr: "required later step \"Upload evidence\" uses always()",
		},
		{
			name: "later evidence quoted success string",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        if: ${{ always() && contains('success()', 'success()') }}
        run: echo upload
`,
			wantErr: "required later step \"Upload evidence\" uses always()",
		},
		{
			name: "disabled later evidence",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        if: false
        run: echo upload
`,
			wantErr: "required later step \"Upload evidence\" is disabled",
		},
		{
			name: "unknown need",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    needs: missing
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "needs unknown job",
		},
		{
			name: "write permissions",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    permissions:
      contents: write
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "permissions must not grant write scopes",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			err := validatePackageGateWorkflow([]byte(item.yaml), expectation)
			if err == nil || !strings.Contains(err.Error(), item.wantErr) {
				t.Fatalf("validatePackageGateWorkflow() error=%v, want %q", err, item.wantErr)
			}
		})
	}
}

func TestPackageGateWorkflowOracleAdmitsLaterAlwaysWithSuccess(t *testing.T) {
	expectation := packageGateWorkflowExpectation{
		label:                "fixture",
		jobID:                "gate",
		stepName:             "Run package gate",
		runCommand:           "npm run check",
		mustPrecedeStepNames: []string{"Upload evidence"},
		requiredTriggers:     []workflowTriggerExpectation{{event: "pull_request"}},
	}
	err := validatePackageGateWorkflow([]byte(`
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        if: ${{ always() && success() }}
        run: echo upload
`), expectation)
	if err != nil {
		t.Fatalf("validatePackageGateWorkflow() error=%v, want admitted success-gated later step", err)
	}
}

func TestPackageGateWorkflowOracleRejectsMissingWorkflowPermissionFloor(t *testing.T) {
	expectation := packageGateWorkflowExpectation{
		label:                              "fixture",
		jobID:                              "gate",
		stepName:                           "Run package gate",
		runCommand:                         "npm run check",
		mustPrecedeStepNames:               []string{"Upload evidence"},
		requireReadOnlyWorkflowPermissions: true,
		requiredTriggers:                   []workflowTriggerExpectation{{event: "pull_request"}},
	}
	err := validatePackageGateWorkflow([]byte(`
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        run: echo upload
`), expectation)
	if err == nil || !strings.Contains(err.Error(), "permissions must be explicitly read-only") {
		t.Fatalf("validatePackageGateWorkflow() error=%v, want explicit permission floor failure", err)
	}
}

func TestPackageGateWorkflowOracleRejectsLateRequiredPriorStep(t *testing.T) {
	expectation := packageGateWorkflowExpectation{
		label:      "fixture",
		jobID:      "gate",
		stepName:   "Verify release closeout",
		runCommand: "npm run release:closeout",
		mustFollowSteps: []workflowStepExpectation{
			{name: "Run semantic tests", runCommand: "go test ./internal/command/..."},
		},
		requiredTriggers: []workflowTriggerExpectation{{event: "pull_request"}},
	}
	err := validatePackageGateWorkflow([]byte(`
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Verify release closeout
        run: npm run release:closeout
      - name: Run semantic tests
        run: go test ./internal/command/...
`), expectation)
	if err == nil || !strings.Contains(err.Error(), "must follow") {
		t.Fatalf("validatePackageGateWorkflow() error=%v, want prior-step ordering failure", err)
	}
}

func TestPackageGateWorkflowOracleRejectsWrongPriorStepCommand(t *testing.T) {
	expectation := packageGateWorkflowExpectation{
		label:      "fixture",
		jobID:      "gate",
		stepName:   "Verify release closeout",
		runCommand: "npm run release:closeout",
		mustFollowSteps: []workflowStepExpectation{
			{name: "Run semantic tests", runCommand: "go test ./internal/command/..."},
		},
		requiredTriggers: []workflowTriggerExpectation{{event: "pull_request"}},
	}
	err := validatePackageGateWorkflow([]byte(`
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run semantic tests
        run: true
      - name: Verify release closeout
        run: npm run release:closeout
`), expectation)
	if err == nil || !strings.Contains(err.Error(), "want \"go test ./internal/command/...\"") {
		t.Fatalf("validatePackageGateWorkflow() error=%v, want exact prior-step command failure", err)
	}
}

func TestPackageGateWorkflowOracleRejectsDuplicatePriorStepName(t *testing.T) {
	expectation := packageGateWorkflowExpectation{
		label:      "fixture",
		jobID:      "gate",
		stepName:   "Verify release closeout",
		runCommand: "npm run release:closeout",
		mustFollowSteps: []workflowStepExpectation{
			{name: "Run semantic tests", runCommand: "go test ./internal/command/..."},
		},
		mustPrecedeStepNames: []string{"Upload evidence"},
		requiredTriggers:     []workflowTriggerExpectation{{event: "pull_request"}},
	}
	err := validatePackageGateWorkflow([]byte(`
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run semantic tests
        run: go test ./internal/command/...
      - name: Verify release closeout
        run: npm run release:closeout
      - name: Run semantic tests
        run: go test ./internal/command/...
      - name: Upload evidence
        run: echo upload
`), expectation)
	if err == nil || !strings.Contains(err.Error(), "must be unique") {
		t.Fatalf("validatePackageGateWorkflow() error=%v, want duplicate prior-step failure", err)
	}
}

func TestPackageGateWorkflowOracleRejectsAlwaysWithoutNeedSuccess(t *testing.T) {
	expectation := packageGateWorkflowExpectation{
		label:         "fixture",
		jobID:         "publish",
		stepName:      "Run package gate",
		runCommand:    "npm run check",
		requiredNeeds: map[string][]string{"publish": []string{"candidate"}},
	}
	err := validatePackageGateWorkflow([]byte(`
on:
  push:
jobs:
  candidate:
    steps:
      - name: Build
        run: npm run check
  publish:
    needs: candidate
    if: ${{ always() }}
    steps:
      - name: Run package gate
        run: npm run check
`), expectation)
	if err == nil || !strings.Contains(err.Error(), "needs.candidate.result == 'success'") {
		t.Fatalf("validatePackageGateWorkflow() error=%v, want missing success predicate failure", err)
	}
}

func TestPackageGateWorkflowOracleRejectsNeedSuccessBypass(t *testing.T) {
	expectation := packageGateWorkflowExpectation{
		label:         "fixture",
		jobID:         "publish",
		stepName:      "Run package gate",
		runCommand:    "npm run check",
		requiredNeeds: map[string][]string{"publish": []string{"candidate"}},
	}
	err := validatePackageGateWorkflow([]byte(`
on:
  push:
jobs:
  candidate:
    steps:
      - name: Build
        run: npm run check
  publish:
    needs: candidate
    if: ${{ always() && (needs.candidate.result == 'success' || true) }}
    steps:
      - name: Run package gate
        run: npm run check
`), expectation)
	if err == nil || !strings.Contains(err.Error(), "needs.candidate.result == 'success'") {
		t.Fatalf("validatePackageGateWorkflow() error=%v, want bypassed success predicate failure", err)
	}
}

func TestPackageGateWorkflowOracleAdmitsPrivateAttestationBypass(t *testing.T) {
	expectation := packageGateWorkflowExpectation{
		label:      "fixture",
		jobID:      "candidate",
		stepName:   "Run package gate",
		runCommand: "npm run check",
		requiredNeeds: map[string][]string{
			"release-assets": []string{"candidate", "release-attestations"},
		},
	}
	err := validatePackageGateWorkflow([]byte(`
on:
  push:
jobs:
  candidate:
    steps:
      - name: Run package gate
        run: npm run check
  release-attestations:
    needs: candidate
    if: ${{ always() && needs.candidate.result == 'success' }}
    steps:
      - name: Attest
        run: echo attest
  release-assets:
    needs:
      - candidate
      - release-attestations
    if: >-
      ${{
        always() &&
        needs.candidate.result == 'success' &&
        (vars.PROOFKIT_ENABLE_GITHUB_ATTESTATIONS != 'true' || github.event.repository.private == true || needs.release-attestations.result == 'success')
      }}
    steps:
      - name: Publish
        run: echo publish
`), expectation)
	if err != nil {
		t.Fatalf("validatePackageGateWorkflow() error=%v, want admitted private attestation bypass", err)
	}
}

func TestPackageGateWorkflowOracleAdmitsAlwaysWithNeedSuccess(t *testing.T) {
	expectation := packageGateWorkflowExpectation{
		label:         "fixture",
		jobID:         "publish",
		stepName:      "Run package gate",
		runCommand:    "npm run check",
		requiredNeeds: map[string][]string{"publish": []string{"candidate"}},
	}
	err := validatePackageGateWorkflow([]byte(`
on:
  push:
jobs:
  candidate:
    steps:
      - name: Build
        run: npm run check
  publish:
    needs: candidate
    if: >-
      ${{
        always() &&
        needs.candidate.result == 'success'
      }}
    steps:
      - name: Run package gate
        run: npm run check
`), expectation)
	if err != nil {
		t.Fatalf("validatePackageGateWorkflow() error=%v, want admitted success predicate", err)
	}
}

func TestNeedsListNormalizesStringAndList(t *testing.T) {
	if got := needsList("build"); !reflect.DeepEqual(got, []string{"build"}) {
		t.Fatalf("needsList(string)=%#v", got)
	}
	if got := needsList([]any{"test", "build"}); !reflect.DeepEqual(got, []string{"build", "test"}) {
		t.Fatalf("needsList(list)=%#v", got)
	}
}
