package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	RunsOn          any            `yaml:"runs-on"`
	Steps           []githubStep   `yaml:"steps"`
}

type githubStep struct {
	ContinueOnError any            `yaml:"continue-on-error"`
	Env             map[string]any `yaml:"env"`
	If              string         `yaml:"if"`
	Name            string         `yaml:"name"`
	Run             string         `yaml:"run"`
	Uses            string         `yaml:"uses"`
	With            map[string]any `yaml:"with"`
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

func permissionHas(raw any, key string, want string) bool {
	record, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	value, ok := record[key]
	if !ok {
		return false
	}
	text, ok := value.(string)
	return ok && strings.EqualFold(strings.TrimSpace(text), want)
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

func TestSecurityScannerWorkflowsSeparateProviderPublicationPermissions(t *testing.T) {
	cases := []struct {
		name         string
		path         string
		advisoryJobs []string
		providerJobs map[string]map[string]string
	}{
		{
			name:         "codeql",
			path:         filepath.Join("..", ".github", "workflows", "codeql.yml"),
			advisoryJobs: []string{"analyze"},
			providerJobs: map[string]map[string]string{
				"upload-sarif": {"security-events": "write"},
			},
		},
		{
			name:         "osv",
			path:         filepath.Join("..", ".github", "workflows", "osv-scanner.yml"),
			advisoryJobs: []string{"scan"},
			providerJobs: map[string]map[string]string{
				"upload-sarif": {"security-events": "write"},
			},
		},
		{
			name:         "scorecard",
			path:         filepath.Join("..", ".github", "workflows", "scorecard.yml"),
			advisoryJobs: []string{"scorecard"},
			providerJobs: map[string]map[string]string{
				"upload-sarif": {"security-events": "write"},
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			workflow := readWorkflowForTest(t, item.path)
			if permissionWrites(workflow.Permissions) {
				t.Fatalf("%s workflow-level permissions grant write scopes", item.path)
			}
			for _, jobID := range item.advisoryJobs {
				job, ok := workflow.Jobs[jobID]
				if !ok {
					t.Fatalf("%s missing advisory job %q", item.path, jobID)
				}
				if permissionWrites(job.Permissions) {
					t.Fatalf("%s advisory job %q grants write scopes: %#v", item.path, jobID, job.Permissions)
				}
			}
			for jobID, permissions := range item.providerJobs {
				job, ok := workflow.Jobs[jobID]
				if !ok {
					t.Fatalf("%s missing provider job %q", item.path, jobID)
				}
				if item.name == "codeql" || item.name == "osv" {
					if !providerUploadDisabledOnPullRequest(job.If) {
						t.Fatalf("%s provider job %q must not upload provider evidence on pull_request: if=%q", item.path, jobID, job.If)
					}
				}
				for scope, want := range permissions {
					if !permissionHas(job.Permissions, scope, want) {
						t.Fatalf("%s provider job %q permission %s=%#v, want %q", item.path, jobID, scope, job.Permissions, want)
					}
				}
			}
		})
	}
}

func providerUploadDisabledOnPullRequest(expression string) bool {
	normalized := normalizedExpression(expression)
	return strings.Contains(normalized, "github.event_name != 'pull_request'") ||
		strings.Contains(normalized, `github.event_name != "pull_request"`)
}

func TestScorecardPublicPublishDeclaresRequiredOutputInputs(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "scorecard-publish.yml"))
	if permissionWrites(workflow.Permissions) {
		t.Fatalf("scorecard publish workflow-level permissions grant write scopes")
	}
	if len(workflow.Jobs) != 1 {
		t.Fatalf("scorecard publish workflow must contain exactly one job, got %d", len(workflow.Jobs))
	}
	job, ok := workflow.Jobs["scorecard"]
	if !ok {
		t.Fatalf("scorecard workflow missing public publish job")
	}
	if !permissionHas(job.Permissions, "id-token", "write") {
		t.Fatalf("scorecard public publish job must declare id-token=write, got %#v", job.Permissions)
	}
	stepIndex, err := uniqueStepIndex(job.Steps, "Publish Scorecard results")
	if err != nil {
		t.Fatal(err)
	}
	if stepIndex < 0 {
		t.Fatalf("scorecard public publish job missing Scorecard action step")
	}
	step := job.Steps[stepIndex]
	if !strings.HasPrefix(step.Uses, "ossf/scorecard-action@") {
		t.Fatalf("public publish step uses %q, want ossf/scorecard-action", step.Uses)
	}
	if !withBool(step.With, "publish_results") {
		t.Fatalf("public publish step must set publish_results=true")
	}
	if got := withString(step.With, "results_file"); got != "scorecard-public-results.json" {
		t.Fatalf("public publish results_file=%q, want scorecard-public-results.json", got)
	}
	if got := withString(step.With, "results_format"); got != "json" {
		t.Fatalf("public publish results_format=%q, want json", got)
	}
}

func readWorkflowForTest(t *testing.T, path string) githubWorkflow {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read workflow %s: %v", path, err)
	}
	var workflow githubWorkflow
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("parse workflow %s: %v", path, err)
	}
	return workflow
}

func TestWorkflowsUseExplicitHostedRunnerLabels(t *testing.T) {
	for _, path := range workflowPathsForTest(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			workflow := readWorkflowForTest(t, path)
			for jobID, job := range workflow.Jobs {
				for _, label := range runnerLabels(job.RunsOn) {
					if strings.HasSuffix(label, "-latest") {
						t.Fatalf("%s job %q uses floating hosted runner label %q", path, jobID, label)
					}
				}
			}
		})
	}
}

func workflowPathsForTest(t *testing.T) []string {
	t.Helper()
	patterns := []string{
		filepath.Join("..", ".github", "workflows", "*.yml"),
		filepath.Join("..", ".github", "workflows", "*.yaml"),
	}
	var paths []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob workflows with %s: %v", pattern, err)
		}
		paths = append(paths, matches...)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("no workflow files found")
	}
	return paths
}

func TestCIWorkflowDeclaresFailClosedRequiredAggregate(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	gate, ok := workflow.Jobs["ci-required-gate"]
	if !ok {
		t.Fatalf("ci workflow missing ci-required-gate job")
	}
	if truthy(gate.ContinueOnError) {
		t.Fatalf("ci-required-gate must not continue on errors")
	}
	if permissionWrites(gate.Permissions) {
		t.Fatalf("ci-required-gate permissions grant write scopes: %#v", gate.Permissions)
	}
	if !usesAlwaysStatusCheck(gate.If) {
		t.Fatalf("ci-required-gate if=%q, want always() so failed or skipped needs are inspected", gate.If)
	}
	wantNeeds := []string{"browser-runtime", "platform-smoke", "source-quality"}
	if got := needsList(gate.Needs); !reflect.DeepEqual(got, wantNeeds) {
		t.Fatalf("ci-required-gate needs=%#v, want %#v", got, wantNeeds)
	}
	if len(gate.Steps) != 1 {
		t.Fatalf("ci-required-gate steps=%d, want one aggregate assertion step", len(gate.Steps))
	}
	run := gate.Steps[0].Run
	for _, need := range wantNeeds {
		want := fmt.Sprintf(`test "${{ needs.%s.result }}" = "success"`, need)
		if !strings.Contains(run, want) {
			t.Fatalf("ci-required-gate run must require %s success, run=%q", need, run)
		}
	}
}

func TestCIBrowserRuntimeInstallsEnginesBeforeProofAndRetainsOnlySuccessfulEvidence(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	job, ok := workflow.Jobs["browser-runtime"]
	if !ok {
		t.Fatal("ci workflow missing browser-runtime job")
	}
	installIndex, err := uniqueStepIndex(job.Steps, "Install pinned browser engines")
	if err != nil {
		t.Fatal(err)
	}
	proofIndex, err := uniqueStepIndex(job.Steps, "Run browser proof")
	if err != nil {
		t.Fatal(err)
	}
	uploadIndex, err := uniqueStepIndex(job.Steps, "Upload browser proof")
	if err != nil {
		t.Fatal(err)
	}
	if !(installIndex < proofIndex && proofIndex < uploadIndex) {
		t.Fatalf("browser runtime order install=%d proof=%d upload=%d", installIndex, proofIndex, uploadIndex)
	}
	if job.Steps[installIndex].Run != "npx playwright install --with-deps chromium firefox webkit" || job.Steps[proofIndex].Run != "npm run browser:check" {
		t.Fatalf("browser runtime commands are not exact: install=%q proof=%q", job.Steps[installIndex].Run, job.Steps[proofIndex].Run)
	}
	upload := job.Steps[uploadIndex]
	if usesAlwaysStatusCheck(upload.If) || upload.With["if-no-files-found"] != "error" || upload.With["path"] != "artifacts/proofkit/browser-runtime-proof.json" {
		t.Fatalf("browser proof upload is not fail-closed success evidence: %#v", upload)
	}
}

func TestReleaseCandidateInstallsBrowserEnginesBeforePackageGate(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "release.yml"))
	job, ok := workflow.Jobs["candidate"]
	if !ok {
		t.Fatal("release workflow missing candidate job")
	}
	installIndex, err := uniqueStepIndex(job.Steps, "Install pinned browser engines")
	if err != nil {
		t.Fatal(err)
	}
	gateIndex, err := uniqueStepIndex(job.Steps, "Run package gate")
	if err != nil {
		t.Fatal(err)
	}
	if installIndex >= gateIndex || job.Steps[installIndex].Run != "npx playwright install --with-deps chromium firefox webkit" || job.Steps[gateIndex].Run != "npm run check" {
		t.Fatalf("release browser prerequisite is not fail-closed before package gate: install=%#v gate=%#v", job.Steps[installIndex], job.Steps[gateIndex])
	}
}

func TestCISourceQualityInstallsPythonBeforeLifecycleTests(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	job, ok := workflow.Jobs["source-quality"]
	if !ok {
		t.Fatal("ci workflow missing source-quality job")
	}
	setupIndex, err := uniqueStepIndex(job.Steps, "Setup Python")
	if err != nil {
		t.Fatal(err)
	}
	if setupIndex < 0 {
		t.Fatal("source-quality job missing Setup Python")
	}
	testIndex, err := uniqueStepIndex(job.Steps, "Run all Go tests")
	if err != nil {
		t.Fatal(err)
	}
	if testIndex < 0 {
		t.Fatal("source-quality job missing Run all Go tests")
	}
	if setupIndex >= testIndex {
		t.Fatalf("Setup Python index=%d must precede Go tests index=%d", setupIndex, testIndex)
	}
	setup := job.Steps[setupIndex]
	if setup.Uses != "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1" {
		t.Fatalf("Setup Python uses=%q, want pinned actions/setup-python v6.3.0", setup.Uses)
	}
	if got := withString(setup.With, "python-version"); got != "3.14.6" {
		t.Fatalf("Setup Python python-version=%q, want 3.14.6", got)
	}
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

func runnerLabels(raw any) []string {
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

func withBool(values map[string]any, key string) bool {
	if values == nil {
		return false
	}
	switch value := values[key].(type) {
	case bool:
		return value
	case string:
		return normalizedExpression(value) == "true"
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
