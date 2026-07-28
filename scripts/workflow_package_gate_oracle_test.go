package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
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

const requiredPlatformSmokeOwnerCommand = "go run ./internal/tools/packagebuild current && ./dist/agentic-proofkit --help >/dev/null && go run ./internal/tools/pythonpackage build-current && go run ./internal/tools/pythonpackage verify-current"
const setupVerifiedNPMActionSHA256 = "ead7e280f6430a9e83a544d5200217efaa36bf7aaedc879f417141fddfb20e8e"
const ciSourceQualityStepInventorySHA256 = "90143666d13b499059937564e0829ecb1799946edb2975f187759cf5ef246da0"
const ciBrowserRuntimeStepInventorySHA256 = "4880405e46ad4daad339117e76174a579e77cdfb70dde9c18d4afc7873f30aa4"
const releaseCandidateStepInventorySHA256 = "a7a1f3216ab9dd0700957ad23ca557df446f5ceb917525aec1e3ead293de0585"

type packageGateWorkflowExpectation struct {
	label                              string
	workflowName                       string
	workflowConcurrency                *workflowConcurrencyExpectation
	jobID                              string
	stepName                           string
	runCommand                         string
	workflowEnv                        map[string]any
	allowedStepEnv                     map[string]map[string]any
	mustFollowSteps                    []workflowStepExpectation
	mustPrecedeStepNames               []string
	requireReadOnlyWorkflowPermissions bool
	requiredNeeds                      map[string][]string
	requiredTriggers                   []workflowTriggerExpectation
	requireReleaseExpressionInventory  bool
	stepInventorySHA256                string
}

type workflowConcurrencyExpectation struct {
	group            string
	cancelInProgress bool
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

func assertPackageGateWorkflowFile(t *testing.T, path string, expectation packageGateWorkflowExpectation) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := validateWorkflowClosedKeys(path, raw); err != nil {
		t.Fatalf("%s closed workflow grammar: %v", expectation.label, err)
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
	if expectation.workflowName != "" && workflow.Name != expectation.workflowName {
		return fmt.Errorf("workflow name=%q, want exact %q", workflow.Name, expectation.workflowName)
	}
	if expectation.workflowConcurrency != nil {
		if err := validateExactWorkflowConcurrency(
			expectation.label,
			workflow.Concurrency,
			*expectation.workflowConcurrency,
		); err != nil {
			return err
		}
	}
	if len(workflow.Jobs) == 0 {
		return fmt.Errorf("workflow must declare jobs")
	}
	if err := validateOptionalWorkflowRunDefaults(workflow.Defaults); err != nil {
		return err
	}
	if !equalStringAnyMaps(workflow.Env, expectation.workflowEnv) {
		return fmt.Errorf("workflow env=%v, want exact %v", workflow.Env, expectation.workflowEnv)
	}
	if err := validateTriggers(workflow.On, expectation.requiredTriggers); err != nil {
		return err
	}
	if err := validateRequiredNeeds(
		workflow.Jobs,
		expectation.requiredNeeds,
		expectation.requireReleaseExpressionInventory,
	); err != nil {
		return err
	}
	if expectation.requireReleaseExpressionInventory {
		if err := validateReleaseWorkflowExpressions(workflow); err != nil {
			return err
		}
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
	if err := validateJobExecutionControls(expectation.jobID, job, expectation.allowedStepEnv); err != nil {
		return err
	}
	if expectation.stepInventorySHA256 != "" {
		if err := validateExactStepInventory(expectation.label, job.Steps, expectation.stepInventorySHA256); err != nil {
			return err
		}
	}
	if disabledExpression(job.If) {
		return fmt.Errorf("job %q is disabled by if expression", expectation.jobID)
	}
	if !expectation.requireReleaseExpressionInventory {
		condition := canonicalWorkflowExpression(job.If)
		_, ownsNeeds := expectation.requiredNeeds[expectation.jobID]
		if (condition == "" && job.ifPresent) ||
			(condition != "" && (!ownsNeeds || !statusGuardExpressionAdmitted(condition))) {
			return fmt.Errorf(
				"job %q if=%q, want absent or exact owner status expression",
				expectation.jobID,
				condition,
			)
		}
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
		if usesAlwaysStatusCheck(later.If) && !requiresPriorStepSuccess(later.If) {
			return fmt.Errorf("required later step %q uses always() and must explicitly require success()", laterStep)
		}
	}
	if !expectation.requireReleaseExpressionInventory {
		allowedLaterConditions := make(map[string]struct{}, len(expectation.mustPrecedeStepNames))
		for _, name := range expectation.mustPrecedeStepNames {
			allowedLaterConditions[name] = struct{}{}
		}
		for _, step := range job.Steps {
			condition := canonicalWorkflowExpression(step.If)
			if condition == "" {
				if step.ifPresent {
					return fmt.Errorf(
						"job %q step %q has an explicit empty condition, want absent exact condition",
						expectation.jobID,
						step.Name,
					)
				}
				continue
			}
			_, later := allowedLaterConditions[step.Name]
			if later && condition == admittedStatusExpressions()[0] {
				continue
			}
			return fmt.Errorf(
				"job %q step %q if=%q, want absent exact condition",
				expectation.jobID,
				step.Name,
				condition,
			)
		}
	}
	return nil
}

func validateExactStepInventory(label string, steps []githubStep, expectedSHA256 string) error {
	records := make([]map[string]any, 0, len(steps))
	for _, step := range steps {
		records = append(records, map[string]any{
			"continueOnError": step.ContinueOnError,
			"env":             step.Env,
			"id":              step.ID,
			"if":              step.If,
			"name":            step.Name,
			"presence": map[string]bool{
				"continueOnError":  step.continueOnErrorPresent,
				"id":               step.idPresent,
				"if":               step.ifPresent,
				"run":              step.runPresent,
				"shell":            step.shellPresent,
				"timeoutMinutes":   step.timeoutMinutesPresent,
				"uses":             step.usesPresent,
				"with":             step.withPresent,
				"workingDirectory": step.workingDirectoryPresent,
			},
			"run":              step.Run,
			"shell":            step.Shell,
			"timeoutMinutes":   step.TimeoutMinutes,
			"uses":             step.Uses,
			"with":             step.With,
			"workingDirectory": step.WorkingDirectory,
		})
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("%s exact step inventory encoding: %w", label, err)
	}
	sum := sha256.Sum256(encoded)
	actual := fmt.Sprintf("%x", sum[:])
	if actual != expectedSHA256 {
		return fmt.Errorf("%s exact step inventory sha256=%s, want %s", label, actual, expectedSHA256)
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

func validateRequiredNeeds(
	jobs map[string]githubJob,
	required map[string][]string,
	conditionsOwnedByExactInventory bool,
) error {
	for jobID, expectedNeeds := range required {
		if len(expectedNeeds) == 0 {
			return fmt.Errorf("required workflow job %q has an empty exact needs inventory", jobID)
		}
		job, ok := jobs[jobID]
		if !ok {
			return fmt.Errorf("required workflow job %q not found", jobID)
		}
		if disabledExpression(job.If) {
			return fmt.Errorf("required workflow job %q is disabled by if expression", jobID)
		}
		condition := canonicalWorkflowExpression(job.If)
		if !conditionsOwnedByExactInventory &&
			((condition == "" && job.ifPresent) ||
				(condition != "" && !statusGuardExpressionAdmitted(condition))) {
			return fmt.Errorf(
				"required workflow job %q if=%q must use an exact owner expression and explicitly require needs.%s.result == 'success'",
				jobID,
				condition,
				expectedNeeds[0],
			)
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
	return strings.Contains(unquotedExpression(canonicalWorkflowExpression(value)), "always()")
}

func requiresSuccessfulNeed(value string, need string) bool {
	normalized := canonicalWorkflowExpression(value)
	token := "needs." + need + ".result=='success'"
	return statusGuardExpressionAdmitted(normalized) &&
		(hasConjunct(normalized, token) || hasAllowedOptionalNeedGuard(normalized, need, token))
}

func requiresPriorStepSuccess(value string) bool {
	normalized := canonicalWorkflowExpression(value)
	return statusGuardExpressionAdmitted(normalized) && hasConjunct(normalized, "success()")
}

func statusGuardExpressionAdmitted(normalized string) bool {
	for _, admitted := range admittedStatusExpressions() {
		if normalized == admitted {
			return true
		}
	}
	return false
}

func admittedStatusExpressions() []string {
	return []string{
		"always()&&success()",
		"always()&&needs.candidate.result=='success'",
		"always()&&needs.candidate.result=='success'&&(vars.proofkit_enable_github_attestations!='true'||github.event.repository.private==true||needs.release-attestations.result=='success')",
		"always()&&(github.event_name=='push'||inputs.mode=='publish')&&needs.candidate.result=='success'&&needs.publish.result=='success'&&(vars.proofkit_enable_pypi_publish!='true'||needs.publish-pypi.result=='success')",
		"always()&&(github.event_name=='push'||inputs.mode=='publish')&&vars.proofkit_enable_github_attestations=='true'&&github.event.repository.private==false&&needs.candidate.result=='success'&&needs.publish.result=='success'&&needs.release-metadata.result=='success'&&(vars.proofkit_enable_pypi_publish!='true'||needs.publish-pypi.result=='success')",
		"always()&&(github.event_name=='push'||inputs.mode=='publish')&&needs.candidate.result=='success'&&needs.publish.result=='success'&&needs.release-metadata.result=='success'&&(vars.proofkit_enable_pypi_publish!='true'||needs.publish-pypi.result=='success')&&(vars.proofkit_enable_github_attestations!='true'||github.event.repository.private==true||needs.release-attestations.result=='success')",
	}
}

func validateReleaseWorkflowExpressions(workflow githubWorkflow) error {
	if err := validateExactWorkflowRuntimeControls(
		"release workflow",
		workflow,
		map[string]jobRuntimeControlsExpectation{
			"candidate":         {timeoutMinutes: 30},
			"publish-readiness": {timeoutMinutes: 10},
			"publish": {
				timeoutMinutes:     20,
				environment:        "npm-production",
				environmentPresent: true,
			},
			"publish-pypi": {
				timeoutMinutes: 20,
				environment: map[string]any{
					"name": "pypi",
					"url":  "https://pypi.org/p/agentic-proofkit",
				},
				environmentPresent: true,
			},
			"release-metadata":     {timeoutMinutes: 10},
			"release-attestations": {timeoutMinutes: 10},
			"release-assets":       {timeoutMinutes: 15},
		},
	); err != nil {
		return err
	}
	jobExpressions := map[string]string{
		"candidate":            "",
		"publish-readiness":    "github.event_name=='push'||inputs.mode=='publish'",
		"publish":              "github.event_name=='push'||inputs.mode=='publish'",
		"publish-pypi":         "(github.event_name=='push'||inputs.mode=='publish')&&vars.proofkit_enable_pypi_publish=='true'",
		"release-metadata":     admittedStatusExpressions()[3],
		"release-attestations": admittedStatusExpressions()[4],
		"release-assets":       admittedStatusExpressions()[5],
	}
	stepExpressions := map[string]map[string]string{
		"publish-pypi": {
			"Publish to PyPI": "steps.pypi-preflight.outputs.skip_publish!='true'",
		},
		"release-metadata": {
			"Download PyPI registry evidence": "vars.proofkit_enable_pypi_publish=='true'",
		},
		"release-assets": {
			"Download PyPI registry evidence": "vars.proofkit_enable_pypi_publish=='true'",
			"Download attestation evidence":   "vars.proofkit_enable_github_attestations=='true'&&github.event.repository.private==false",
			"Upload PyPI release evidence":    "vars.proofkit_enable_pypi_publish=='true'",
		},
	}
	return validateExactWorkflowExpressions(
		"release workflow",
		workflow,
		jobExpressions,
		stepExpressions,
	)
}

type jobRuntimeControlsExpectation struct {
	timeoutMinutes     int
	environment        any
	environmentPresent bool
}

func validateExactWorkflowRuntimeControls(
	label string,
	workflow githubWorkflow,
	expected map[string]jobRuntimeControlsExpectation,
) error {
	if len(workflow.Jobs) != len(expected) {
		return fmt.Errorf("%s runtime-control job count=%d, want exact %d", label, len(workflow.Jobs), len(expected))
	}
	for jobID, want := range expected {
		job, ok := workflow.Jobs[jobID]
		if !ok {
			return fmt.Errorf("%s runtime-control job %q is missing", label, jobID)
		}
		if !job.timeoutMinutesPresent || !reflect.DeepEqual(job.TimeoutMinutes, want.timeoutMinutes) {
			return fmt.Errorf(
				"%s job %q timeout-minutes=%v, want exact %d",
				label,
				jobID,
				job.TimeoutMinutes,
				want.timeoutMinutes,
			)
		}
		if job.environmentPresent != want.environmentPresent ||
			!reflect.DeepEqual(job.Environment, want.environment) {
			return fmt.Errorf(
				"%s job %q environment=%v presence=%t, want exact %v presence=%t",
				label,
				jobID,
				job.Environment,
				job.environmentPresent,
				want.environment,
				want.environmentPresent,
			)
		}
		if job.ContinueOnError != nil || job.continueOnErrorPresent ||
			job.Defaults != nil || job.defaultsPresent ||
			len(job.Env) != 0 ||
			job.Uses != "" || job.usesPresent {
			return fmt.Errorf("%s job %q contains an unowned execution control", label, jobID)
		}
		for _, step := range job.Steps {
			if step.ContinueOnError != nil || step.continueOnErrorPresent ||
				step.Shell != nil || step.shellPresent ||
				step.TimeoutMinutes != nil || step.timeoutMinutesPresent ||
				step.WorkingDirectory != nil || step.workingDirectoryPresent {
				return fmt.Errorf(
					"%s job %q step %q contains an unowned execution control",
					label,
					jobID,
					step.Name,
				)
			}
		}
	}
	return nil
}

func validateExactWorkflowExpressions(
	label string,
	workflow githubWorkflow,
	jobExpressions map[string]string,
	stepExpressions map[string]map[string]string,
) error {
	if len(workflow.Jobs) != len(jobExpressions) {
		return fmt.Errorf(
			"%s job inventory count=%d, want exact %d",
			label,
			len(workflow.Jobs),
			len(jobExpressions),
		)
	}
	for jobID, job := range workflow.Jobs {
		expectedJobExpression, owned := jobExpressions[jobID]
		if !owned {
			return fmt.Errorf("%s has unowned job %s", label, jobID)
		}
		if actual := canonicalWorkflowExpression(job.If); actual != expectedJobExpression {
			return fmt.Errorf(
				"%s job %s if=%q, want exact owner expression %q",
				label,
				jobID,
				actual,
				expectedJobExpression,
			)
		}
		if expectedJobExpression == "" && job.ifPresent {
			return fmt.Errorf(
				"%s job %s has an explicit empty condition, want absent condition",
				label,
				jobID,
			)
		}
		expectedStepExpressions := stepExpressions[jobID]
		seen := make(map[string]int, len(expectedStepExpressions))
		for _, step := range job.Steps {
			expected := ""
			if ownerExpression, ok := expectedStepExpressions[step.Name]; ok {
				expected = ownerExpression
				seen[step.Name]++
			}
			if actual := canonicalWorkflowExpression(step.If); actual != expected {
				return fmt.Errorf(
					"%s job %s step %s if=%q, want exact owner expression %q",
					label,
					jobID,
					step.Name,
					actual,
					expected,
				)
			}
			if expected == "" && step.ifPresent {
				return fmt.Errorf(
					"%s job %s step %s has an explicit empty condition, want absent condition",
					label,
					jobID,
					step.Name,
				)
			}
		}
		for stepName := range expectedStepExpressions {
			if seen[stepName] != 1 {
				return fmt.Errorf(
					"%s job %s expression step %s count=%d, want exactly one",
					label,
					jobID,
					stepName,
					seen[stepName],
				)
			}
		}
	}
	return nil
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

func TestCIWorkflowDeclaresFailClosedRequiredAggregate(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err := validateCIRequiredAggregate(workflow); err != nil {
		t.Fatal(err)
	}
	if err := validatePlatformSmokeOwnerScript(readPackageManifestForTest(t)); err != nil {
		t.Fatal(err)
	}
	if err := validateSetupVerifiedNPMAction(readSetupVerifiedNPMActionForTest(t)); err != nil {
		t.Fatal(err)
	}
	gate, ok := workflow.Jobs["ci-required-gate"]
	if !ok {
		t.Fatalf("ci workflow missing ci-required-gate job")
	}
	if gate.ContinueOnError != nil {
		t.Fatalf("ci-required-gate must omit continue-on-error")
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

func TestCIRequiredAggregateRejectsNeutralizedScript(t *testing.T) {
	base := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err := validateCIRequiredAggregate(base); err != nil {
		t.Fatalf("owner CI workflow: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*githubJob)
	}{
		{
			name: "dead branch",
			mutate: func(job *githubJob) {
				job.Steps[0].Run = "if false; then\n" + job.Steps[0].Run + "fi\n"
			},
		},
		{
			name: "or true",
			mutate: func(job *githubJob) {
				job.Steps[0].Run = strings.Replace(job.Steps[0].Run, `"success"`, `"success" || true`, 1)
			},
		},
		{
			name: "early exit",
			mutate: func(job *githubJob) {
				job.Steps[0].Run = "exit 0\n" + job.Steps[0].Run
			},
		},
		{
			name: "background assertion",
			mutate: func(job *githubJob) {
				job.Steps[0].Run = strings.Replace(job.Steps[0].Run, `"success"`, `"success" &`, 1)
			},
		},
		{
			name: "step bypass",
			mutate: func(job *githubJob) {
				job.Steps[0].ContinueOnError = true
			},
		},
		{
			name: "job bypass",
			mutate: func(job *githubJob) {
				job.ContinueOnError = true
			},
		},
		{
			name: "job expression bypass",
			mutate: func(job *githubJob) {
				job.ContinueOnError = "${{ 1 == 1 }}"
			},
		},
		{
			name: "job bypass field present but false",
			mutate: func(job *githubJob) {
				job.ContinueOnError = false
			},
		},
		{
			name: "guard neutralized",
			mutate: func(job *githubJob) {
				job.If = "${{ always() || true }}"
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			workflow := cloneWorkflow(t, base)
			job := workflow.Jobs["ci-required-gate"]
			test.mutate(&job)
			workflow.Jobs["ci-required-gate"] = job
			if err := validateCIRequiredAggregate(workflow); err == nil {
				t.Fatal("neutralized required aggregate was admitted")
			}
		})
	}
}

func TestCIRequiredAggregateRejectsExecutionOverrides(t *testing.T) {
	base := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err := validateCIRequiredAggregate(base); err != nil {
		t.Fatalf("owner CI workflow: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*githubWorkflow)
	}{
		{
			name: "workflow name",
			mutate: func(workflow *githubWorkflow) {
				workflow.Name = "shadow"
			},
		},
		{
			name: "workflow concurrency group",
			mutate: func(workflow *githubWorkflow) {
				workflow.Concurrency.Group = "shadow"
			},
		},
		{
			name: "workflow concurrency cancellation",
			mutate: func(workflow *githubWorkflow) {
				workflow.Concurrency.CancelInProgress = false
			},
		},
		{
			name: "workflow shell",
			mutate: func(workflow *githubWorkflow) {
				workflow.Defaults.Run.Shell = "bash {0} || true"
			},
		},
		{
			name: "workflow working directory",
			mutate: func(workflow *githubWorkflow) {
				workflow.Defaults.Run.WorkingDirectory = "shadow"
			},
		},
		{
			name: "workflow environment",
			mutate: func(workflow *githubWorkflow) {
				workflow.Env = map[string]any{"BASH_ENV": "./scripts/bypass.sh"}
			},
		},
		{
			name: "job shell defaults",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["ci-required-gate"]
				job.Defaults = &githubDefaults{
					Run: &githubRunDefaults{Shell: "bash {0} || true"},
				}
				workflow.Jobs["ci-required-gate"] = job
			},
		},
		{
			name: "required leaf job continue on error",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["browser-runtime"]
				job.ContinueOnError = "${{ 1 == 1 }}"
				workflow.Jobs["browser-runtime"] = job
			},
		},
		{
			name: "required leaf job null continue on error",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["browser-runtime"]
				job.continueOnErrorPresent = true
				workflow.Jobs["browser-runtime"] = job
			},
		},
		{
			name: "required leaf job shell defaults",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["platform-smoke"]
				job.Defaults = &githubDefaults{
					Run: &githubRunDefaults{Shell: "bash {0} || true"},
				}
				workflow.Jobs["platform-smoke"] = job
			},
		},
		{
			name: "required leaf job null defaults",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["platform-smoke"]
				job.defaultsPresent = true
				workflow.Jobs["platform-smoke"] = job
			},
		},
		{
			name: "required leaf job environment",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["platform-smoke"]
				job.Env = map[string]any{"PATH": "./shadow"}
				workflow.Jobs["platform-smoke"] = job
			},
		},
		{
			name: "required leaf job timeout",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["source-quality"]
				job.TimeoutMinutes = 1
				workflow.Jobs["source-quality"] = job
			},
		},
		{
			name: "required leaf job dynamic false condition",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["source-quality"]
				job.If = "${{ github.event_name == 'never' }}"
				workflow.Jobs["source-quality"] = job
			},
		},
		{
			name: "required leaf job explicit null condition",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["source-quality"]
				job.If = ""
				job.ifPresent = true
				workflow.Jobs["source-quality"] = job
			},
		},
		{
			name: "required leaf step dynamic false condition",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["source-quality"]
				for index := range job.Steps {
					if job.Steps[index].Name == "Run all Go tests" {
						job.Steps[index].If = "${{ github.event_name == 'never' }}"
					}
				}
				workflow.Jobs["source-quality"] = job
			},
		},
		{
			name: "required leaf step explicit null condition",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["source-quality"]
				for index := range job.Steps {
					if job.Steps[index].Name == "Run all Go tests" {
						job.Steps[index].If = ""
						job.Steps[index].ifPresent = true
					}
				}
				workflow.Jobs["source-quality"] = job
			},
		},
		{
			name: "required leaf step shell",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["source-quality"]
				for index := range job.Steps {
					if job.Steps[index].Name == "Verify browser source types" {
						job.Steps[index].Shell = "bash {0} || true"
					}
				}
				workflow.Jobs["source-quality"] = job
			},
		},
		{
			name: "required leaf step environment",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["source-quality"]
				for index := range job.Steps {
					if job.Steps[index].Name == "Verify browser source types" {
						job.Steps[index].Env = map[string]any{"NODE_OPTIONS": "--require ./scripts/bypass.cjs"}
					}
				}
				workflow.Jobs["source-quality"] = job
			},
		},
		{
			name: "source quality semantic shadow step",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["source-quality"]
				index, err := uniqueStepIndex(job.Steps, "Run all Go tests")
				if err != nil || index < 0 {
					panic("owner source-quality workflow lost Run all Go tests")
				}
				shadow := githubStep{
					Name:       "Shadow Go tests",
					Run:        "npm pkg set scripts.go:test=true",
					runPresent: true,
				}
				job.Steps = append(job.Steps[:index], append([]githubStep{shadow}, job.Steps[index:]...)...)
				workflow.Jobs["source-quality"] = job
			},
		},
		{
			name: "source quality step id",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["source-quality"]
				index, err := uniqueStepIndex(job.Steps, "Run all Go tests")
				if err != nil || index < 0 {
					panic("owner source-quality workflow lost Run all Go tests")
				}
				job.Steps[index].ID = "shadow-go-tests"
				job.Steps[index].idPresent = true
				workflow.Jobs["source-quality"] = job
			},
		},
		{
			name: "source quality timeout minutes",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["source-quality"]
				index, err := uniqueStepIndex(job.Steps, "Run all Go tests")
				if err != nil || index < 0 {
					panic("owner source-quality workflow lost Run all Go tests")
				}
				job.Steps[index].TimeoutMinutes = 1
				job.Steps[index].timeoutMinutesPresent = true
				workflow.Jobs["source-quality"] = job
			},
		},
		{
			name: "browser runtime semantic shadow step",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["browser-runtime"]
				index, err := uniqueStepIndex(job.Steps, "Run browser proof")
				if err != nil || index < 0 {
					panic("owner browser-runtime workflow lost Run browser proof")
				}
				shadow := githubStep{
					Name:       "Shadow browser proof",
					Run:        "npm pkg set scripts.browser:check=true",
					runPresent: true,
				}
				job.Steps = append(job.Steps[:index], append([]githubStep{shadow}, job.Steps[index:]...)...)
				workflow.Jobs["browser-runtime"] = job
			},
		},
		{
			name: "browser runtime step id",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["browser-runtime"]
				index, err := uniqueStepIndex(job.Steps, "Run browser proof")
				if err != nil || index < 0 {
					panic("owner browser-runtime workflow lost Run browser proof")
				}
				job.Steps[index].ID = "shadow-browser-proof"
				job.Steps[index].idPresent = true
				workflow.Jobs["browser-runtime"] = job
			},
		},
		{
			name: "browser runtime timeout minutes",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["browser-runtime"]
				index, err := uniqueStepIndex(job.Steps, "Run browser proof")
				if err != nil || index < 0 {
					panic("owner browser-runtime workflow lost Run browser proof")
				}
				job.Steps[index].TimeoutMinutes = 1
				job.Steps[index].timeoutMinutesPresent = true
				workflow.Jobs["browser-runtime"] = job
			},
		},
		{
			name: "step shell",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["ci-required-gate"]
				job.Steps[0].Shell = "bash {0} || true"
				workflow.Jobs["ci-required-gate"] = job
			},
		},
		{
			name: "step null shell",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["ci-required-gate"]
				job.Steps[0].shellPresent = true
				workflow.Jobs["ci-required-gate"] = job
			},
		},
		{
			name: "step working directory",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["ci-required-gate"]
				job.Steps[0].WorkingDirectory = "shadow"
				workflow.Jobs["ci-required-gate"] = job
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			workflow := cloneWorkflow(t, base)
			test.mutate(&workflow)
			if err := validateCIRequiredAggregate(workflow); err == nil {
				t.Fatal("execution override on required aggregate was admitted")
			}
		})
	}
}

func TestCIRequiredAggregateRejectsPlatformSmokeSubstitution(t *testing.T) {
	base := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err := validateCIRequiredAggregate(base); err != nil {
		t.Fatalf("owner CI workflow: %v", err)
	}
	packageManifest := readPackageManifestForTest(t)
	if err := validatePlatformSmokeOwnerScript(packageManifest); err != nil {
		t.Fatalf("owner platform-smoke package script: %v", err)
	}
	setupAction := readSetupVerifiedNPMActionForTest(t)
	if err := validateSetupVerifiedNPMAction(setupAction); err != nil {
		t.Fatalf("owner setup-verified-npm action: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*githubWorkflow)
	}{
		{
			name: "wrong platform runner",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["platform-smoke"]
				job.RunsOn = "ubuntu-24.04"
				workflow.Jobs["platform-smoke"] = job
			},
		},
		{
			name: "no-op replaces platform smoke",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["platform-smoke"]
				job.Steps = []githubStep{{
					Name: "No-op",
					Run:  "true",
				}}
				workflow.Jobs["platform-smoke"] = job
			},
		},
		{
			name: "platform smoke command neutralized",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["platform-smoke"]
				index, err := uniqueStepIndex(job.Steps, "Run platform smoke")
				if err != nil || index < 0 {
					t.Fatalf("locate platform smoke: index=%d err=%v", index, err)
				}
				job.Steps[index].Run = "true"
				workflow.Jobs["platform-smoke"] = job
			},
		},
		{
			name: "reusable job substitution",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["platform-smoke"]
				job.Steps = nil
				job.Uses = "example/ci/.github/workflows/no-op.yml@0123456789012345678901234567890123456789"
				workflow.Jobs["platform-smoke"] = job
			},
		},
		{
			name: "provider check name drift",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["platform-smoke"]
				job.Name = "quality / platform smoke"
				workflow.Jobs["platform-smoke"] = job
			},
		},
		{
			name: "non-string runner label",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["platform-smoke"]
				job.RunsOn = []any{"macos-15", false}
				workflow.Jobs["platform-smoke"] = job
			},
		},
		{
			name: "inserted semantic shadow step",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["platform-smoke"]
				job.Steps = append([]githubStep{{
					Name: "Shadow platform smoke",
					Run:  "npm pkg set scripts.platform:smoke=true",
				}}, job.Steps...)
				workflow.Jobs["platform-smoke"] = job
			},
		},
		{
			name: "dual uses and whitespace run",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["platform-smoke"]
				job.Steps[0].Run = " "
				job.Steps[0].runPresent = true
				workflow.Jobs["platform-smoke"] = job
			},
		},
		{
			name: "explicit null run on uses step",
			mutate: func(workflow *githubWorkflow) {
				job := workflow.Jobs["platform-smoke"]
				job.Steps[0].runPresent = true
				workflow.Jobs["platform-smoke"] = job
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			workflow := cloneWorkflow(t, base)
			test.mutate(&workflow)
			if err := validateCIRequiredAggregate(workflow); err == nil {
				t.Fatal("platform-smoke substitution was admitted")
			}
		})
	}
	t.Run("package script owner neutralized", func(t *testing.T) {
		var manifest map[string]any
		if err := json.Unmarshal(packageManifest, &manifest); err != nil {
			t.Fatal(err)
		}
		scripts, ok := manifest["scripts"].(map[string]any)
		if !ok {
			t.Fatal("package scripts are not an object")
		}
		scripts["platform:smoke"] = "true"
		mutated, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePlatformSmokeOwnerScript(mutated); err == nil {
			t.Fatal("neutralized platform-smoke package script was admitted")
		}
	})
	t.Run("local setup action shadows package script", func(t *testing.T) {
		owner := string(setupAction)
		mutated := strings.Replace(
			owner,
			`        echo "$bin_dir" >> "$GITHUB_PATH"`+"\n",
			`        echo "$bin_dir" >> "$GITHUB_PATH"`+"\n\n"+
				"    - name: Shadow platform smoke\n"+
				"      shell: bash\n"+
				"      run: npm pkg set scripts.platform:smoke=true\n",
			1,
		)
		if mutated == owner {
			t.Fatal("local setup action mutation did not change the owner")
		}
		var parsedAction any
		if err := yaml.Unmarshal([]byte(mutated), &parsedAction); err != nil {
			t.Fatalf("semantic-shadow action mutant is not valid YAML: %v", err)
		}
		if err := validateSetupVerifiedNPMAction([]byte(mutated)); err == nil {
			t.Fatal("mutated setup-verified-npm action was admitted")
		}
	})
}

func TestPackageGateWorkflowOracleAcceptsOwnerCIAndReleaseWorkflows(t *testing.T) {
	t.Run("ci", func(t *testing.T) {
		assertPackageGateWorkflowFile(
			t,
			filepath.Join("..", ".github", "workflows", "ci.yml"),
			ciPackageGateWorkflowExpectation(),
		)
	})
	t.Run("release", func(t *testing.T) {
		assertPackageGateWorkflowFile(
			t,
			filepath.Join("..", ".github", "workflows", "release.yml"),
			releasePackageGateWorkflowExpectation(),
		)
	})
}

func TestWorkflowGuardExpressionsRejectNeutralization(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "release.yml"))
	if err := validateReleaseWorkflowExpressions(workflow); err != nil {
		t.Fatalf("owner release workflow expressions: %v", err)
	}
	expected := workflow.Jobs["release-metadata"].If
	if !statusGuardExpressionAdmitted(canonicalWorkflowExpression(expected)) {
		t.Fatalf("owner-reviewed release-metadata expression was rejected: %q", expected)
	}
	cases := []string{
		expected + " || true",
		"false && (" + expected + ")",
		`'` + expected + `' == '` + expected + `'`,
		strings.Replace(expected, "'push'", "'p ush'", 1),
		"",
	}
	for _, expression := range cases {
		if statusGuardExpressionAdmitted(canonicalWorkflowExpression(expression)) {
			t.Fatalf("neutralized or non-owner expression was admitted: %q", expression)
		}
	}
	t.Run("candidate job dynamic false", func(t *testing.T) {
		mutated := cloneWorkflow(t, workflow)
		job := mutated.Jobs["candidate"]
		job.If = "${{ github.event_name == 'never' }}"
		mutated.Jobs["candidate"] = job
		if err := validateReleaseWorkflowExpressions(mutated); err == nil {
			t.Fatal("dynamically false release candidate job condition was admitted")
		}
	})
	t.Run("candidate job explicit null", func(t *testing.T) {
		mutated := cloneWorkflow(t, workflow)
		job := mutated.Jobs["candidate"]
		job.If = ""
		job.ifPresent = true
		mutated.Jobs["candidate"] = job
		if err := validateReleaseWorkflowExpressions(mutated); err == nil {
			t.Fatal("explicit null release candidate job condition was admitted")
		}
	})
	t.Run("package gate step dynamic false", func(t *testing.T) {
		mutated := cloneWorkflow(t, workflow)
		job := mutated.Jobs["candidate"]
		index, err := uniqueStepIndex(job.Steps, "Run package gate")
		if err != nil || index < 0 {
			t.Fatalf("locate package gate: index=%d err=%v", index, err)
		}
		job.Steps[index].If = "${{ github.event_name == 'never' }}"
		mutated.Jobs["candidate"] = job
		if err := validateReleaseWorkflowExpressions(mutated); err == nil {
			t.Fatal("dynamically false release package-gate step condition was admitted")
		}
	})
}

func validateOptionalWorkflowRunDefaults(defaults *githubDefaults) error {
	if defaults == nil {
		return nil
	}
	if defaults.Run == nil {
		return errors.New("workflow defaults must declare only exact run defaults")
	}
	shell, ok := defaults.Run.Shell.(string)
	if !ok || shell != "bash" {
		return fmt.Errorf("workflow defaults run shell=%v, want exact bash", defaults.Run.Shell)
	}
	if defaults.Run.WorkingDirectory != nil {
		return errors.New("workflow defaults must not override run working-directory")
	}
	return nil
}

func validateJobExecutionControls(jobID string, job githubJob, allowedStepEnv map[string]map[string]any) error {
	if job.ContinueOnError != nil || job.continueOnErrorPresent {
		return fmt.Errorf("job %q must omit continue-on-error", jobID)
	}
	if job.Defaults != nil || job.defaultsPresent {
		return fmt.Errorf("job %q must not override workflow run defaults", jobID)
	}
	if len(job.Env) != 0 {
		return fmt.Errorf("job %q must not override workflow environment", jobID)
	}
	if job.Environment != nil || job.environmentPresent {
		return fmt.Errorf("job %q must not select a deployment environment", jobID)
	}
	if job.Uses != "" || job.usesPresent {
		return fmt.Errorf("job %q must not substitute a reusable workflow", jobID)
	}
	seenAllowedStepEnv := make(map[string]int, len(allowedStepEnv))
	for _, step := range job.Steps {
		if step.ContinueOnError != nil || step.continueOnErrorPresent {
			return fmt.Errorf("job %q step %q must omit continue-on-error", jobID, step.Name)
		}
		if step.Shell != nil || step.shellPresent ||
			step.TimeoutMinutes != nil || step.timeoutMinutesPresent ||
			step.WorkingDirectory != nil || step.workingDirectoryPresent {
			return fmt.Errorf(
				"job %q step %q must not override shell or working-directory; timeout-minutes is also forbidden",
				jobID,
				step.Name,
			)
		}
		expectedEnv, allowed := allowedStepEnv[step.Name]
		if !equalStringAnyMaps(step.Env, expectedEnv) {
			return fmt.Errorf("job %q step %q env=%v, want exact %v", jobID, step.Name, step.Env, expectedEnv)
		}
		if allowed {
			seenAllowedStepEnv[step.Name]++
		}
	}
	for name := range allowedStepEnv {
		if seenAllowedStepEnv[name] != 1 {
			return fmt.Errorf("job %q allowed env step %q count=%d, want exactly one", jobID, name, seenAllowedStepEnv[name])
		}
	}
	return nil
}

func equalStringAnyMaps(left, right map[string]any) bool {
	if len(left) == 0 && len(right) == 0 {
		return true
	}
	return reflect.DeepEqual(left, right)
}

func unquotedExpression(value string) string {
	var output strings.Builder
	quote := rune(0)
	escaped := false
	for _, character := range value {
		if quote != 0 {
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
			continue
		}
		output.WriteRune(character)
	}
	return output.String()
}

func singleLineRun(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.ContainsAny(trimmed, "\n\r") {
		return trimmed
	}
	return trimmed
}

const requiredAggregateShell = `set -euo pipefail
test "${{ needs.browser-runtime.result }}" = "success"
test "${{ needs.source-quality.result }}" = "success"
test "${{ needs.platform-smoke.result }}" = "success"
printf 'OK: all required quality checks passed\n'`

const requiredPlatformSmokeShell = `set -euo pipefail
npm run npm:version
npm run platform:smoke
`

func readPackageManifestForTest(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "package.json"))
	if err != nil {
		t.Fatalf("read package manifest: %v", err)
	}
	return raw
}

func validatePlatformSmokeOwnerScript(raw []byte) error {
	var manifest struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("parse package manifest: %w", err)
	}
	if actual := manifest.Scripts["platform:smoke"]; actual != requiredPlatformSmokeOwnerCommand {
		return fmt.Errorf(
			"package platform:smoke=%q, want exact owner command %q",
			actual,
			requiredPlatformSmokeOwnerCommand,
		)
	}
	return nil
}

func readSetupVerifiedNPMActionForTest(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", ".github", "actions", "setup-verified-npm", "action.yml"))
	if err != nil {
		t.Fatalf("read setup-verified-npm action: %v", err)
	}
	return raw
}

func validateSetupVerifiedNPMAction(raw []byte) error {
	sum := sha256.Sum256(raw)
	actual := fmt.Sprintf("%x", sum[:])
	if actual != setupVerifiedNPMActionSHA256 {
		return fmt.Errorf(
			"setup-verified-npm action digest=%s, want exact owner digest %s",
			actual,
			setupVerifiedNPMActionSHA256,
		)
	}
	return nil
}

func validateExactPlatformSmokeSteps(job githubJob) error {
	expected := []githubStep{
		{
			Name: "Checkout",
			Uses: "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
			With: map[string]any{"persist-credentials": false},
		},
		{
			Name: "Setup Node",
			Uses: "actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e",
			With: map[string]any{
				"node-version":          "24.18.0",
				"package-manager-cache": false,
			},
		},
		{
			Name: "Install verified npm",
			Uses: "./.github/actions/setup-verified-npm",
		},
		{
			Name: "Setup Go",
			Uses: "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
			With: map[string]any{
				"go-version-file": "go.mod",
				"cache":           true,
			},
		},
		{
			Name: "Run platform smoke",
			Run:  requiredPlatformSmokeShell,
		},
	}
	if len(job.Steps) != len(expected) {
		return fmt.Errorf(
			"ci workflow platform-smoke step count=%d, want exact %d",
			len(job.Steps),
			len(expected),
		)
	}
	for index, want := range expected {
		actual := job.Steps[index]
		if actual.Name != want.Name ||
			actual.Uses != want.Uses ||
			actual.Run != want.Run ||
			!reflect.DeepEqual(actual.With, want.With) ||
			actual.runPresent != (want.Run != "") ||
			actual.usesPresent != (want.Uses != "") ||
			actual.withPresent != (want.With != nil) {
			return fmt.Errorf(
				"ci workflow platform-smoke step %d differs from exact owner step %q",
				index,
				want.Name,
			)
		}
	}
	return nil
}

func validateCIRequiredAggregate(workflow githubWorkflow) error {
	if workflow.Name != "ci" {
		return fmt.Errorf("ci workflow name=%q, want exact ci", workflow.Name)
	}
	if err := validateExactWorkflowConcurrency(
		"ci workflow",
		workflow.Concurrency,
		workflowConcurrencyExpectation{
			group:            "ci-${{ github.event.pull_request.number || github.ref }}",
			cancelInProgress: true,
		},
	); err != nil {
		return err
	}
	if len(workflow.Env) != 0 {
		return errors.New("ci workflow must not override workflow environment")
	}
	if workflow.Defaults == nil {
		return errors.New("ci workflow must declare exact bash run defaults")
	}
	if err := validateOptionalWorkflowRunDefaults(workflow.Defaults); err != nil {
		return fmt.Errorf("ci workflow run defaults: %w", err)
	}
	wantNeeds := []string{"browser-runtime", "platform-smoke", "source-quality"}
	for _, jobID := range append(append([]string{}, wantNeeds...), "ci-required-gate") {
		job, ok := workflow.Jobs[jobID]
		if !ok {
			return fmt.Errorf("ci workflow missing required job %q", jobID)
		}
		if err := validateJobExecutionControls(jobID, job, nil); err != nil {
			return err
		}
	}
	if err := validateExactWorkflowExpressions(
		"ci workflow",
		workflow,
		map[string]string{
			"browser-runtime":  "",
			"platform-smoke":   "",
			"source-quality":   "",
			"ci-required-gate": "always()",
		},
		map[string]map[string]string{
			"browser-runtime": {
				"Upload browser failure diagnostics": "failure()",
			},
		},
	); err != nil {
		return err
	}
	exactJobTopology := map[string]struct {
		name           string
		runner         string
		timeoutMinutes int
	}{
		"source-quality":   {name: "quality / source", runner: "ubuntu-24.04", timeoutMinutes: 15},
		"platform-smoke":   {name: "quality / platform smoke / macos-15", runner: "macos-15", timeoutMinutes: 12},
		"browser-runtime":  {name: "quality / browser runtime", runner: "ubuntu-24.04", timeoutMinutes: 20},
		"ci-required-gate": {name: "quality / required aggregate", runner: "ubuntu-24.04", timeoutMinutes: 5},
	}
	for jobID, expected := range exactJobTopology {
		job := workflow.Jobs[jobID]
		if job.Name != expected.name {
			return fmt.Errorf("ci workflow job %s name=%q, want exact %q", jobID, job.Name, expected.name)
		}
		actualRunner, stringRunner := job.RunsOn.(string)
		if !stringRunner || actualRunner != expected.runner {
			return fmt.Errorf("ci workflow job %s runs-on=%v, want exact scalar %q", jobID, job.RunsOn, expected.runner)
		}
		if !job.timeoutMinutesPresent || !reflect.DeepEqual(job.TimeoutMinutes, expected.timeoutMinutes) {
			return fmt.Errorf(
				"ci workflow job %s timeout-minutes=%v, want exact %d",
				jobID,
				job.TimeoutMinutes,
				expected.timeoutMinutes,
			)
		}
	}
	platformSmoke := workflow.Jobs["platform-smoke"]
	if err := validateExactPlatformSmokeSteps(platformSmoke); err != nil {
		return err
	}
	if err := validateExactStepInventory(
		"ci workflow source-quality",
		workflow.Jobs["source-quality"].Steps,
		ciSourceQualityStepInventorySHA256,
	); err != nil {
		return err
	}
	if err := validateExactStepInventory(
		"ci workflow browser-runtime",
		workflow.Jobs["browser-runtime"].Steps,
		ciBrowserRuntimeStepInventorySHA256,
	); err != nil {
		return err
	}
	gate, ok := workflow.Jobs["ci-required-gate"]
	if !ok {
		return errors.New("ci workflow missing ci-required-gate")
	}
	if canonicalWorkflowExpression(gate.If) != "always()" {
		return fmt.Errorf("ci-required-gate if=%q, want exact always()", gate.If)
	}
	if gate.ContinueOnError != nil || gate.Defaults != nil || gate.Uses != "" {
		return errors.New("ci-required-gate has a bypass field")
	}
	if got := needsList(gate.Needs); !reflect.DeepEqual(got, wantNeeds) {
		return fmt.Errorf("ci-required-gate needs=%v, want %v", got, wantNeeds)
	}
	if len(gate.Steps) != 1 {
		return fmt.Errorf("ci-required-gate steps=%d, want exactly one", len(gate.Steps))
	}
	step := gate.Steps[0]
	if step.Name != "Verify required quality results" ||
		step.If != "" ||
		step.ContinueOnError != nil ||
		step.Shell != nil ||
		step.Uses != "" ||
		step.WorkingDirectory != nil ||
		len(step.Env) != 0 ||
		strings.TrimSpace(step.Run) != requiredAggregateShell {
		return errors.New("ci-required-gate aggregate step differs from the exact owner-reviewed shell block")
	}
	return nil
}

func validateExactWorkflowConcurrency(
	label string,
	actual *githubConcurrency,
	expected workflowConcurrencyExpectation,
) error {
	if actual == nil ||
		!actual.groupPresent ||
		!actual.cancelInProgressPresent ||
		!reflect.DeepEqual(actual.Group, expected.group) ||
		!reflect.DeepEqual(actual.CancelInProgress, expected.cancelInProgress) {
		return fmt.Errorf(
			"%s concurrency=%v, want exact group=%q cancel-in-progress=%t",
			label,
			actual,
			expected.group,
			expected.cancelInProgress,
		)
	}
	return nil
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
			name: "dynamically false job",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    if: ${{ github.event_name == 'never' }}
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "want absent or exact owner status expression",
		},
		{
			name: "explicit null job condition",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    if: null
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "want absent or exact owner status expression",
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
			wantErr: "must omit continue-on-error",
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
			name: "dynamically false gate step",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        if: ${{ github.event_name == 'never' }}
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "want absent exact condition",
		},
		{
			name: "explicit null gate step condition",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        if: null
        run: npm run check
      - name: Upload evidence
        run: echo upload
`,
			wantErr: "want absent exact condition",
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
			wantErr: "must omit continue-on-error",
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
			wantErr: "must omit continue-on-error",
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
			wantErr: "step \"Upload evidence\" must omit continue-on-error",
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
			name: "dynamically false later evidence",
			yaml: `
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        if: ${{ github.event_name == 'never' }}
        run: echo upload
`,
			wantErr: "want absent exact condition",
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
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutant := range []struct {
		name        string
		replacement string
		wantErr     string
	}{
		{
			name: "release candidate semantic shadow step",
			replacement: "      - name: Shadow package gate\n" +
				"        run: npm pkg set scripts.check=true\n\n" +
				"      - name: Run package gate\n",
			wantErr: "exact step inventory sha256",
		},
		{
			name:        "release candidate step id",
			replacement: "      - name: Run package gate\n        id: shadow-package-gate\n",
			wantErr:     "exact step inventory sha256",
		},
		{
			name:        "release candidate timeout minutes",
			replacement: "      - name: Run package gate\n        timeout-minutes: 1\n",
			wantErr:     "contains an unowned execution control",
		},
	} {
		t.Run(mutant.name, func(t *testing.T) {
			mutated := strings.Replace(
				string(raw),
				"      - name: Run package gate\n",
				mutant.replacement,
				1,
			)
			if mutated == string(raw) {
				t.Fatal("release candidate mutation did not change the workflow")
			}
			err := validatePackageGateWorkflow([]byte(mutated), releasePackageGateWorkflowExpectation())
			if err == nil || !strings.Contains(err.Error(), mutant.wantErr) {
				t.Fatalf("release candidate mutation error=%v, want %q rejection", err, mutant.wantErr)
			}
		})
	}
	for _, mutant := range []struct {
		name        string
		old         string
		replacement string
		wantErr     string
	}{
		{
			name:        "release workflow name",
			old:         "name: release\n",
			replacement: "name: shadow\n",
			wantErr:     "workflow name=",
		},
		{
			name:        "release concurrency group",
			old:         "  group: release-${{ github.ref }}\n",
			replacement: "  group: shadow\n",
			wantErr:     "concurrency=",
		},
		{
			name:        "release concurrency cancellation",
			old:         "  cancel-in-progress: false\n",
			replacement: "  cancel-in-progress: true\n",
			wantErr:     "concurrency=",
		},
		{
			name:        "release candidate job timeout",
			old:         "    timeout-minutes: 30\n",
			replacement: "    timeout-minutes: 1\n",
			wantErr:     "timeout-minutes=1",
		},
	} {
		t.Run(mutant.name, func(t *testing.T) {
			mutated := strings.Replace(string(raw), mutant.old, mutant.replacement, 1)
			if mutated == string(raw) {
				t.Fatal("release owner-value mutation did not change the workflow")
			}
			err := validatePackageGateWorkflow([]byte(mutated), releasePackageGateWorkflowExpectation())
			if err == nil || !strings.Contains(err.Error(), mutant.wantErr) {
				t.Fatalf("release owner-value mutation error=%v, want %q", err, mutant.wantErr)
			}
		})
	}
}

func TestPackageGateWorkflowOracleRejectsExecutionOverrides(t *testing.T) {
	expectation := packageGateWorkflowExpectation{
		label:                "fixture",
		jobID:                "gate",
		stepName:             "Run package gate",
		runCommand:           "npm run check",
		mustPrecedeStepNames: []string{"Upload evidence"},
		requiredTriggers:     []workflowTriggerExpectation{{event: "pull_request"}},
	}
	const base = `
on:
  pull_request:
defaults:
  run:
    shell: bash
jobs:
  gate:
    steps:
      - name: Run package gate
        run: npm run check
      - name: Upload evidence
        run: echo upload
`
	cases := []struct {
		name        string
		old         string
		replacement string
		wantErr     string
	}{
		{name: "workflow shell", old: "    shell: bash\n", replacement: "    shell: bash {0} || true\n", wantErr: "want exact bash"},
		{name: "workflow working directory", old: "    shell: bash\n", replacement: "    shell: bash\n    working-directory: shadow\n", wantErr: "must not override run working-directory"},
		{name: "workflow environment", old: "defaults:\n", replacement: "env:\n  BASH_ENV: ./scripts/bypass.sh\ndefaults:\n", wantErr: "workflow env="},
		{name: "job expression continue on error", old: "  gate:\n", replacement: "  gate:\n    continue-on-error: ${{ 1 == 1 }}\n", wantErr: "must omit continue-on-error"},
		{name: "job false continue on error", old: "  gate:\n", replacement: "  gate:\n    continue-on-error: false\n", wantErr: "must omit continue-on-error"},
		{name: "job null continue on error", old: "  gate:\n", replacement: "  gate:\n    continue-on-error: null\n", wantErr: "must omit continue-on-error"},
		{name: "job defaults", old: "  gate:\n", replacement: "  gate:\n    defaults:\n      run:\n        shell: bash {0} || true\n", wantErr: "must not override workflow run defaults"},
		{name: "job null defaults", old: "  gate:\n", replacement: "  gate:\n    defaults: null\n", wantErr: "must not override workflow run defaults"},
		{name: "job environment", old: "  gate:\n", replacement: "  gate:\n    env:\n      PATH: ./shadow\n", wantErr: "must not override workflow environment"},
		{name: "job deployment environment", old: "  gate:\n", replacement: "  gate:\n    environment: shadow\n", wantErr: "must not select a deployment environment"},
		{name: "step expression continue on error", old: "      - name: Run package gate\n", replacement: "      - name: Run package gate\n        continue-on-error: ${{ 1 == 1 }}\n", wantErr: "must omit continue-on-error"},
		{name: "step false continue on error", old: "      - name: Run package gate\n", replacement: "      - name: Run package gate\n        continue-on-error: false\n", wantErr: "must omit continue-on-error"},
		{name: "step null continue on error", old: "      - name: Run package gate\n", replacement: "      - name: Run package gate\n        continue-on-error: null\n", wantErr: "must omit continue-on-error"},
		{name: "step shell", old: "      - name: Run package gate\n", replacement: "      - name: Run package gate\n        shell: bash {0} || true\n", wantErr: "must not override shell or working-directory"},
		{name: "step null shell", old: "      - name: Run package gate\n", replacement: "      - name: Run package gate\n        shell: null\n", wantErr: "must not override shell or working-directory"},
		{name: "step working directory", old: "      - name: Run package gate\n", replacement: "      - name: Run package gate\n        working-directory: shadow\n", wantErr: "must not override shell or working-directory"},
		{name: "step null working directory", old: "      - name: Run package gate\n", replacement: "      - name: Run package gate\n        working-directory: null\n", wantErr: "must not override shell or working-directory"},
		{name: "step timeout", old: "      - name: Run package gate\n", replacement: "      - name: Run package gate\n        timeout-minutes: 1\n", wantErr: "timeout-minutes is also forbidden"},
		{name: "step environment", old: "      - name: Run package gate\n", replacement: "      - name: Run package gate\n        env:\n          NODE_OPTIONS: --require ./scripts/bypass.cjs\n", wantErr: "step \"Run package gate\" env="},
		{name: "later step shell", old: "      - name: Upload evidence\n", replacement: "      - name: Upload evidence\n        shell: bash {0} || true\n", wantErr: "step \"Upload evidence\" must not override shell"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			raw := strings.Replace(base, test.old, test.replacement, 1)
			if raw == base {
				t.Fatal("test mutation did not change the workflow")
			}
			err := validatePackageGateWorkflow([]byte(raw), expectation)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validatePackageGateWorkflow() error=%v, want %q", err, test.wantErr)
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

func TestPackageGateWorkflowOracleRejectsUnusedAllowedStepEnvironment(t *testing.T) {
	expectation := packageGateWorkflowExpectation{
		label:      "fixture",
		jobID:      "gate",
		stepName:   "Run package gate",
		runCommand: "npm run check",
		allowedStepEnv: map[string]map[string]any{
			"Missing owner step": {"MODE": "candidate"},
		},
		requiredTriggers: []workflowTriggerExpectation{{event: "pull_request"}},
	}
	err := validatePackageGateWorkflow([]byte(`
on:
  pull_request:
jobs:
  gate:
    steps:
      - name: Run package gate
        run: npm run check
`), expectation)
	if err == nil || !strings.Contains(err.Error(), "allowed env step \"Missing owner step\" count=0") {
		t.Fatalf("validatePackageGateWorkflow() error=%v, want unused allowed-step environment failure", err)
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

func TestPackageGateWorkflowOracleRejectsRequiredPriorExecutionOverride(t *testing.T) {
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
        shell: bash {0} || true
        run: go test ./internal/command/...
      - name: Verify release closeout
        run: npm run release:closeout
`), expectation)
	if err == nil || !strings.Contains(err.Error(), "step \"Run semantic tests\" must not override shell") {
		t.Fatalf("validatePackageGateWorkflow() error=%v, want prior-step execution override failure", err)
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
