package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

type securityScannerPermissionExpectation struct {
	name                string
	path                string
	workflowPermissions map[string]string
	advisoryJobs        map[string]map[string]string
	providerJobs        map[string]map[string]string
}

func TestSecurityScannerWorkflowsSeparateProviderPublicationPermissions(t *testing.T) {
	cases := []securityScannerPermissionExpectation{
		{
			name:                "codeql",
			path:                filepath.Join("..", ".github", "workflows", "codeql.yml"),
			workflowPermissions: map[string]string{"actions": "read", "contents": "read"},
			advisoryJobs:        map[string]map[string]string{"analyze": nil},
			providerJobs: map[string]map[string]string{
				"upload-sarif": {"actions": "read", "contents": "read", "security-events": "write"},
			},
		},
		{
			name:                "osv",
			path:                filepath.Join("..", ".github", "workflows", "osv-scanner.yml"),
			workflowPermissions: map[string]string{"actions": "read", "contents": "read"},
			advisoryJobs:        map[string]map[string]string{"scan": nil},
			providerJobs: map[string]map[string]string{
				"upload-sarif": {"actions": "read", "contents": "read", "security-events": "write"},
			},
		},
		{
			name:                "scorecard",
			path:                filepath.Join("..", ".github", "workflows", "scorecard.yml"),
			workflowPermissions: map[string]string{},
			advisoryJobs: map[string]map[string]string{
				"scorecard": {"checks": "read", "contents": "read", "issues": "read", "pull-requests": "read"},
			},
			providerJobs: map[string]map[string]string{
				"upload-sarif": {"actions": "read", "contents": "read", "security-events": "write"},
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			workflow := readWorkflowForTest(t, item.path)
			if err := validateSecurityScannerPermissionSeparation(workflow, item); err != nil {
				t.Fatalf("owner scanner permissions: %v", err)
			}

			missingWorkflowPermissions := cloneWorkflow(t, workflow)
			missingWorkflowPermissions.Permissions = nil
			if err := validateSecurityScannerPermissionSeparation(missingWorkflowPermissions, item); err == nil {
				t.Fatal("scanner permission oracle admitted missing workflow permission floor")
			}

			advisoryWrite := cloneWorkflow(t, workflow)
			for jobID := range item.advisoryJobs {
				job := advisoryWrite.Jobs[jobID]
				job.Permissions = map[string]any{"contents": "write"}
				advisoryWrite.Jobs[jobID] = job
				break
			}
			if err := validateSecurityScannerPermissionSeparation(advisoryWrite, item); err == nil {
				t.Fatal("scanner permission oracle admitted advisory write authority")
			}

			providerSurplus := cloneWorkflow(t, workflow)
			for jobID := range item.providerJobs {
				job := providerSurplus.Jobs[jobID]
				permissions := job.Permissions.(map[string]any)
				permissions["contents"] = "write"
				job.Permissions = permissions
				providerSurplus.Jobs[jobID] = job
				break
			}
			if err := validateSecurityScannerPermissionSeparation(providerSurplus, item); err == nil {
				t.Fatal("scanner permission oracle admitted surplus provider write authority")
			}

			unclassifiedWriteJob := cloneWorkflow(t, workflow)
			unclassifiedWriteJob.Jobs["unclassified-write"] = githubJob{
				Permissions: map[string]any{"contents": "write"},
			}
			if err := validateSecurityScannerPermissionSeparation(unclassifiedWriteJob, item); err == nil {
				t.Fatal("scanner permission oracle admitted an unclassified job")
			}
		})
	}
}

func TestOSVSourceScanFailsForEveryNonzeroScannerStatus(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "osv-scanner.yml"))
	job := workflow.Jobs["scan"]
	run := ""
	for _, step := range job.Steps {
		if step.Name == "Run OSV source scan" {
			run = step.Run
			break
		}
	}
	if run == "" {
		t.Fatal("OSV workflow is missing the source scan step")
	}
	if !strings.Contains(run, `if [ "$scanner_status" -ne 0 ]`) || !strings.Contains(run, `exit "$scanner_status"`) {
		t.Fatal("OSV source scan must fail for vulnerability status 1 and scanner errors")
	}
	for _, weak := range []string{`[ "$scanner_status" -gt 1 ]`, `[ "$scanner_status" -eq 1 ]`} {
		if strings.Contains(run, weak) {
			t.Fatalf("OSV source scan contains partial status gate %q", weak)
		}
	}
	upload := workflow.Jobs["upload-sarif"]
	if canonicalWorkflowExpression(upload.If) != "!cancelled()&&needs.scan.result!='skipped'&&github.event_name!='pull_request'&&(github.event.repository.private==false||vars.enable_code_scanning_upload=='true')" {
		t.Fatalf("OSV provider upload must run after a finding failure but not after cancellation or a skipped scan: if=%q", upload.If)
	}
	if needs, ok := upload.Needs.(string); !ok || needs != "scan" {
		t.Fatalf("OSV provider upload needs=%#v, want scan", upload.Needs)
	}
}

func validateSecurityScannerPermissionSeparation(
	workflow githubWorkflow,
	expectation securityScannerPermissionExpectation,
) error {
	if !permissionSetEquals(workflow.Permissions, expectation.workflowPermissions) {
		return fmt.Errorf(
			"%s workflow permissions=%#v, want exact %#v",
			expectation.path,
			workflow.Permissions,
			expectation.workflowPermissions,
		)
	}
	expectedJobCount := len(expectation.advisoryJobs) + len(expectation.providerJobs)
	if len(workflow.Jobs) != expectedJobCount {
		return fmt.Errorf(
			"%s jobs=%d, want exact advisory/provider inventory of %d",
			expectation.path,
			len(workflow.Jobs),
			expectedJobCount,
		)
	}
	for jobID, permissions := range expectation.advisoryJobs {
		job, ok := workflow.Jobs[jobID]
		if !ok {
			return fmt.Errorf("%s missing advisory job %q", expectation.path, jobID)
		}
		if permissions == nil {
			if job.Permissions != nil {
				return fmt.Errorf("%s advisory job %q must inherit the exact workflow permission floor", expectation.path, jobID)
			}
			continue
		}
		if !permissionSetEquals(job.Permissions, permissions) {
			return fmt.Errorf(
				"%s advisory job %q permissions=%#v, want exact %#v",
				expectation.path,
				jobID,
				job.Permissions,
				permissions,
			)
		}
	}
	for jobID, permissions := range expectation.providerJobs {
		job, ok := workflow.Jobs[jobID]
		if !ok {
			return fmt.Errorf("%s missing provider job %q", expectation.path, jobID)
		}
		if expectation.name == "codeql" || expectation.name == "osv" {
			if !providerUploadDisabledOnPullRequest(expectation.name, job.If) {
				return fmt.Errorf(
					"%s provider job %q must not upload provider evidence on pull_request: if=%q",
					expectation.path,
					jobID,
					job.If,
				)
			}
		}
		if !permissionSetEquals(job.Permissions, permissions) {
			return fmt.Errorf(
				"%s provider job %q permissions=%#v, want exact %#v",
				expectation.path,
				jobID,
				job.Permissions,
				permissions,
			)
		}
	}
	return nil
}

func permissionSetEquals(raw any, want map[string]string) bool {
	record, ok := raw.(map[string]any)
	if !ok || len(record) != len(want) {
		return false
	}
	for key, value := range want {
		actual, ok := record[key].(string)
		if !ok || !strings.EqualFold(strings.TrimSpace(actual), value) {
			return false
		}
	}
	return true
}

func providerUploadDisabledOnPullRequest(scanner string, expression string) bool {
	expected := "github.event_name!='pull_request'&&(github.event.repository.private==false||vars.enable_code_scanning_upload=='true')"
	if scanner == "osv" {
		expected = "!cancelled()&&needs.scan.result!='skipped'&&" + expected
	}
	return canonicalWorkflowExpression(expression) == expected
}

func TestScorecardPublicPublishDeclaresRequiredOutputInputs(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "scorecard-publish.yml"))
	if !permissionSetEquals(workflow.Permissions, map[string]string{}) {
		t.Fatalf("scorecard publish workflow permissions=%#v, want exact empty map", workflow.Permissions)
	}
	if len(workflow.Jobs) != 1 {
		t.Fatalf("scorecard publish workflow must contain exactly one job, got %d", len(workflow.Jobs))
	}
	job, ok := workflow.Jobs["scorecard"]
	if !ok {
		t.Fatalf("scorecard workflow missing public publish job")
	}
	wantPermissions := map[string]string{
		"checks":        "read",
		"contents":      "read",
		"id-token":      "write",
		"issues":        "read",
		"pull-requests": "read",
	}
	if !permissionSetEquals(job.Permissions, wantPermissions) {
		t.Fatalf("scorecard public publish permissions=%#v, want exact %#v", job.Permissions, wantPermissions)
	}
	stepIndex, err := uniqueStepIndex(job.Steps, "Publish Scorecard results")
	if err != nil {
		t.Fatal(err)
	}
	if stepIndex < 0 {
		t.Fatalf("scorecard public publish job missing Scorecard action step")
	}
	step := job.Steps[stepIndex]
	if !isScorecardActionReference(step.Uses) {
		t.Fatalf("public publish step uses %q, want ossf/scorecard-action", step.Uses)
	}
	if !scorecardActionBoundaryIsExact(job.Steps, stepIndex) {
		t.Fatalf("scorecard public publish boundary is not exact at step %d", stepIndex)
	}

	missingWorkflowPermissions := cloneWorkflow(t, workflow)
	missingWorkflowPermissions.Permissions = nil
	if permissionSetEquals(missingWorkflowPermissions.Permissions, map[string]string{}) {
		t.Fatal("scorecard publish permission oracle admitted a missing workflow permission floor")
	}
	surplusProviderPermission := cloneWorkflow(t, workflow)
	surplusJob := surplusProviderPermission.Jobs["scorecard"]
	surplusPermissions := surplusJob.Permissions.(map[string]any)
	surplusPermissions["actions"] = "write"
	surplusJob.Permissions = surplusPermissions
	surplusProviderPermission.Jobs["scorecard"] = surplusJob
	if permissionSetEquals(surplusJob.Permissions, wantPermissions) {
		t.Fatal("scorecard publish permission oracle admitted surplus provider write authority")
	}
	surplusOutputInput := cloneWorkflow(t, workflow)
	surplusOutputInputJob := surplusOutputInput.Jobs["scorecard"]
	surplusOutputInputStep := surplusOutputInputJob.Steps[stepIndex]
	surplusOutputInputStep.With["repo_token"] = "${{ github.token }}"
	surplusOutputInputJob.Steps[stepIndex] = surplusOutputInputStep
	surplusOutputInput.Jobs["scorecard"] = surplusOutputInputJob
	if scorecardActionBoundaryIsExact(surplusOutputInputJob.Steps, stepIndex) {
		t.Fatal("scorecard publish input oracle admitted a surplus authority-bearing input")
	}
	substitutedOutputValue := cloneWorkflow(t, workflow)
	substitutedOutputValueJob := substitutedOutputValue.Jobs["scorecard"]
	substitutedOutputValueStep := substitutedOutputValueJob.Steps[stepIndex]
	substitutedOutputValueStep.With["publish_results"] = "true }}"
	substitutedOutputValueJob.Steps[stepIndex] = substitutedOutputValueStep
	substitutedOutputValue.Jobs["scorecard"] = substitutedOutputValueJob
	if scorecardActionBoundaryIsExact(substitutedOutputValueJob.Steps, stepIndex) {
		t.Fatal("scorecard publish input oracle admitted a substituted boolean value")
	}
	secondScorecardAction := cloneWorkflow(t, workflow)
	secondScorecardActionJob := secondScorecardAction.Jobs["scorecard"]
	secondScorecardActionJob.Steps = append(secondScorecardActionJob.Steps, githubStep{
		Name: "Unexpected second Scorecard action",
		Uses: step.Uses,
		With: map[string]any{
			"publish_results": true,
			"repo_token":      "${{ github.token }}",
			"results_file":    "scorecard-public-results.json",
			"results_format":  "json",
		},
	})
	secondScorecardAction.Jobs["scorecard"] = secondScorecardActionJob
	if scorecardActionBoundaryIsExact(secondScorecardActionJob.Steps, stepIndex) {
		t.Fatal("scorecard publish oracle admitted a second Scorecard action")
	}
	_, scorecardRef, _ := strings.Cut(step.Uses, "@")
	caseVariantScorecardAction := cloneWorkflow(t, workflow)
	caseVariantScorecardActionJob := caseVariantScorecardAction.Jobs["scorecard"]
	caseVariantScorecardActionJob.Steps = append(caseVariantScorecardActionJob.Steps, githubStep{
		Name: "Unexpected case-variant Scorecard action",
		Uses: "OSSF/Scorecard-Action@" + scorecardRef,
		With: map[string]any{
			"publish_results": true,
			"repo_token":      "${{ github.token }}",
			"results_file":    "scorecard-public-results.json",
			"results_format":  "json",
		},
	})
	caseVariantScorecardAction.Jobs["scorecard"] = caseVariantScorecardActionJob
	if scorecardActionBoundaryIsExact(caseVariantScorecardActionJob.Steps, stepIndex) {
		t.Fatal("scorecard publish oracle admitted a case-variant second Scorecard action")
	}
	for _, otherAction := range []string{
		"ossf/scorecard-action-extra@" + scorecardRef,
		"ossf/scorecard-action/subpath@" + scorecardRef,
		"ossf/scorecard-action",
		"ossf/scorecard-action@",
		"ossf/scorecard-action@@" + scorecardRef,
		"o\u017f\u017ff/\u017fcorecard-action@" + scorecardRef,
	} {
		if isScorecardActionReference(otherAction) {
			t.Fatalf("scorecard action classifier admitted distinct or malformed reference %q", otherAction)
		}
	}
}

func scorecardActionBoundaryIsExact(steps []githubStep, selectedIndex int) bool {
	if selectedIndex < 0 || selectedIndex >= len(steps) {
		return false
	}
	scorecardActionCount := 0
	scorecardActionIndex := -1
	for index, step := range steps {
		if isScorecardActionReference(step.Uses) {
			scorecardActionCount++
			scorecardActionIndex = index
		}
	}
	return scorecardActionCount == 1 &&
		scorecardActionIndex == selectedIndex &&
		scorecardOutputInputsEqual(steps[selectedIndex].With)
}

func isScorecardActionReference(value string) bool {
	repository, ref, found := strings.Cut(value, "@")
	return found &&
		repository != "" &&
		ref != "" &&
		!strings.Contains(ref, "@") &&
		isASCII(repository) &&
		strings.EqualFold(repository, "ossf/scorecard-action")
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] > 0x7f {
			return false
		}
	}
	return true
}

func scorecardOutputInputsEqual(values map[string]any) bool {
	publishResults, publishResultsIsBool := values["publish_results"].(bool)
	return len(values) == 3 &&
		publishResultsIsBool &&
		publishResults &&
		withString(values, "results_file") == "scorecard-public-results.json" &&
		withString(values, "results_format") == "json"
}
