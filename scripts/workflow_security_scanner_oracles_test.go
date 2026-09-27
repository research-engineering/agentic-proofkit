package main

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type securityScannerPermissionExpectation struct {
	name                string
	path                string
	workflowPermissions map[string]string
	advisoryJobs        map[string]map[string]string
	providerJobs        map[string]map[string]string
}

func validateCodeQLStrategy(strategy map[string]any) error {
	want := map[string]any{
		"fail-fast": false,
		"matrix": map[string]any{"include": []any{
			map[string]any{"language": "go", "build-mode": "autobuild"},
			map[string]any{"language": "javascript-typescript", "build-mode": "none"},
			map[string]any{"language": "python", "build-mode": "none"},
		}},
	}
	if !reflect.DeepEqual(strategy, want) {
		return fmt.Errorf("CodeQL must scan exactly Go, browser JavaScript/TypeScript and Python; only Go may autobuild")
	}
	return nil
}

func validateCodeQLSourceScan(workflow githubWorkflow) error {
	if err := validateSecurityScannerPermissionSeparation(workflow, securityScannerPermissionExpectation{
		name: "codeql", path: ".github/workflows/codeql.yml",
		workflowPermissions: map[string]string{"actions": "read", "contents": "read"},
		advisoryJobs:        map[string]map[string]string{"analyze": nil},
		providerJobs:        map[string]map[string]string{"upload-sarif": {"actions": "read", "contents": "read", "security-events": "write"}},
	}); err != nil {
		return err
	}
	if !reflect.DeepEqual(workflow.On, map[string]any{
		"pull_request": nil, "workflow_dispatch": nil,
		"push":     map[string]any{"branches": []any{"main"}},
		"schedule": []any{map[string]any{"cron": "17 7 * * 1"}},
	}) || len(workflow.Env) != 0 {
		return fmt.Errorf("CodeQL trusted event inventory and environment must remain unchanged")
	}
	analyze, upload := workflow.Jobs["analyze"], workflow.Jobs["upload-sarif"]
	if err := validateCodeQLStrategy(analyze.Strategy); err != nil {
		return err
	}
	if analyze.Name != "codeql / ${{ matrix.language }}" ||
		canonicalWorkflowExpression(analyze.If) != "github.event.repository.private==false||vars.enable_code_scanning=='true'" ||
		analyze.Needs != nil || analyze.TimeoutMinutes != 20 ||
		upload.Needs != "analyze" || upload.TimeoutMinutes != 10 || len(upload.Strategy) != 0 {
		return fmt.Errorf("CodeQL job identity, analysis dependency, conditions or timeouts changed")
	}
	for _, job := range []githubJob{analyze, upload} {
		if job.RunsOn != "ubuntu-24.04" || len(job.Env) != 0 || job.Environment != nil ||
			job.ContinueOnError != nil || job.Uses != "" || job.Defaults != nil {
			return fmt.Errorf("CodeQL job adds an unowned execution boundary")
		}
	}
	const codeql = "github/codeql-action/"
	const codeqlPin = "@cdf488f595d80d6e07e03d4674febd5ab45fa938"
	if err := validateCodeQLSteps(analyze.Steps, []githubStep{
		{Name: "Checkout", Uses: "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", With: map[string]any{"persist-credentials": false}},
		{Name: "Setup Go", Uses: "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", If: "${{ matrix.language == 'go' }}", With: map[string]any{"go-version-file": "go.mod", "cache": true}},
		{Name: "Initialize CodeQL", Uses: codeql + "init" + codeqlPin, With: map[string]any{"languages": "${{ matrix.language }}", "build-mode": "${{ matrix.build-mode }}"}},
		{Name: "Analyze", ID: "analyze", Uses: codeql + "analyze" + codeqlPin, With: map[string]any{
			"output": "codeql-results", "category": "codeql-${{ matrix.language }}", "upload": "never", "upload-database": false, "wait-for-processing": false,
		}},
		{Name: "Upload CodeQL SARIF artifact", If: "${{ always() && steps.analyze.outputs.sarif-output != '' }}",
			Uses: "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", With: map[string]any{
				"name": "codeql-sarif-${{ matrix.language }}-${{ github.sha }}", "path": "codeql-results/**/*.sarif", "if-no-files-found": "error", "retention-days": 14,
			}},
	}); err != nil {
		return err
	}
	// The pinned upload action recursively discovers SARIF and preserves the
	// categories already emitted by analyze. Separate artifact directories avoid collisions.
	return validateCodeQLSteps(upload.Steps, []githubStep{
		{Name: "Download CodeQL SARIF artifact", Uses: "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", With: map[string]any{
			"pattern": "codeql-sarif-*-${{ github.sha }}", "path": "codeql-results", "merge-multiple": false,
		}},
		{Name: "Upload CodeQL SARIF", Uses: codeql + "upload-sarif" + codeqlPin, With: map[string]any{"sarif_file": "codeql-results"}},
	})
}

// A closed action inventory prevents source installs or scripts from being added
// to interpreted scans or to the write-authorized upload job.
func validateCodeQLSteps(got, want []githubStep) error {
	if len(got) != len(want) {
		return fmt.Errorf("CodeQL action inventory has %d steps, want %d", len(got), len(want))
	}
	for index, step := range got {
		expected := want[index]
		if step.Name != expected.Name || step.ID != expected.ID || step.Uses != expected.Uses ||
			canonicalWorkflowExpression(step.If) != canonicalWorkflowExpression(expected.If) ||
			!reflect.DeepEqual(step.With, expected.With) || step.Run != "" || len(step.Env) != 0 ||
			step.ContinueOnError != nil || step.Shell != nil || step.TimeoutMinutes != nil || step.WorkingDirectory != nil {
			return fmt.Errorf("CodeQL step %d (%s) changed its exact action/input/execution boundary", index, expected.Name)
		}
	}
	return nil
}

func TestCodeQLSourceScanCoversLanguagesAndAllSARIFWithoutPRWrite(t *testing.T) {
	path := filepath.Join("..", ".github", "workflows", "codeql.yml")
	workflow := readWorkflowForTest(t, path)
	if err := validateCodeQLSourceScan(workflow); err != nil {
		t.Fatal(err)
	}
	if err := validateCodeQLSourceScan(cloneWorkflow(t, workflow)); err != nil {
		t.Fatalf("unchanged YAML roundtrip must remain an admitted positive control: %v", err)
	}
	type mutation struct {
		name   string
		change func(*githubWorkflow)
	}
	mutants := []mutation{
		{"Go setup for interpreted languages", func(w *githubWorkflow) { w.Jobs["analyze"].Steps[1].If = "" }},
		{"source dependency install", func(w *githubWorkflow) {
			job := w.Jobs["analyze"]
			job.Steps = append(job.Steps, githubStep{Run: "npm install && python setup.py install"})
			w.Jobs["analyze"] = job
		}},
		{"scan subset", func(w *githubWorkflow) { w.Jobs["analyze"].Steps[2].With["languages"] = "go" }},
		{"filtered source", func(w *githubWorkflow) { w.Jobs["analyze"].Steps[2].With["source-root"] = "cmd" }},
		{"shared category", func(w *githubWorkflow) { w.Jobs["analyze"].Steps[3].With["category"] = "codeql-go" }},
		{"advisory provider upload", func(w *githubWorkflow) { w.Jobs["analyze"].Steps[3].With["upload"] = "always" }},
		{"shared artifact", func(w *githubWorkflow) { w.Jobs["analyze"].Steps[4].With["name"] = "codeql-sarif-${{ github.sha }}" }},
		{"partial artifact", func(w *githubWorkflow) { w.Jobs["analyze"].Steps[4].With["path"] = "codeql-results/go.sarif" }},
		{"flat artifact collision", func(w *githubWorkflow) { w.Jobs["upload-sarif"].Steps[0].With["merge-multiple"] = true }},
		{"download only Go", func(w *githubWorkflow) {
			w.Jobs["upload-sarif"].Steps[0].With["name"] = "codeql-sarif-go-${{ github.sha }}"
		}},
		{"upload first file", func(w *githubWorkflow) {
			job := w.Jobs["upload-sarif"]
			job.Steps[1].With["sarif_file"] = "${{ steps.sarif.outputs.path }}"
			job.Steps = append(job.Steps[:1], append([]githubStep{{ID: "sarif", Run: "find codeql-results -name '*.sarif' | sort | head -n 1"}}, job.Steps[1:]...)...)
			w.Jobs["upload-sarif"] = job
		}},
		{"single SARIF path", func(w *githubWorkflow) {
			w.Jobs["upload-sarif"].Steps[1].With["sarif_file"] = "codeql-results/go.sarif"
		}},
		{"provider category collapse", func(w *githubWorkflow) { w.Jobs["upload-sarif"].Steps[1].With["category"] = "codeql-go" }},
		{"PR write edge", func(w *githubWorkflow) {
			job := w.Jobs["upload-sarif"]
			job.If = "${{ always() }}"
			w.Jobs["upload-sarif"] = job
		}},
		{"skipped analysis edge", func(w *githubWorkflow) { job := w.Jobs["upload-sarif"]; job.Needs = nil; w.Jobs["upload-sarif"] = job }},
		{"advisory write permission", func(w *githubWorkflow) {
			job := w.Jobs["analyze"]
			job.Permissions = map[string]any{"security-events": "write"}
			w.Jobs["analyze"] = job
		}},
		{"workflow write permission", func(w *githubWorkflow) { w.Permissions.(map[string]any)["security-events"] = "write" }},
		{"trusted PR event", func(w *githubWorkflow) { w.On["pull_request_target"] = nil }},
		{"credential persistence", func(w *githubWorkflow) { w.Jobs["analyze"].Steps[0].With["persist-credentials"] = true }},
		{"unpinned action", func(w *githubWorkflow) { w.Jobs["analyze"].Steps[2].Uses = "github/codeql-action/init@main" }},
		{"cancel remaining languages", func(w *githubWorkflow) { w.Jobs["analyze"].Strategy["fail-fast"] = true }},
		{"duplicate language", func(w *githubWorkflow) {
			matrix := w.Jobs["analyze"].Strategy["matrix"].(map[string]any)
			rows := matrix["include"].([]any)
			matrix["include"] = append(rows, rows[0])
		}},
	}
	for index, language := range []string{"go", "javascript-typescript", "python"} {
		mutants = append(mutants, mutation{
			"missing " + language, func(w *githubWorkflow) {
				matrix := w.Jobs["analyze"].Strategy["matrix"].(map[string]any)
				rows := matrix["include"].([]any)
				matrix["include"] = append(rows[:index], rows[index+1:]...)
			},
		})
	}
	for index, language := range []string{"go", "javascript-typescript", "python"} {
		mutants = append(mutants, mutation{
			"wrong build mode for " + language, func(w *githubWorkflow) {
				rows := w.Jobs["analyze"].Strategy["matrix"].(map[string]any)["include"].([]any)
				rows[index].(map[string]any)["build-mode"] = "manual"
			},
		})
	}
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			changed := cloneWorkflow(t, workflow)
			mutant.change(&changed)
			// Reparse real YAML so controls exercise the same representation as the owner.
			raw, err := yaml.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			var reparsed githubWorkflow
			if err := yaml.Unmarshal(raw, &reparsed); err != nil {
				t.Fatal(err)
			}
			if err := validateCodeQLSourceScan(reparsed); err == nil {
				t.Fatal("CodeQL oracle admitted the isolated boundary mutation")
			}
		})
	}
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
