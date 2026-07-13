package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const maxPlaywrightReportBytes = 8 << 20

var requiredBrowserProjects = []string{"chromium", "firefox", "webkit"}

type browserProjectExecution struct {
	BrowserName    string
	BrowserVersion string
	Name           string
	TestIDs        []string
}

func writeAdmittedPlaywrightReport(root, reportPath string) error {
	info, err := os.Lstat(reportPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("playwright report must be a regular non-symlink file")
	}
	if info.Size() > maxPlaywrightReportBytes {
		return fmt.Errorf("playwright report exceeds the input size limit")
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return err
	}
	manifest, err := loadProofInputManifest(root)
	if err != nil {
		return err
	}
	resolution, err := resolveProofInputs(root, manifest)
	if err != nil {
		return err
	}
	admittedPaths := make(map[string]struct{}, len(resolution.InputPaths))
	for _, path := range resolution.InputPaths {
		admittedPaths[path] = struct{}{}
	}
	projects, err := admitPlaywrightReport(bytes.NewReader(raw), root, manifest.TestRoot, admittedPaths)
	if err != nil {
		return err
	}
	encoded, err := encodeBrowserProjectExecutions(projects)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(encoded)
	return err
}

func admitPlaywrightReport(reader io.Reader, root, testRoot string, admittedPaths map[string]struct{}) ([]browserProjectExecution, error) {
	raw, err := admission.DecodeJSON(reader, maxPlaywrightReportBytes)
	if err != nil {
		return nil, err
	}
	report, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("playwright report must be an object")
	}
	if err := admit.KnownKeys(report, []string{"config", "errors", "stats", "suites"}, "playwright report"); err != nil {
		return nil, err
	}
	projectIDs, err := admitPlaywrightConfig(report["config"], root, testRoot)
	if err != nil {
		return nil, err
	}
	errors, ok := report["errors"].([]any)
	if !ok || len(errors) != 0 {
		return nil, fmt.Errorf("playwright report must contain no aggregate errors")
	}
	suites, ok := report["suites"].([]any)
	if !ok || len(suites) == 0 {
		return nil, fmt.Errorf("playwright report must contain suites")
	}
	testsByProject := make(map[string]map[string]struct{}, len(requiredBrowserProjects))
	browserVersions := make(map[string]string, len(requiredBrowserProjects))
	for _, project := range requiredBrowserProjects {
		testsByProject[project] = map[string]struct{}{}
	}
	if err := collectPlaywrightSuites(suites, nil, testRoot, admittedPaths, projectIDs, browserVersions, testsByProject); err != nil {
		return nil, err
	}
	projects := make([]browserProjectExecution, len(requiredBrowserProjects))
	totalExecutions := 0
	for index, name := range requiredBrowserProjects {
		testIDs := make([]string, 0, len(testsByProject[name]))
		for testID := range testsByProject[name] {
			testIDs = append(testIDs, testID)
		}
		slices.Sort(testIDs)
		if len(testIDs) == 0 {
			return nil, fmt.Errorf("required Playwright project executed no tests")
		}
		browserVersion := browserVersions[name]
		if browserVersion == "" {
			return nil, fmt.Errorf("required Playwright project recorded no runtime browser version")
		}
		projects[index] = browserProjectExecution{BrowserName: name, BrowserVersion: browserVersion, Name: name, TestIDs: testIDs}
		totalExecutions += len(testIDs)
	}
	for _, project := range projects[1:] {
		if !slices.Equal(project.TestIDs, projects[0].TestIDs) {
			return nil, fmt.Errorf("playwright projects did not execute the same test identities")
		}
	}
	if err := admitPlaywrightStats(report["stats"], totalExecutions); err != nil {
		return nil, err
	}
	return projects, nil
}

func admitPlaywrightConfig(raw any, root, testRoot string) (map[string]string, error) {
	config, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("playwright report config must be an object")
	}
	expectedRoot := filepath.ToSlash(filepath.Join(root, filepath.FromSlash(testRoot)))
	if config["rootDir"] != expectedRoot {
		return nil, fmt.Errorf("playwright report rootDir does not match the content-bound test root")
	}
	projects, ok := config["projects"].([]any)
	if !ok || len(projects) != len(requiredBrowserProjects) {
		return nil, fmt.Errorf("playwright report config must contain the required projects")
	}
	projectIDs := make(map[string]string, len(projects))
	for index, expectedName := range requiredBrowserProjects {
		project, ok := projects[index].(map[string]any)
		if !ok || project["name"] != expectedName || project["testDir"] != expectedRoot {
			return nil, fmt.Errorf("playwright report project configuration is invalid")
		}
		projectID, err := admit.NonEmptyText(project["id"], "playwright report project id")
		if err != nil {
			return nil, err
		}
		if _, duplicate := projectIDs[expectedName]; duplicate {
			return nil, fmt.Errorf("playwright report project configuration is duplicated")
		}
		projectIDs[expectedName] = projectID
	}
	return projectIDs, nil
}

func collectPlaywrightSuites(suites []any, parentTitles []string, testRoot string, admittedPaths map[string]struct{}, projectIDs, browserVersions map[string]string, testsByProject map[string]map[string]struct{}) error {
	for _, rawSuite := range suites {
		suite, ok := rawSuite.(map[string]any)
		if !ok {
			return fmt.Errorf("playwright suite must be an object")
		}
		if err := admit.KnownKeys(suite, []string{"column", "file", "line", "specs", "suites", "title"}, "playwright suite"); err != nil {
			return err
		}
		title, err := admit.NonEmptyText(suite["title"], "playwright suite title")
		if err != nil {
			return err
		}
		titles := append(slices.Clone(parentTitles), title)
		if rawSpecs, exists := suite["specs"]; exists {
			specs, ok := rawSpecs.([]any)
			if !ok {
				return fmt.Errorf("playwright suite specs must be an array")
			}
			for _, rawSpec := range specs {
				if err := collectPlaywrightSpec(rawSpec, titles, testRoot, admittedPaths, projectIDs, browserVersions, testsByProject); err != nil {
					return err
				}
			}
		}
		if rawSuites, exists := suite["suites"]; exists {
			children, ok := rawSuites.([]any)
			if !ok {
				return fmt.Errorf("playwright nested suites must be an array")
			}
			if err := collectPlaywrightSuites(children, titles, testRoot, admittedPaths, projectIDs, browserVersions, testsByProject); err != nil {
				return err
			}
		}
	}
	return nil
}

func collectPlaywrightSpec(raw any, parentTitles []string, testRoot string, admittedPaths map[string]struct{}, projectIDs, browserVersions map[string]string, testsByProject map[string]map[string]struct{}) error {
	spec, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("playwright spec must be an object")
	}
	if err := admit.KnownKeys(spec, []string{"column", "file", "id", "line", "ok", "tags", "tests", "title"}, "playwright spec"); err != nil {
		return err
	}
	if spec["ok"] != true {
		return fmt.Errorf("playwright spec status must be successful")
	}
	path, err := admittedPlaywrightSpecPath(spec["file"], testRoot, admittedPaths)
	if err != nil {
		return err
	}
	title, err := admit.NonEmptyText(spec["title"], "playwright spec title")
	if err != nil {
		return err
	}
	testID, err := admit.NonEmptyText(path+"::"+strings.Join(append(slices.Clone(parentTitles), title), " > "), "playwright test identity")
	if err != nil {
		return err
	}
	tests, ok := spec["tests"].([]any)
	if !ok || len(tests) == 0 {
		return fmt.Errorf("playwright spec must contain tests")
	}
	for _, rawTest := range tests {
		if err := collectPlaywrightTest(rawTest, testID, projectIDs, browserVersions, testsByProject); err != nil {
			return err
		}
	}
	return nil
}

func admittedPlaywrightSpecPath(raw any, testRoot string, admittedPaths map[string]struct{}) (string, error) {
	reported, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("playwright spec file must be an admitted browser test path")
	}
	reported, err := admit.SafeRepoRelativePath(reported, "playwright spec file")
	if err != nil {
		return "", fmt.Errorf("playwright spec file must be an admitted browser test path")
	}
	candidate := testRoot + "/" + reported
	if _, exists := admittedPaths[candidate]; exists {
		return candidate, nil
	}
	return "", fmt.Errorf("playwright spec file is outside the content-bound input set")
}

func collectPlaywrightTest(raw any, testID string, projectIDs, browserVersions map[string]string, testsByProject map[string]map[string]struct{}) error {
	test, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("playwright test must be an object")
	}
	if err := admit.KnownKeys(test, []string{"annotations", "expectedStatus", "projectId", "projectName", "results", "status", "timeout"}, "playwright test"); err != nil {
		return err
	}
	project, ok := test["projectName"].(string)
	identities, exists := testsByProject[project]
	if !ok || !exists {
		return fmt.Errorf("playwright report contains an unexpected project")
	}
	if test["projectId"] != projectIDs[project] {
		return fmt.Errorf("playwright report test is not bound to its configured project")
	}
	browserVersion, err := admitBrowserRuntimeAnnotations(test["annotations"], project)
	if err != nil {
		return err
	}
	if previous := browserVersions[project]; previous != "" && previous != browserVersion {
		return fmt.Errorf("playwright project tests recorded inconsistent runtime browser versions")
	}
	browserVersions[project] = browserVersion
	if test["expectedStatus"] != "passed" || test["status"] != "expected" {
		return fmt.Errorf("playwright test status is not an expected pass")
	}
	results, ok := test["results"].([]any)
	if !ok || len(results) != 1 {
		return fmt.Errorf("playwright test must have exactly one non-retried result")
	}
	result, ok := results[0].(map[string]any)
	if !ok {
		return fmt.Errorf("playwright test result must be an object")
	}
	if err := admit.KnownKeys(result, []string{"annotations", "attachments", "duration", "errors", "parallelIndex", "retry", "startTime", "status", "stderr", "stdout", "workerIndex"}, "playwright test result"); err != nil {
		return err
	}
	resultErrors, ok := result["errors"].([]any)
	if result["status"] != "passed" || !admit.JSONNumberEquals(result["retry"], 0) || !ok || len(resultErrors) != 0 {
		return fmt.Errorf("playwright test result is not a clean first-attempt pass")
	}
	if _, duplicate := identities[testID]; duplicate {
		return fmt.Errorf("playwright report duplicates a project test identity")
	}
	identities[testID] = struct{}{}
	return nil
}

func admitBrowserRuntimeAnnotations(raw any, expectedEngine string) (string, error) {
	annotations, ok := raw.([]any)
	if !ok {
		return "", fmt.Errorf("playwright test must record its runtime browser identity")
	}
	engineCount := 0
	versionCount := 0
	browserVersion := ""
	for _, rawAnnotation := range annotations {
		annotation, ok := rawAnnotation.(map[string]any)
		if !ok {
			return "", fmt.Errorf("playwright test annotation must be an object")
		}
		switch annotation["type"] {
		case "proofkit.browser-engine":
			if annotation["description"] != expectedEngine {
				return "", fmt.Errorf("playwright test runtime browser engine does not match its project")
			}
			engineCount++
		case "proofkit.browser-version":
			version, err := admit.NonEmptyText(annotation["description"], "playwright runtime browser version")
			if err != nil {
				return "", err
			}
			browserVersion = version
			versionCount++
		}
	}
	if engineCount != 1 || versionCount != 1 {
		return "", fmt.Errorf("playwright test must record exactly one runtime browser engine and version")
	}
	return browserVersion, nil
}

func admitPlaywrightStats(raw any, expectedExecutions int) error {
	stats, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("playwright report stats must be an object")
	}
	if err := admit.KnownKeys(stats, []string{"duration", "expected", "flaky", "skipped", "startTime", "unexpected"}, "playwright report stats"); err != nil {
		return err
	}
	if !admit.JSONNumberEquals(stats["expected"], int64(expectedExecutions)) ||
		!admit.JSONNumberEquals(stats["flaky"], 0) ||
		!admit.JSONNumberEquals(stats["skipped"], 0) ||
		!admit.JSONNumberEquals(stats["unexpected"], 0) {
		return fmt.Errorf("playwright report stats do not prove an all-passing execution")
	}
	return nil
}

func encodeBrowserProjectExecutions(projects []browserProjectExecution) ([]byte, error) {
	values := make([]any, len(projects))
	for index, project := range projects {
		testIDs := make([]any, len(project.TestIDs))
		for testIndex, testID := range project.TestIDs {
			testIDs[testIndex] = testID
		}
		values[index] = map[string]any{
			"browserName":       project.BrowserName,
			"browserVersion":    project.BrowserVersion,
			"executedTestCount": len(testIDs),
			"name":              project.Name,
			"passedTestCount":   len(testIDs),
			"testIds":           testIDs,
		}
	}
	return stablejson.MarshalLayout(values, stablejson.LayoutCompact)
}
