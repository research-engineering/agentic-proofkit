package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAdmitPlaywrightReportRequiresCleanEquivalentProjectExecutions(t *testing.T) {
	root := t.TempDir()
	report := validPlaywrightReport(root)
	projects, err := admitPlaywrightReport(bytes.NewReader(encodePlaywrightReport(t, report)), root, "tests/browser", admittedBrowserTestPaths())
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 3 || projects[0].Name != "chromium" || projects[1].Name != "firefox" || projects[2].Name != "webkit" {
		t.Fatalf("unexpected projects: %#v", projects)
	}
	if len(projects[0].TestIDs) != 2 || !slices.Equal(projects[0].TestIDs, projects[1].TestIDs) || !slices.Equal(projects[1].TestIDs, projects[2].TestIDs) {
		t.Fatalf("project test identities are not equivalent: %#v", projects)
	}
	if projects[0].BrowserVersion != "123.0" || projects[1].BrowserVersion != "123.0" || projects[2].BrowserVersion != "123.0" {
		t.Fatalf("project runtime versions were not admitted: %#v", projects)
	}
}

func TestAdmitPlaywrightReportResolvesTestDirRelativeSpecPaths(t *testing.T) {
	root := t.TempDir()
	report := validPlaywrightReport(root)
	for _, rawSpec := range firstPlaywrightSuite(report)["specs"].([]any) {
		rawSpec.(map[string]any)["file"] = "workspace.spec.mjs"
	}
	projects, err := admitPlaywrightReport(bytes.NewReader(encodePlaywrightReport(t, report)), root, "tests/browser", admittedBrowserTestPaths())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(projects[0].TestIDs[0], "tests/browser/workspace.spec.mjs::") {
		t.Fatalf("test identity is not repository-relative: %q", projects[0].TestIDs[0])
	}
}

func TestAdmitPlaywrightReportRejectsInvalidEvidenceSemantics(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "aggregate errors", mutate: func(report map[string]any) { report["errors"] = []any{map[string]any{"message": "failure"}} }},
		{name: "unexpected test status", mutate: func(report map[string]any) { firstPlaywrightTest(report)["status"] = "unexpected" }},
		{name: "flaky test status", mutate: func(report map[string]any) { firstPlaywrightTest(report)["status"] = "flaky" }},
		{name: "retried result", mutate: func(report map[string]any) { firstPlaywrightResult(report)["retry"] = 1 }},
		{name: "result errors", mutate: func(report map[string]any) {
			firstPlaywrightResult(report)["errors"] = []any{map[string]any{"message": "failure"}}
		}},
		{name: "unsafe spec path", mutate: func(report map[string]any) { firstPlaywrightSpec(report)["file"] = "../outside.spec.mjs" }},
		{name: "unbound spec path", mutate: func(report map[string]any) { firstPlaywrightSpec(report)["file"] = "tests/browser/unbound.spec.mjs" }},
		{name: "unbound root directory", mutate: func(report map[string]any) {
			report["config"].(map[string]any)["rootDir"] = "/tmp/unbound-browser-tests"
		}},
		{name: "unbound project test directory", mutate: func(report map[string]any) { firstPlaywrightProject(report)["testDir"] = "/tmp/unbound-browser-tests" }},
		{name: "mismatched project id", mutate: func(report map[string]any) { firstPlaywrightTest(report)["projectId"] = "other" }},
		{name: "remapped runtime engine", mutate: func(report map[string]any) { firstPlaywrightEngineAnnotation(report)["description"] = "webkit" }},
		{name: "missing runtime version", mutate: func(report map[string]any) {
			firstPlaywrightTest(report)["annotations"] = firstPlaywrightTest(report)["annotations"].([]any)[:1]
		}},
		{name: "inconsistent runtime version", mutate: func(report map[string]any) { firstPlaywrightVersionAnnotation(report)["description"] = "999.0" }},
		{name: "non-text suite title", mutate: func(report map[string]any) {
			firstPlaywrightSuite(report)["title"] = map[string]any{"value": "workspace"}
		}},
		{name: "stats mismatch", mutate: func(report map[string]any) { report["stats"].(map[string]any)["expected"] = 5 }},
		{name: "missing project", mutate: func(report map[string]any) {
			tests := firstPlaywrightSpec(report)["tests"].([]any)
			firstPlaywrightSpec(report)["tests"] = tests[:2]
		}},
		{name: "extra project", mutate: func(report map[string]any) {
			firstPlaywrightSpec(report)["tests"] = append(firstPlaywrightSpec(report)["tests"].([]any), passingPlaywrightTest("mobile"))
			report["stats"].(map[string]any)["expected"] = 7
		}},
		{name: "duplicate identity", mutate: func(report map[string]any) {
			firstPlaywrightSpec(report)["tests"] = append(firstPlaywrightSpec(report)["tests"].([]any), passingPlaywrightTest("chromium"))
			report["stats"].(map[string]any)["expected"] = 7
		}},
		{name: "different project test sets", mutate: func(report map[string]any) {
			specs := firstPlaywrightSuite(report)["specs"].([]any)
			second := specs[1].(map[string]any)
			second["tests"] = second["tests"].([]any)[:2]
			report["stats"].(map[string]any)["expected"] = 5
		}},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			root := t.TempDir()
			report := validPlaywrightReport(root)
			item.mutate(report)
			if _, err := admitPlaywrightReport(bytes.NewReader(encodePlaywrightReport(t, report)), root, "tests/browser", admittedBrowserTestPaths()); err == nil {
				t.Fatal("expected report admission failure")
			}
		})
	}
}

func TestAdmitPlaywrightReportRejectsDuplicateJSONKeys(t *testing.T) {
	root := t.TempDir()
	encoded := string(encodePlaywrightReport(t, validPlaywrightReport(root)))
	duplicated := strings.Replace(encoded, `"suites":`, `"suites":[],"suites":`, 1)
	if _, err := admitPlaywrightReport(strings.NewReader(duplicated), root, "tests/browser", admittedBrowserTestPaths()); err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("expected duplicate-key rejection, got %v", err)
	}
}

func validPlaywrightReport(root string) map[string]any {
	testRoot := filepath.ToSlash(filepath.Join(root, "tests/browser"))
	return map[string]any{
		"config": map[string]any{
			"rootDir": testRoot,
			"projects": []any{
				map[string]any{"id": "chromium", "name": "chromium", "testDir": testRoot},
				map[string]any{"id": "firefox", "name": "firefox", "testDir": testRoot},
				map[string]any{"id": "webkit", "name": "webkit", "testDir": testRoot},
			},
		},
		"errors": []any{},
		"stats":  map[string]any{"duration": 1, "expected": 6, "flaky": 0, "skipped": 0, "startTime": "2026-07-13T00:00:00Z", "unexpected": 0},
		"suites": []any{map[string]any{
			"title": "workspace.spec.mjs",
			"specs": []any{
				map[string]any{"file": "workspace.spec.mjs", "ok": true, "title": "renders authority", "tests": passingPlaywrightTests()},
				map[string]any{"file": "workspace.spec.mjs", "ok": true, "title": "creates handoff", "tests": passingPlaywrightTests()},
			},
		}},
	}
}

func passingPlaywrightTests() []any {
	return []any{passingPlaywrightTest("chromium"), passingPlaywrightTest("firefox"), passingPlaywrightTest("webkit")}
}

func passingPlaywrightTest(project string) map[string]any {
	return map[string]any{
		"annotations": []any{
			map[string]any{"description": project, "type": "proofkit.browser-engine"},
			map[string]any{"description": "123.0", "type": "proofkit.browser-version"},
		},
		"expectedStatus": "passed",
		"projectId":      project,
		"projectName":    project,
		"results":        []any{map[string]any{"errors": []any{}, "retry": 0, "status": "passed"}},
		"status":         "expected",
	}
}

func admittedBrowserTestPaths() map[string]struct{} {
	return map[string]struct{}{"tests/browser/workspace.spec.mjs": {}}
}

func encodePlaywrightReport(t *testing.T, report map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func firstPlaywrightSuite(report map[string]any) map[string]any {
	return report["suites"].([]any)[0].(map[string]any)
}

func firstPlaywrightProject(report map[string]any) map[string]any {
	return report["config"].(map[string]any)["projects"].([]any)[0].(map[string]any)
}

func firstPlaywrightSpec(report map[string]any) map[string]any {
	return firstPlaywrightSuite(report)["specs"].([]any)[0].(map[string]any)
}

func firstPlaywrightTest(report map[string]any) map[string]any {
	return firstPlaywrightSpec(report)["tests"].([]any)[0].(map[string]any)
}

func firstPlaywrightResult(report map[string]any) map[string]any {
	return firstPlaywrightTest(report)["results"].([]any)[0].(map[string]any)
}

func firstPlaywrightEngineAnnotation(report map[string]any) map[string]any {
	return firstPlaywrightTest(report)["annotations"].([]any)[0].(map[string]any)
}

func firstPlaywrightVersionAnnotation(report map[string]any) map[string]any {
	return firstPlaywrightTest(report)["annotations"].([]any)[1].(map[string]any)
}
