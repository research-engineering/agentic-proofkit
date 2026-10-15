package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

const setupPythonActionRepository = "actions/setup-python"
const pinnedSetupPythonUses = setupPythonActionRepository + "@5fda3b95a4ea91299a34e894583c3862153e4b97"
const pinnedPythonRuntime = "3.15.0"

// A run step depends on the host Python when it invokes python3 directly or
// runs a repository command whose Go tests or wheel verifiers exec python3.
var hostPythonConsumer = regexp.MustCompile(`\bpython3\b|npm run (check|go:test|package:artifact|platform:smoke|python:package|python:verify)\b`)

// Jobs whose run steps consume the host Python. Every other job must not.
var expectedPythonJobs = map[string][]string{
	"ci.yml":      {"platform-smoke", "source-quality"},
	"release.yml": {"candidate", "publish-pypi", "publish-readiness"},
}

func validateWorkflowPythonRuntime(file string, workflow githubWorkflow) error {
	var consumers []string
	for jobID, job := range workflow.Jobs {
		first := -1
		for index, step := range job.Steps {
			if hostPythonConsumer.MatchString(step.Run) {
				first = index
				break
			}
		}
		setupIndex, err := setupPythonStepIndex(job.Steps)
		if err != nil {
			return fmt.Errorf("%s job %q: %w", file, jobID, err)
		}
		if first < 0 {
			if setupIndex >= 0 {
				return fmt.Errorf("%s job %q sets up Python without a Python consumer", file, jobID)
			}
			continue
		}
		consumers = append(consumers, jobID)
		if setupIndex < 0 || setupIndex >= first {
			return fmt.Errorf("%s job %q must set up pinned Python before its first Python consumer", file, jobID)
		}
		setup := job.Steps[setupIndex]
		if setup.Uses != pinnedSetupPythonUses || len(setup.With) != 1 || withString(setup.With, "python-version") != pinnedPythonRuntime ||
			setup.Run != "" || setup.If != "" || setup.ifPresent || setup.Env != nil || setup.ContinueOnError != nil || setup.continueOnErrorPresent {
			return fmt.Errorf("%s job %q %s step must be the exact unconditional pinned %s runtime", file, jobID, setupPythonActionRepository, pinnedPythonRuntime)
		}
	}
	sort.Strings(consumers)
	if want := expectedPythonJobs[file]; !slices.Equal(consumers, want) {
		return fmt.Errorf("%s host Python consumer jobs=%v, want exact %v", file, consumers, want)
	}
	return nil
}

// setupPythonStepIndex finds the only Python installation by action identity,
// not display name. GitHub resolves action owner and repository names
// case-insensitively, so a case variant is the same action.
func setupPythonStepIndex(steps []githubStep) (int, error) {
	found := -1
	for index, step := range steps {
		repository, _, _ := strings.Cut(step.Uses, "@")
		if !strings.EqualFold(repository, setupPythonActionRepository) {
			continue
		}
		if found >= 0 {
			return -1, fmt.Errorf("%s must be invoked at most once", setupPythonActionRepository)
		}
		found = index
	}
	return found, nil
}

func TestWorkflowPythonConsumersUsePinnedRuntime(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", ".github", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		seen++
		workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", entry.Name()))
		if err := validateWorkflowPythonRuntime(entry.Name(), workflow); err != nil {
			t.Fatal(err)
		}
	}
	if seen < len(expectedPythonJobs) {
		t.Fatalf("workflow inventory has %d files, want at least %d", seen, len(expectedPythonJobs))
	}
}

func TestWorkflowPythonRuntimeIdentifiesActionNotDisplayName(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "release.yml"))
	job := workflow.Jobs["publish-readiness"]
	for index := range job.Steps {
		if job.Steps[index].Uses == pinnedSetupPythonUses {
			job.Steps[index].Name = "Select admitted Python"
		}
	}
	workflow.Jobs["publish-readiness"] = job
	if err := validateWorkflowPythonRuntime("release.yml", workflow); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowPythonRuntimeRejectsUnpinnedConsumers(t *testing.T) {
	base := map[string]githubWorkflow{
		"ci.yml":      readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml")),
		"release.yml": readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "release.yml")),
	}
	setupStep := func(job githubJob) int {
		index, err := setupPythonStepIndex(job.Steps)
		if err != nil || index < 0 {
			t.Fatalf("fixture job lacks one %s step: %v", setupPythonActionRepository, err)
		}
		return index
	}
	mutations := []struct {
		name, file, job string
		change          func(*githubJob)
	}{
		{"candidate setup omitted", "release.yml", "candidate", func(job *githubJob) {
			index := setupStep(*job)
			job.Steps = append(job.Steps[:index], job.Steps[index+1:]...)
		}},
		{"readiness runtime drift", "release.yml", "publish-readiness", func(job *githubJob) {
			job.Steps[setupStep(*job)].With["python-version"] = "3.14.7"
		}},
		{"readiness differently named duplicate setup", "release.yml", "publish-readiness", func(job *githubJob) {
			index, err := uniqueStepIndex(job.Steps, "Verify tag source and channel readiness")
			if err != nil || index < 0 {
				t.Fatalf("fixture job lacks readiness consumer: %v", err)
			}
			job.Steps = slices.Insert(job.Steps, index, githubStep{
				Name: "Select alternate Python",
				Uses: pinnedSetupPythonUses,
				With: map[string]any{"python-version": "3.14.7"},
			})
		}},
		{"readiness case-variant duplicate setup", "release.yml", "publish-readiness", func(job *githubJob) {
			job.Steps = append(job.Steps, githubStep{
				Name: "Select alternate Python",
				Uses: "Actions/Setup-Python@" + strings.TrimPrefix(pinnedSetupPythonUses, setupPythonActionRepository+"@"),
				With: map[string]any{"python-version": "3.14.7"},
			})
		}},
		{"pypi unpinned action", "release.yml", "publish-pypi", func(job *githubJob) {
			job.Steps[setupStep(*job)].Uses = "actions/setup-python@v7"
		}},
		{"source setup after tests", "ci.yml", "source-quality", func(job *githubJob) {
			index := setupStep(*job)
			step := job.Steps[index]
			job.Steps = append(job.Steps[:index], job.Steps[index+1:]...)
			job.Steps = append(job.Steps, step)
		}},
		{"platform conditional setup", "ci.yml", "platform-smoke", func(job *githubJob) {
			job.Steps[setupStep(*job)].If = "runner.os == 'Linux'"
		}},
		{"new unpinned consumer", "release.yml", "release-metadata", func(job *githubJob) {
			job.Steps = append(job.Steps, githubStep{Name: "Read version", Run: "python3 -c 'print(1)'", runPresent: true})
		}},
		{"browser job gains package gate", "ci.yml", "browser-runtime", func(job *githubJob) {
			job.Steps = append(job.Steps, githubStep{Name: "Package", Run: "npm run package:artifact", runPresent: true})
		}},
	}
	for file, workflow := range base {
		if err := validateWorkflowPythonRuntime(file, workflow); err != nil {
			t.Fatalf("owner %s: %v", file, err)
		}
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			workflow := cloneWorkflow(t, base[mutation.file])
			job, ok := workflow.Jobs[mutation.job]
			if !ok {
				t.Fatalf("fixture job %q missing", mutation.job)
			}
			mutation.change(&job)
			workflow.Jobs[mutation.job] = job
			if err := validateWorkflowPythonRuntime(mutation.file, workflow); err == nil {
				t.Fatal("unpinned or misplaced Python runtime admitted")
			}
		})
	}
}
