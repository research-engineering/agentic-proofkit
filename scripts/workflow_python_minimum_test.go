package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCIMinimumFailureCannotSatisfyAggregate(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err := validateCIRequiredAggregate(workflow); err != nil {
		t.Fatal(err)
	}
	// Both jobs that run the CPython 3.11.0 installed smoke are required
	// leaves: a minimum failure in either job is a job result the aggregate
	// must refuse, whatever the other leaves report.
	leaves := []string{"source-quality", "browser-runtime", "browser-visual", "browser-matrix", "platform-smoke", "platform-smoke-intel", "platform-smoke-linux-arm64"}
	for _, failing := range ciMinimumPythonJobIDs() {
		for _, status := range []string{"success", "failure", "skipped", "cancelled"} {
			t.Run(failing+"/"+status, func(t *testing.T) {
				script := workflow.Jobs["ci-required-gate"].Steps[0].Run
				for _, job := range leaves {
					value := "success"
					if job == failing {
						value = status
					}
					script = strings.ReplaceAll(script, "${{ needs."+job+".result }}", value)
				}
				if strings.Contains(script, "${{") {
					t.Fatalf("aggregate script references an unsubstituted job result: %q", script)
				}
				command := exec.CommandContext(t.Context(), "bash", "-c", script)
				output, err := command.CombinedOutput()
				if (err == nil) != (status == "success") {
					t.Fatalf("%s %s aggregate error=%v", failing, status, err)
				}
				if status != "success" && strings.Contains(string(output), "OK:") {
					t.Fatal("failed minimum lane emitted aggregate success")
				}
			})
		}
	}
}

// Each required job that runs the CPython 3.11.0 installed smoke names the
// step that produces its current release wheel set and the steps the smoke
// must precede.
var ciMinimumPythonJobs = map[string]struct {
	producer   string
	successors []string
}{
	"source-quality": {
		producer:   "Build and verify package artifacts",
		successors: []string{"Verify self-hosting receipts", "Verify self-hosting coverage", "Verify release closeout"},
	},
	linuxArm64PlatformSmokeJob: {producer: "Build release wheel set"},
}

func ciMinimumPythonJobIDs() []string {
	ids := make([]string, 0, len(ciMinimumPythonJobs))
	for id := range ciMinimumPythonJobs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func validateCIMinimumPythonStep(jobID string, job githubJob) error {
	owner, ok := ciMinimumPythonJobs[jobID]
	if !ok {
		return fmt.Errorf("CI job %s has no owner Python minimum step", jobID)
	}
	index, err := uniqueStepIndex(job.Steps, "Verify Python 3.11.0 installed wheel")
	if err != nil || index < 0 {
		return fmt.Errorf("CI job %s must contain exactly one Python minimum installed-wheel step", jobID)
	}
	step := job.Steps[index]
	if step.Run != requiredMinimumPythonCommand || !step.runPresent ||
		step.If != "" || step.ifPresent || step.ContinueOnError != nil || step.continueOnErrorPresent ||
		step.Uses != "" || step.usesPresent || step.With != nil || step.withPresent || step.Env != nil ||
		step.Shell != nil || step.shellPresent || step.WorkingDirectory != nil || step.workingDirectoryPresent ||
		step.TimeoutMinutes != nil || step.timeoutMinutesPresent || step.ID != "" || step.idPresent {
		return fmt.Errorf("CI job %s Python minimum step must be the exact unconditional owner invocation", jobID)
	}
	buildIndex, err := uniqueStepIndex(job.Steps, owner.producer)
	if err != nil || buildIndex < 0 || index != buildIndex+1 {
		return fmt.Errorf("CI job %s Python minimum step must immediately follow %s", jobID, owner.producer)
	}
	for _, successor := range owner.successors {
		next, err := uniqueStepIndex(job.Steps, successor)
		if err != nil || next <= index {
			return fmt.Errorf("CI job %s Python minimum step must precede %s", jobID, successor)
		}
	}
	return nil
}

func TestCIMinimumPythonStepRejectsOmissionAndNeutralization(t *testing.T) {
	base := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	for _, jobID := range ciMinimumPythonJobIDs() {
		if err := validateCIMinimumPythonStep(jobID, base.Jobs[jobID]); err != nil {
			t.Fatal(err)
		}
	}
	mutations := []struct {
		name   string
		jobs   []string
		change func(*githubJob, int)
	}{
		{"omitted", nil, func(job *githubJob, index int) { job.Steps = append(job.Steps[:index], job.Steps[index+1:]...) }},
		{"duplicate", nil, func(job *githubJob, index int) { job.Steps = append(job.Steps, job.Steps[index]) }},
		{"before artifact", nil, func(job *githubJob, index int) {
			job.Steps[index], job.Steps[index-1] = job.Steps[index-1], job.Steps[index]
		}},
		{"after receipts", []string{"source-quality"}, func(job *githubJob, index int) {
			job.Steps[index], job.Steps[index+1] = job.Steps[index+1], job.Steps[index]
		}},
		{"before platform smoke", []string{linuxArm64PlatformSmokeJob}, func(job *githubJob, index int) {
			step := job.Steps[index]
			job.Steps = append(job.Steps[:index], job.Steps[index+1:]...)
			smoke, err := uniqueStepIndex(job.Steps, "Run platform smoke")
			if err != nil || smoke < 0 {
				panic("owner Linux arm64 workflow lost Run platform smoke")
			}
			job.Steps = slices.Insert(job.Steps, smoke, step)
		}},
		{"wheel set omitted", []string{linuxArm64PlatformSmokeJob}, func(job *githubJob, index int) {
			job.Steps = append(job.Steps[:index-1], job.Steps[index:]...)
		}},
		{"no-op", nil, func(job *githubJob, index int) { job.Steps[index].Run = "true" }},
		{"masked exit", nil, func(job *githubJob, index int) { job.Steps[index].Run += " || true" }},
		{"background", nil, func(job *githubJob, index int) { job.Steps[index].Run += " &" }},
		{"conditional", nil, func(job *githubJob, index int) { job.Steps[index].If = "false" }},
		{"null condition", nil, func(job *githubJob, index int) { job.Steps[index].ifPresent = true }},
		{"continue on error", nil, func(job *githubJob, index int) { job.Steps[index].ContinueOnError = true }},
		{"null continue", nil, func(job *githubJob, index int) { job.Steps[index].continueOnErrorPresent = true }},
		{"shadow environment", nil, func(job *githubJob, index int) { job.Steps[index].Env = map[string]any{"PATH": "/other"} }},
		{"uses", nil, func(job *githubJob, index int) { job.Steps[index].Uses = "other/action@main" }},
		{"wrong tool", nil, func(job *githubJob, index int) { job.Steps[index].Run = "go run ./internal/tools/pythonpackage verify" }},
	}
	for _, jobID := range ciMinimumPythonJobIDs() {
		for _, mutation := range mutations {
			if mutation.jobs != nil && !slices.Contains(mutation.jobs, jobID) {
				continue
			}
			t.Run(jobID+"/"+mutation.name, func(t *testing.T) {
				workflow := cloneWorkflow(t, base)
				job := workflow.Jobs[jobID]
				index, err := uniqueStepIndex(job.Steps, "Verify Python 3.11.0 installed wheel")
				if err != nil {
					t.Fatal(err)
				}
				mutation.change(&job, index)
				workflow.Jobs[jobID] = job
				if err := validateCIMinimumPythonStep(jobID, job); err == nil {
					t.Fatal("minimum step mutation admitted by independent owner predicate")
				}
				if err := validateCIRequiredAggregate(workflow); err == nil {
					t.Fatal("minimum step mutation admitted by aggregate oracle")
				}
			})
		}
	}
}
