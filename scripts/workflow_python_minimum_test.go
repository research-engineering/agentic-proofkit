package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCIMinimumFailureCannotSatisfyAggregate(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err := validateCIRequiredAggregate(workflow); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"success", "failure", "skipped", "cancelled"} {
		t.Run(status, func(t *testing.T) {
			script := workflow.Jobs["ci-required-gate"].Steps[0].Run
			for _, job := range []string{"source-quality", "browser-runtime", "platform-smoke"} {
				value := "success"
				if job == "source-quality" {
					value = status
				}
				script = strings.ReplaceAll(script, "${{ needs."+job+".result }}", value)
			}
			command := exec.CommandContext(t.Context(), "bash", "-c", script)
			output, err := command.CombinedOutput()
			if (err == nil) != (status == "success") {
				t.Fatalf("source-quality %s aggregate error=%v", status, err)
			}
			if status != "success" && strings.Contains(string(output), "OK:") {
				t.Fatal("failed minimum lane emitted aggregate success")
			}
		})
	}
}

func validateCIMinimumPythonStep(job githubJob) error {
	index, err := uniqueStepIndex(job.Steps, "Verify Python 3.9.0 installed wheel")
	if err != nil || index < 0 {
		return fmt.Errorf("CI must contain exactly one Python minimum installed-wheel step")
	}
	step := job.Steps[index]
	if step.Run != "go run ./internal/tools/pythonpackage verify-minimum" || !step.runPresent ||
		step.If != "" || step.ifPresent || step.ContinueOnError != nil || step.continueOnErrorPresent ||
		step.Uses != "" || step.usesPresent || step.With != nil || step.withPresent || step.Env != nil ||
		step.Shell != nil || step.shellPresent || step.WorkingDirectory != nil || step.workingDirectoryPresent ||
		step.TimeoutMinutes != nil || step.timeoutMinutesPresent || step.ID != "" || step.idPresent {
		return fmt.Errorf("CI Python minimum step must be the exact unconditional owner invocation")
	}
	buildIndex, err := uniqueStepIndex(job.Steps, "Build and verify package artifacts")
	if err != nil || buildIndex < 0 || index != buildIndex+1 {
		return fmt.Errorf("CI Python minimum step must immediately follow current package artifacts")
	}
	for _, successor := range []string{"Verify self-hosting receipts", "Verify self-hosting coverage", "Verify release closeout"} {
		next, err := uniqueStepIndex(job.Steps, successor)
		if err != nil || next <= index {
			return fmt.Errorf("CI Python minimum step must precede %s", successor)
		}
	}
	return nil
}

func TestCIMinimumPythonStepRejectsOmissionAndNeutralization(t *testing.T) {
	base := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err := validateCIMinimumPythonStep(base.Jobs["source-quality"]); err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		change func(*githubJob, int)
	}{
		{"omitted", func(job *githubJob, index int) { job.Steps = append(job.Steps[:index], job.Steps[index+1:]...) }},
		{"duplicate", func(job *githubJob, index int) { job.Steps = append(job.Steps, job.Steps[index]) }},
		{"before artifact", func(job *githubJob, index int) {
			job.Steps[index], job.Steps[index-1] = job.Steps[index-1], job.Steps[index]
		}},
		{"after receipts", func(job *githubJob, index int) {
			job.Steps[index], job.Steps[index+1] = job.Steps[index+1], job.Steps[index]
		}},
		{"no-op", func(job *githubJob, index int) { job.Steps[index].Run = "true" }},
		{"masked exit", func(job *githubJob, index int) { job.Steps[index].Run += " || true" }},
		{"background", func(job *githubJob, index int) { job.Steps[index].Run += " &" }},
		{"conditional", func(job *githubJob, index int) { job.Steps[index].If = "false" }},
		{"null condition", func(job *githubJob, index int) { job.Steps[index].ifPresent = true }},
		{"continue on error", func(job *githubJob, index int) { job.Steps[index].ContinueOnError = true }},
		{"null continue", func(job *githubJob, index int) { job.Steps[index].continueOnErrorPresent = true }},
		{"shadow environment", func(job *githubJob, index int) { job.Steps[index].Env = map[string]any{"PATH": "/other"} }},
		{"uses", func(job *githubJob, index int) { job.Steps[index].Uses = "other/action@main" }},
		{"wrong tool", func(job *githubJob, index int) { job.Steps[index].Run = "go run ./internal/tools/pythonpackage verify" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			workflow := cloneWorkflow(t, base)
			job := workflow.Jobs["source-quality"]
			index, err := uniqueStepIndex(job.Steps, "Verify Python 3.9.0 installed wheel")
			if err != nil {
				t.Fatal(err)
			}
			mutation.change(&job, index)
			workflow.Jobs["source-quality"] = job
			if err := validateCIMinimumPythonStep(job); err == nil {
				t.Fatal("minimum step mutation admitted by independent owner predicate")
			}
			if err := validateCIRequiredAggregate(workflow); err == nil {
				t.Fatal("minimum step mutation admitted by aggregate oracle")
			}
		})
	}
}
