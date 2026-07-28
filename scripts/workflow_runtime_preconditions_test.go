package main

import (
	"path/filepath"
	"testing"
)

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
