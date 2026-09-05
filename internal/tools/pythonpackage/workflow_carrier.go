package main

import (
	"context"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

type installedPythonWorkflowCarrier struct {
	label   string
	carrier workflowsmoke.ProcessCarrier
}

func installedPythonWorkflowCarriers(dir string, environment []string, venvPython string, binPath string) []installedPythonWorkflowCarrier {
	return []installedPythonWorkflowCarrier{
		{
			label: "python module",
			carrier: workflowsmoke.ProcessCarrier{
				Directory:   dir,
				Executable:  venvPython,
				Environment: append([]string(nil), environment...),
				Prefix:      []string{"-m", "agentic_proofkit"},
			},
		},
		{
			label: "python console script",
			carrier: workflowsmoke.ProcessCarrier{
				Directory:   dir,
				Executable:  binPath,
				Environment: append([]string(nil), environment...),
			},
		},
	}
}

func verifyInstalledPythonWorkflowSmokes(dir string, environment []string, venvPython string, binPath string) error {
	for _, candidate := range installedPythonWorkflowCarriers(dir, environment, venvPython, binPath) {
		if err := workflowsmoke.VerifyProcess(context.Background(), candidate.carrier); err != nil {
			return fmt.Errorf("%s agent-workflow smoke failed: %w", candidate.label, err)
		}
	}
	return nil
}
