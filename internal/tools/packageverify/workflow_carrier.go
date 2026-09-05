package main

import (
	"context"

	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

func verifyInstalledNPMWorkflowSmoke(consumer string) error {
	return workflowsmoke.VerifyProcess(context.Background(), installedNPMWorkflowCarrier(consumer))
}

func installedNPMWorkflowCarrier(consumer string) workflowsmoke.ProcessCarrier {
	return workflowsmoke.ProcessCarrier{
		Directory:  consumer,
		Executable: "npm",
		Prefix:     []string{"--silent", "exec", "--offline", "--", "agentic-proofkit"},
	}
}
