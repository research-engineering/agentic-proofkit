package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

func verifyInstalledNPMWorkflowSmoke(consumer string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return workflowsmoke.VerifyProcess(ctx, installedNPMWorkflowCarrier(consumer))
}

func installedNPMWorkflowCarrier(consumer string) workflowsmoke.ProcessCarrier {
	return workflowsmoke.ProcessCarrier{
		Directory:  consumer,
		Executable: "npm",
		Prefix:     []string{"--silent", "exec", "--offline", "--", "agentic-proofkit"},
	}
}
