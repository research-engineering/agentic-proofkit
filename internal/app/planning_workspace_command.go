package app

import (
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/workspaceplanning"
)

func runWorkspacePlanning(command string, input any, options planningArgs, stdout io.Writer, stderr io.Writer) int {
	switch command {
	case "workspace-changed-package-plan":
		plan, err := workspaceplanning.BuildChangedPackagePlan(input)
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		if options.agentEnvelope {
			return writeJSON(workspaceplanning.BuildChangedPackagePlanEnvelope(plan), 0, nil, stdout, stderr)
		}
		return writeJSON(plan, 0, nil, stdout, stderr)
	case "workspace-shard-partition":
		partition, exitCode, err := workspaceplanning.BuildShardPartition(input)
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
		if options.agentEnvelope {
			return writeJSON(workspaceplanning.BuildShardPartitionEnvelope(partition), exitCode, nil, stdout, stderr)
		}
		return writeJSON(partition, exitCode, nil, stdout, stderr)
	default:
		writeDiagnostic(stderr, fmt.Errorf("unsupported workspace planning command: %s", command))
		return 1
	}
}
