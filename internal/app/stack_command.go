package app

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
)

func parseStackPresetArgs(args []string) (string, error) {
	presetID := ""
	for _, arg := range args {
		if arg == "--input" {
			return "", fmt.Errorf("--input is not valid for stack-preset")
		}
	}
	for index := 0; index < len(args); index++ {
		if args[index] != "--preset" || index+1 >= len(args) || args[index+1] == "" || presetID != "" || len(args) != 2 {
			return "", fmt.Errorf("stack-preset supports only --preset <id>")
		}
		presetID = args[index+1]
		index++
	}
	if presetID == "" || !stackpreset.IsPresetID(presetID) {
		return "", fmt.Errorf("--preset requires a known stack preset id")
	}
	return presetID, nil
}
