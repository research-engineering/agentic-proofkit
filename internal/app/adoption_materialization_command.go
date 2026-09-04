package app

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

type adoptionMaterializationArgs struct {
	action                 string
	color                  string
	colorExplicit          bool
	expectedDesiredStateID string
	expectedTransactionID  string
	format                 string
	inputPath              string
	inputPointer           jsonpointer.Pointer
	pointerPresent         bool
	repositoryRoot         string
	transactionID          string
}

func runAdoptionMaterialization(ctx context.Context, command string, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, capabilities PresentationCapabilities) int {
	options, err := parseAdoptionMaterializationArgs(command, args)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if command == "adopt-materialize-recover" {
		receipt, exitCode, err := adoptionmaterialization.Recover(ctx, options.repositoryRoot, options.transactionID, options.action)
		return writeAdoptionMaterializationReceipt(receipt, exitCode, err, options, stdout, stderr, capabilities)
	}
	input, err := readInput(options.inputPath, stdin)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if options.pointerPresent {
		input, err = jsonpointer.SelectParsed(input, options.inputPointer)
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
	}
	if command == "adopt-materialize-plan" {
		plan, err := adoptionmaterialization.BuildPlan(ctx, input, options.repositoryRoot)
		if options.format == "json" {
			return writeJSON(plan.JSONValue(), 0, err, stdout, stderr)
		}
		if err != nil {
			return writeText("", 1, err, stdout, stderr)
		}
		plain, err := adoptionmaterialization.RenderPlanText(plan)
		return writeAdoptionMaterializationText(plain, 0, err, options, stdout, stderr, capabilities)
	}
	receipt, exitCode, err := adoptionmaterialization.Apply(
		ctx,
		input,
		options.repositoryRoot,
		options.expectedTransactionID,
		options.expectedDesiredStateID,
	)
	return writeAdoptionMaterializationReceipt(receipt, exitCode, err, options, stdout, stderr, capabilities)
}

func writeAdoptionMaterializationReceipt(receipt adoptionmaterialization.Receipt, exitCode int, err error, options adoptionMaterializationArgs, stdout io.Writer, stderr io.Writer, capabilities PresentationCapabilities) int {
	if options.format == "json" {
		return writeJSON(receipt.JSONValue(), exitCode, err, stdout, stderr)
	}
	if err != nil {
		return writeText("", 1, err, stdout, stderr)
	}
	plain, err := adoptionmaterialization.RenderReceiptText(receipt)
	return writeAdoptionMaterializationText(plain, exitCode, err, options, stdout, stderr, capabilities)
}

func writeAdoptionMaterializationText(plain string, exitCode int, err error, options adoptionMaterializationArgs, stdout io.Writer, stderr io.Writer, capabilities PresentationCapabilities) int {
	if err != nil {
		return writeText("", 1, err, stdout, stderr)
	}
	output, err := renderTerminalText(adoptionMaterializationTerminalText(plain), options.color, capabilities)
	if err == nil && options.color == "never" && output != plain {
		err = fmt.Errorf("adoption materialization text projection drifted")
	}
	return writeText(output, exitCode, err, stdout, stderr)
}

func adoptionMaterializationTerminalText(plain string) terminalText {
	lines := strings.SplitAfter(plain, "\n")
	tokens := make([]terminalTextToken, 0, len(lines)*2)
	for _, line := range lines {
		if line == "" {
			continue
		}
		content := strings.TrimSuffix(line, "\n")
		newline := strings.TrimPrefix(line, content)
		if strings.HasPrefix(content, "- ") {
			tokens = append(tokens, terminalTextToken{kind: terminalTokenPlain, text: line})
			continue
		}
		separator := strings.IndexByte(content, ':')
		if separator < 0 {
			tokens = append(tokens,
				terminalTextToken{kind: terminalTokenLabel, text: content},
				terminalTextToken{kind: terminalTokenPlain, text: newline},
			)
			continue
		}
		tokens = append(tokens,
			terminalTextToken{kind: terminalTokenLabel, text: content[:separator]},
			terminalTextToken{kind: terminalTokenPlain, text: content[separator:] + newline},
		)
	}
	return newTerminalText(tokens...)
}

func parseAdoptionMaterializationArgs(command string, args []string) (adoptionMaterializationArgs, error) {
	options := adoptionMaterializationArgs{color: "never", format: "json"}
	seen := map[string]bool{}
	for index := 0; index < len(args); index++ {
		flag := args[index]
		if !adoptionMaterializationFlagAllowed(command, flag) {
			return adoptionMaterializationArgs{}, fmt.Errorf("unsupported argument for %s: %s", commandRouteForDiagnostic(command), flag)
		}
		if seen[flag] {
			return adoptionMaterializationArgs{}, fmt.Errorf("%s may be specified only once", flag)
		}
		seen[flag] = true
		if index+1 >= len(args) || args[index+1] == "" && flag != "--input-pointer" {
			return adoptionMaterializationArgs{}, missingAdoptionMaterializationValue(flag)
		}
		value := args[index+1]
		index++
		switch flag {
		case "--action":
			if value != repositorytransaction.RecoveryResume && value != repositorytransaction.RecoveryRollback {
				return adoptionMaterializationArgs{}, fmt.Errorf("--action requires one of: resume, rollback")
			}
			options.action = value
		case "--color":
			if value != "auto" && value != "never" {
				return adoptionMaterializationArgs{}, fmt.Errorf("--color requires one of: auto, never")
			}
			options.color = value
			options.colorExplicit = true
		case "--expect-desired-state":
			admitted, err := admit.SHA256Ref(value, "adoption materialization expected desired state")
			if err != nil {
				return adoptionMaterializationArgs{}, err
			}
			options.expectedDesiredStateID = admitted
		case "--expect-transaction":
			admitted, err := admit.SHA256Ref(value, "adoption materialization expected transaction")
			if err != nil {
				return adoptionMaterializationArgs{}, err
			}
			options.expectedTransactionID = admitted
		case "--format":
			if value != "json" && value != "text" {
				return adoptionMaterializationArgs{}, fmt.Errorf("--format requires one of: json, text")
			}
			options.format = value
		case "--input":
			options.inputPath = value
		case "--input-pointer":
			pointer, err := jsonpointer.Parse(value)
			if err != nil {
				return adoptionMaterializationArgs{}, err
			}
			options.inputPointer = pointer
			options.pointerPresent = true
		case "--repo-root":
			options.repositoryRoot = value
		case "--transaction":
			admitted, err := admit.SHA256Ref(value, "adoption materialization transaction")
			if err != nil {
				return adoptionMaterializationArgs{}, err
			}
			options.transactionID = admitted
		}
	}
	if command != "adopt-materialize-recover" && options.inputPath == "" {
		return adoptionMaterializationArgs{}, fmt.Errorf("%s requires --input <path|->", commandRouteForDiagnostic(command))
	}
	if options.repositoryRoot == "" {
		return adoptionMaterializationArgs{}, fmt.Errorf("%s requires --repo-root <path>", commandRouteForDiagnostic(command))
	}
	if command == "adopt-materialize-apply" && options.expectedTransactionID == "" {
		return adoptionMaterializationArgs{}, fmt.Errorf("adopt materialize apply requires --expect-transaction <sha256-ref>")
	}
	if command == "adopt-materialize-apply" && options.expectedDesiredStateID == "" {
		return adoptionMaterializationArgs{}, fmt.Errorf("adopt materialize apply requires --expect-desired-state <sha256-ref>")
	}
	if command == "adopt-materialize-recover" && options.transactionID == "" {
		return adoptionMaterializationArgs{}, fmt.Errorf("adopt materialize recover requires --transaction <sha256-ref>")
	}
	if command == "adopt-materialize-recover" && options.action == "" {
		return adoptionMaterializationArgs{}, fmt.Errorf("adopt materialize recover requires --action <resume|rollback>")
	}
	if options.colorExplicit && options.format != "text" {
		return adoptionMaterializationArgs{}, fmt.Errorf("--color is valid only with --format text")
	}
	return options, nil
}

func adoptionMaterializationFlagAllowed(command, flag string) bool {
	switch command {
	case "adopt-materialize-plan":
		switch flag {
		case "--color", "--format", "--input", "--input-pointer", "--repo-root":
			return true
		}
	case "adopt-materialize-apply":
		switch flag {
		case "--color", "--expect-desired-state", "--expect-transaction", "--format", "--input", "--input-pointer", "--repo-root":
			return true
		}
	case "adopt-materialize-recover":
		switch flag {
		case "--action", "--color", "--format", "--repo-root", "--transaction":
			return true
		}
	}
	return false
}

func missingAdoptionMaterializationValue(flag string) error {
	switch flag {
	case "--action":
		return fmt.Errorf("--action requires one of: resume, rollback")
	case "--color":
		return fmt.Errorf("--color requires one of: auto, never")
	case "--expect-desired-state":
		return fmt.Errorf("--expect-desired-state requires a sha256 ref")
	case "--expect-transaction":
		return fmt.Errorf("--expect-transaction requires a sha256 ref")
	case "--format":
		return fmt.Errorf("--format requires one of: json, text")
	case "--input":
		return fmt.Errorf("--input requires a path or -")
	case "--input-pointer":
		return fmt.Errorf("--input-pointer requires a JSON pointer")
	case "--repo-root":
		return fmt.Errorf("--repo-root requires a path")
	case "--transaction":
		return fmt.Errorf("--transaction requires a sha256 ref")
	default:
		return fmt.Errorf("unsupported adoption materialization argument")
	}
}
