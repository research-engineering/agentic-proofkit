package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func runRequirementView(command string, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	options, err := parseRequirementViewArgs(command, args)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	input, err := readInput(options.inputPath, stdin)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if options.inputPointer != "" {
		input, err = jsonpointer.Select(input, options.inputPointer)
		if err != nil {
			writeDiagnostic(stderr, err)
			return 1
		}
	}
	if command == "requirement-source-view" {
		return writeSourceView(input, options, stdout, stderr)
	}
	if command == "requirement-coverage-view" {
		return writeCoverageView(input, options, stdout, stderr)
	}
	if command == "requirement-spec-tree-view" {
		return writeSpecTreeView(input, options, stdout, stderr)
	}
	compact := requirementproofview.IsCompact(input)
	if compact && options.scope != "" {
		_, _ = fmt.Fprintln(stderr, "--scope is valid only for structured requirement-proof-view input")
		return 1
	}
	if !compact && (len(options.localEnvironmentClasses) > 0 || options.emptyLocalEnvironmentPolicy) {
		_, _ = fmt.Fprintln(stderr, "--local-environment-class and --empty-local-environment-policy are valid only for compact requirement-proof-view input")
		return 1
	}
	if compact && len(options.localEnvironmentClasses) == 0 && !options.emptyLocalEnvironmentPolicy {
		_, _ = fmt.Fprintln(stderr, "compact requirement-proof-view requires --local-environment-class or --empty-local-environment-policy")
		return 1
	}
	return writeProofView(input, options, stdout, stderr)
}

func parseRequirementViewArgs(command string, args []string) (requirementViewArgs, error) {
	options := requirementViewArgs{format: "json"}
	inputPointerSeen := false
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--input":
			if options.inputPath != "" || index+1 >= len(args) || args[index+1] == "" {
				return requirementViewArgs{}, fmt.Errorf("%s requires --input <path|->", command)
			}
			options.inputPath = args[index+1]
			index++
		case "--input-pointer":
			if inputPointerSeen || index+1 >= len(args) {
				return requirementViewArgs{}, fmt.Errorf("--input-pointer requires a JSON pointer")
			}
			inputPointerSeen = true
			options.inputPointer = args[index+1]
			index++
		case "--format":
			if index+1 >= len(args) || (args[index+1] != "json" && args[index+1] != "markdown" && args[index+1] != "html") {
				return requirementViewArgs{}, fmt.Errorf("--format must be json, markdown, or html")
			}
			options.format = args[index+1]
			index++
		case "--output":
			if command != "requirement-spec-tree-view" {
				return requirementViewArgs{}, fmt.Errorf("--output is valid only for requirement-spec-tree-view")
			}
			if options.outputPath != "" || index+1 >= len(args) || args[index+1] == "" {
				return requirementViewArgs{}, fmt.Errorf("--output requires a repository-relative POSIX path")
			}
			if args[index+1] == "-" {
				return requirementViewArgs{}, fmt.Errorf("--output requires a repository-relative POSIX path other than -")
			}
			outputPath, err := admit.SafeRepoRelativePath(args[index+1], "requirement-spec-tree-view output")
			if err != nil {
				return requirementViewArgs{}, err
			}
			options.outputPath = outputPath
			index++
		case "--scope":
			if command != "requirement-proof-view" {
				return requirementViewArgs{}, fmt.Errorf("--scope is valid only for requirement-proof-view or proof requirement-browser-server")
			}
			if index+1 >= len(args) || (args[index+1] != "graph" && args[index+1] != "slice") {
				return requirementViewArgs{}, fmt.Errorf("--scope must be graph or slice")
			}
			options.scope = args[index+1]
			index++
		case "--local-environment-class":
			if command != "requirement-proof-view" {
				return requirementViewArgs{}, fmt.Errorf("--local-environment-class and --empty-local-environment-policy are valid only for requirement-proof-resolver, compact requirement-proof-view, or proof requirement-browser-server")
			}
			if index+1 >= len(args) || args[index+1] == "" {
				return requirementViewArgs{}, fmt.Errorf("--local-environment-class requires an id")
			}
			class, err := compactproofcontract.AdmitLocalEnvironmentClass(args[index+1])
			if err != nil {
				return requirementViewArgs{}, err
			}
			options.localEnvironmentClasses = append(options.localEnvironmentClasses, class)
			index++
		case "--empty-local-environment-policy":
			if command != "requirement-proof-view" {
				return requirementViewArgs{}, fmt.Errorf("--local-environment-class and --empty-local-environment-policy are valid only for requirement-proof-resolver, compact requirement-proof-view, or proof requirement-browser-server")
			}
			options.emptyLocalEnvironmentPolicy = true
		case "--agent-envelope":
			if command != "requirement-coverage-view" {
				return requirementViewArgs{}, fmt.Errorf("--agent-envelope is valid only for %s", agentEnvelopeCommandList())
			}
			options.agentEnvelope = true
		default:
			return requirementViewArgs{}, fmt.Errorf("unsupported argument for %s: %s", command, args[index])
		}
	}
	if options.inputPath == "" {
		return requirementViewArgs{}, fmt.Errorf("%s requires --input <path|->", command)
	}
	if len(options.localEnvironmentClasses) > 0 && options.emptyLocalEnvironmentPolicy {
		return requirementViewArgs{}, fmt.Errorf("--local-environment-class and --empty-local-environment-policy are mutually exclusive")
	}
	if options.agentEnvelope && options.format != "json" {
		return requirementViewArgs{}, fmt.Errorf("--agent-envelope requires --format json")
	}
	return options, nil
}

func writeSourceView(input any, options requirementViewArgs, stdout io.Writer, stderr io.Writer) int {
	if options.format == "markdown" {
		output, exitCode, err := requirementsourceview.BuildMarkdown(input)
		return writeText(output, exitCode, err, stdout, stderr)
	}
	if options.format == "html" {
		output, exitCode, err := requirementsourceview.BuildHTML(input)
		return writeText(output, exitCode, err, stdout, stderr)
	}
	output, exitCode, err := requirementsourceview.BuildJSON(input)
	return writeJSON(output, exitCode, err, stdout, stderr)
}

func writeProofView(input any, options requirementViewArgs, stdout io.Writer, stderr io.Writer) int {
	viewOptions := requirementproofview.Options{
		Scope:                   options.scope,
		LocalEnvironmentClasses: options.localEnvironmentClasses,
	}
	if format := options.format; format == "markdown" {
		output, exitCode, err := requirementproofview.BuildMarkdown(input, viewOptions)
		return writeText(output, exitCode, err, stdout, stderr)
	} else if format == "html" {
		output, exitCode, err := requirementproofview.BuildHTML(input, viewOptions)
		return writeText(output, exitCode, err, stdout, stderr)
	}
	output, exitCode, err := requirementproofview.BuildJSON(input, viewOptions)
	return writeJSON(output, exitCode, err, stdout, stderr)
}

func writeCoverageView(input any, options requirementViewArgs, stdout io.Writer, stderr io.Writer) int {
	if format := options.format; format == "markdown" {
		output, exitCode, err := requirementcoverageview.BuildMarkdown(input)
		return writeText(output, exitCode, err, stdout, stderr)
	} else if format == "html" {
		output, exitCode, err := requirementcoverageview.BuildHTML(input)
		return writeText(output, exitCode, err, stdout, stderr)
	}
	output, exitCode, err := requirementcoverageview.BuildJSON(input, requirementcoverageview.Options{AgentEnvelope: options.agentEnvelope})
	return writeJSON(output, exitCode, err, stdout, stderr)
}

func writeSpecTreeView(input any, options requirementViewArgs, stdout io.Writer, stderr io.Writer) int {
	if options.format == "markdown" {
		output, exitCode, err := requirementspectree.BuildViewMarkdown(input)
		return writeViewText(output, exitCode, err, options.outputPath, stdout, stderr)
	}
	if options.format == "html" {
		output, exitCode, err := requirementspectree.BuildViewHTML(input)
		return writeViewText(output, exitCode, err, options.outputPath, stdout, stderr)
	}
	output, exitCode, err := requirementspectree.BuildViewJSON(input)
	if options.outputPath != "" {
		return writeViewJSON(output, exitCode, err, options.outputPath, jsonLayoutFromWriter(stdout), stderr)
	}
	return writeJSON(output, exitCode, err, stdout, stderr)
}

func writeViewJSON(output any, exitCode int, err error, outputPath string, layout stablejson.Layout, stderr io.Writer) int {
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	bytes, err := stablejson.MarshalLayout(output, layout)
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if err := writeRepoRelativeOutputFile(filepath.FromSlash(outputPath), bytes); err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	return exitCode
}

func writeViewText(output string, exitCode int, err error, outputPath string, stdout io.Writer, stderr io.Writer) int {
	if err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	if outputPath == "" {
		return writeText(output, exitCode, nil, stdout, stderr)
	}
	nativePath := filepath.FromSlash(outputPath)
	if err := writeRepoRelativeOutputFile(nativePath, []byte(output)); err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	return exitCode
}

func writeRepoRelativeOutputFile(nativePath string, content []byte) error {
	parent := filepath.Dir(nativePath)
	if err := ensureOutputParent(parent); err != nil {
		return err
	}
	if info, err := os.Lstat(nativePath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("output path must not be a symlink: %s", filepath.ToSlash(nativePath))
		}
		if info.IsDir() {
			return fmt.Errorf("output path must not be a directory: %s", filepath.ToSlash(nativePath))
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	temp, err := os.CreateTemp(parent, ".proofkit-output-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(0o644); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, nativePath); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func ensureOutputParent(parent string) error {
	if parent == "." || parent == "" {
		return nil
	}
	current := "."
	for _, part := range strings.Split(filepath.Clean(parent), string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0o755); err != nil && !os.IsExist(err) {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("output parent must not contain a symlink: %s", filepath.ToSlash(current))
		}
		if !info.IsDir() {
			return fmt.Errorf("output parent component must be a directory: %s", filepath.ToSlash(current))
		}
	}
	return nil
}
