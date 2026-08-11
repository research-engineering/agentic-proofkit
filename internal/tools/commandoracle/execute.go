package commandoracle

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
	"github.com/research-engineering/agentic-proofkit/internal/tools/repositorysnapshot"
	"golang.org/x/mod/modfile"
)

const (
	innerTestTimeout = 4*time.Minute + 30*time.Second
	outerRunTimeout  = 5 * time.Minute
	processWaitDelay = 10 * time.Second
	maxStderrBytes   = 1 << 20
	maxGoModBytes    = 1 << 20
)

type commandRunner func(context.Context, string, []ExecutionCommand, *eventLedger) error

var runSelectedTests commandRunner = runGoTests

func Execute(ctx context.Context, liveRoot string) (Evidence, error) {
	operationContext, cancel := context.WithTimeout(ctx, outerRunTimeout)
	defer cancel()
	if err := InvalidateDiagnostic(liveRoot); err != nil {
		return Evidence{}, err
	}
	materializedRoot, err := os.MkdirTemp("", "proofkit-command-oracle-")
	if err != nil {
		return Evidence{}, fmt.Errorf("create command oracle snapshot root: %w", err)
	}
	defer os.RemoveAll(materializedRoot)

	snapshot, err := repositorysnapshot.MaterializeContext(operationContext, liveRoot, materializedRoot)
	if err != nil {
		return Evidence{}, err
	}
	if err := repositorysnapshot.ValidateMaterializedContext(operationContext, materializedRoot, snapshot); err != nil {
		return Evidence{}, err
	}
	currentAfterCopy, err := repositorysnapshot.CaptureContext(operationContext, liveRoot)
	if err != nil {
		return Evidence{}, err
	}
	if !repositorysnapshot.EqualIdentity(snapshot, currentAfterCopy) {
		return Evidence{}, decision("source.changed_during_materialization")
	}

	candidates, err := app.CommandCoverageOracleCandidatesAtRoot(materializedRoot)
	if err != nil {
		return Evidence{}, err
	}
	if len(candidates) == 0 {
		return Evidence{}, decision("candidate.inventory_empty")
	}
	if err := rejectReservedAttributeForgery(materializedRoot, snapshot.Paths); err != nil {
		return Evidence{}, err
	}
	modulePath, err := readModulePath(materializedRoot)
	if err != nil {
		return Evidence{}, err
	}
	packageImports := packageImportPaths(modulePath, candidates)
	ledger, err := newEventLedger(candidates, packageImports)
	if err != nil {
		return Evidence{}, err
	}
	commands := executionCommands(candidates)
	if err := runSelectedTests(operationContext, materializedRoot, commands, ledger); err != nil {
		return Evidence{}, err
	}
	if err := ledger.finalize(); err != nil {
		return Evidence{}, err
	}
	if err := repositorysnapshot.ValidateMaterializedContext(operationContext, materializedRoot, snapshot); err != nil {
		return Evidence{}, decision("source.materialized_snapshot_mutated")
	}
	for attempt := 0; attempt < 2; attempt++ {
		current, err := repositorysnapshot.CaptureContext(operationContext, liveRoot)
		if err != nil {
			return Evidence{}, err
		}
		if !repositorysnapshot.EqualIdentity(snapshot, current) {
			return Evidence{}, decision("source.current_snapshot_mismatch")
		}
	}
	corpusDigest, err := ValidateCounterfeitCorpus(materializedRoot)
	if err != nil {
		return Evidence{}, err
	}
	return buildEvidence(snapshot, candidates, packageImports, commands, corpusDigest)
}

func executionCommands(candidates []app.CommandCoverageOracleCandidate) []ExecutionCommand {
	testsByPackage := map[string]map[string]struct{}{}
	for _, candidate := range candidates {
		if testsByPackage[candidate.PackagePath] == nil {
			testsByPackage[candidate.PackagePath] = map[string]struct{}{}
		}
		testsByPackage[candidate.PackagePath][candidate.TestName] = struct{}{}
	}
	packagePaths := make([]string, 0, len(testsByPackage))
	for packagePath := range testsByPackage {
		packagePaths = append(packagePaths, packagePath)
	}
	sort.Strings(packagePaths)
	commands := make([]ExecutionCommand, 0, len(packagePaths))
	for _, packagePath := range packagePaths {
		testNames := make([]string, 0, len(testsByPackage[packagePath]))
		for testName := range testsByPackage[packagePath] {
			testNames = append(testNames, testName)
		}
		sort.Strings(testNames)
		quoted := make([]string, 0, len(testNames))
		for _, testName := range testNames {
			quoted = append(quoted, regexp.QuoteMeta(testName))
		}
		commands = append(commands, ExecutionCommand{
			Argv:        []string{"go", "test", "-json", "-count=1", "-timeout=" + innerTestTimeout.String(), "-run", "^(" + strings.Join(quoted, "|") + ")$", packagePath},
			PackagePath: packagePath,
		})
	}
	return commands
}

func ExecutionCommandsForCandidates(candidates []app.CommandCoverageOracleCandidate) []ExecutionCommand {
	return cloneExecutionCommands(executionCommands(candidates))
}

func runGoTests(ctx context.Context, root string, commands []ExecutionCommand, ledger *eventLedger) error {
	for _, command := range commands {
		if err := runGoTestCommand(ctx, root, command.Argv, ledger); err != nil {
			return fmt.Errorf("command oracle package %s: %w", command.PackagePath, err)
		}
	}
	return nil
}

func runGoTestCommand(ctx context.Context, root string, argv []string, ledger *eventLedger) error {
	goExecutable, err := exec.LookPath(argv[0])
	if err != nil {
		return decision("process.go_executable_missing")
	}
	command := exec.CommandContext(ctx, goExecutable, argv[1:]...)
	command.Dir = root
	command.WaitDelay = processWaitDelay
	configureProcessGroup(command)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return decision("process.stdout_pipe_failed")
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return decision("process.stderr_pipe_failed")
	}
	if err := command.Start(); err != nil {
		return decision("process.start_failed")
	}
	stderrState := newBoundedDrain()
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		_, _ = io.Copy(stderrState, stderr)
	}()
	parseDone := make(chan error, 1)
	go func() { parseDone <- parseEvents(stdout, ledger) }()

	var parseErr error
	overflowChannel := stderrState.Exceeded()
	contextChannel := ctx.Done()
	overflowed := false
	parseComplete := false
	for !parseComplete {
		select {
		case parseErr = <-parseDone:
			parseComplete = true
			if parseErr != nil {
				_ = terminateProcessGroup(command)
			}
		case <-overflowChannel:
			overflowed = true
			overflowChannel = nil
			_ = terminateProcessGroup(command)
		case <-contextChannel:
			contextChannel = nil
			_ = terminateProcessGroup(command)
		}
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	var waitErr error
	waitComplete := false
	for !waitComplete {
		select {
		case waitErr = <-waitDone:
			waitComplete = true
		case <-overflowChannel:
			overflowed = true
			overflowChannel = nil
			_ = terminateProcessGroup(command)
		case <-contextChannel:
			contextChannel = nil
			_ = terminateProcessGroup(command)
		}
	}
	<-stderrDone
	if overflowed || stderrState.Overflowed() {
		return decision("process.stderr_exceeded")
	}
	if ctx.Err() != nil {
		return decision("process.timeout")
	}
	if parseErr != nil {
		return parseErr
	}
	if waitErr != nil {
		return decision("process.suite_failed")
	}
	return nil
}

type boundedDrain struct {
	count    int
	exceeded chan struct{}
	once     sync.Once
}

func newBoundedDrain() *boundedDrain {
	return &boundedDrain{exceeded: make(chan struct{})}
}

func (drain *boundedDrain) Write(value []byte) (int, error) {
	drain.count += len(value)
	if drain.count > maxStderrBytes {
		drain.once.Do(func() { close(drain.exceeded) })
	}
	return len(value), nil
}

func (drain *boundedDrain) Exceeded() <-chan struct{} { return drain.exceeded }

func (drain *boundedDrain) Overflowed() bool {
	select {
	case <-drain.exceeded:
		return true
	default:
		return false
	}
}

func readModulePath(root string) (string, error) {
	content, err := artifactfile.ReadBounded(root, "go.mod", maxGoModBytes)
	if err != nil {
		return "", decision("module.file_missing")
	}
	modulePath := modfile.ModulePath(content)
	if strings.TrimSpace(modulePath) == "" {
		return "", decision("module.path_missing")
	}
	return modulePath, nil
}

func packageImportPaths(modulePath string, candidates []app.CommandCoverageOracleCandidate) map[string]string {
	out := map[string]string{}
	for _, candidate := range candidates {
		relative := strings.TrimPrefix(candidate.PackagePath, "./")
		out[candidate.PackagePath] = modulePath + "/" + relative
	}
	return out
}

func rejectReservedAttributeForgery(root string, paths []string) error {
	const helperPath = "internal/testsupport/commandcoverage/semantic_route.go"
	for _, path := range paths {
		if !strings.HasSuffix(path, ".go") || path == helperPath {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, filepath.FromSlash(path)), nil, 0)
		if err != nil {
			return decision("source.go_parse_failed")
		}
		forged := false
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Attr" {
				return true
			}
			if reservedAttributeArgument(call.Args[0]) {
				forged = true
				return false
			}
			return true
		})
		if forged {
			return decision("source.reserved_attribute_direct_use")
		}
	}
	return nil
}

func reservedAttributeArgument(expression ast.Expr) bool {
	switch typed := expression.(type) {
	case *ast.BasicLit:
		value, err := strconv.Unquote(typed.Value)
		return err == nil && value == commandcoverage.ExecutionAttributeKey
	case *ast.SelectorExpr:
		return typed.Sel.Name == "ExecutionAttributeKey"
	default:
		return false
	}
}
