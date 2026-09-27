package processgroup

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetainedCallerConstructionHasNoIndependentWaitOrSignal(t *testing.T) {
	for _, directory := range []string{"workflowsmoke", "commandoracle", "repositorysnapshot"} {
		root := filepath.Join("..", "..", "tools", directory)
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		starts, ordinary := 0, 0
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, entry.Name()), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				name := selector.Sel.Name
				if owner, ok := selector.X.(*ast.Ident); ok {
					if owner.Name == "exec" && name == "Command" {
						ordinary++
					}
					if owner.Name == "processgroup" && name == "Start" {
						starts++
					}
					if owner.Name == "exec" && name == "CommandContext" {
						t.Errorf("%s: independent context watcher", entry.Name())
					}
				}
				if name == "Wait" || name == "Kill" || name == "Signal" || name == "Release" || name == "Terminate" || name == "TerminateAndWait" || name == "Configure" {
					t.Errorf("%s: independent lifecycle selector %s", entry.Name(), name)
				}
				return true
			})
		}
		if starts != 1 || ordinary != 1 {
			t.Errorf("%s: construction/start = %d/%d", directory, ordinary, starts)
		}
	}
}

// Structural wiring proof complements native context cancellation. It is not a
// claim that every source entrypoint has been executed under native SIGTERM.
func TestSourceEntrypointSignalScopeWiring(t *testing.T) {
	for _, test := range []struct{ path, function, operation string }{
		{"packageverify/workflow_carrier.go", "verifyInstalledNPMWorkflowSmoke", "workflowsmoke.VerifyProcess"},
		{"pythonpackage/workflow_carrier.go", "verifyInstalledPythonWorkflowSmokes", "workflowsmoke.VerifyProcess"},
		{"pythonpackage/minimum_installed.go", "verifyMinimumInstalledPython", "workflowsmoke.VerifyCarrier"},
		{"coveragemetrics/main.go", "run", "commandOracleExecute"},
		{"packageartifact/main.go", "sourceSnapshot", "packageartifactrecord.SourceSnapshotContext"},
		{"releasecloseoutinput/main.go", "readSelfEvidenceSnapshot", "commandOracleValidateCurrent"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", "tools", test.path), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var body *ast.BlockStmt
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == test.function {
				body = fn.Body
			}
		}
		if body == nil || !hasSignalScope(body, test.operation) {
			t.Errorf("missing scoped wiring: %s::%s", test.path, test.function)
		}
	}
	for _, body := range []string{
		`ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM); defer stop(); operation(ctx)`,
		`ctx, stop := context.WithCancel(context.Background()); defer stop(); operation(ctx)`,
		`ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM); operation(ctx)`,
		`ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM); defer stop(); operation(context.Background())`,
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "control.go", "package p; func f(){"+body+"}", 0)
		if err != nil {
			t.Fatal(err)
		}
		got := hasSignalScope(file.Decls[0].(*ast.FuncDecl).Body, "operation")
		want := strings.Contains(body, "signal.NotifyContext") && strings.Contains(body, "defer stop()") && strings.Contains(body, "operation(ctx)")
		if got != want {
			t.Fatalf("signal-scope control admitted incorrectly: %s", body)
		}
	}
}

func hasSignalScope(body *ast.BlockStmt, operation string) bool {
	contextName, stopName := "", ""
	deferred, wired := false, false
	ast.Inspect(body, func(node ast.Node) bool {
		if assign, ok := node.(*ast.AssignStmt); ok && len(assign.Lhs) == 2 && len(assign.Rhs) == 1 {
			if call, ok := assign.Rhs[0].(*ast.CallExpr); ok && expressionName(call.Fun) == "signal.NotifyContext" && len(call.Args) == 3 && expressionName(call.Args[1]) == "os.Interrupt" && expressionName(call.Args[2]) == "syscall.SIGTERM" {
				contextName, stopName = expressionName(assign.Lhs[0]), expressionName(assign.Lhs[1])
			}
		}
		if deferStmt, ok := node.(*ast.DeferStmt); ok && stopName != "" && expressionName(deferStmt.Call.Fun) == stopName {
			deferred = true
		}
		if call, ok := node.(*ast.CallExpr); ok && contextName != "" && expressionName(call.Fun) == operation && len(call.Args) > 0 && expressionName(call.Args[0]) == contextName {
			wired = true
		}
		return true
	})
	return contextName != "" && deferred && wired
}

func expressionName(expr ast.Expr) string {
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.SelectorExpr:
		return expressionName(expr.X) + "." + expr.Sel.Name
	default:
		return ""
	}
}
