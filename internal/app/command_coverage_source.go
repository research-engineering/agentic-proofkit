package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
)

const commandCoverageSourceOracleImport = "github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"

func routeSemanticSourceProblem(command string, route commandCoverageRoute) string {
	if !route.isSemantic() {
		return ""
	}
	filePath, err := commandCoverageRouteFilePath(route.file)
	if err != nil {
		return err.Error()
	}
	return goTestSemanticOracleProblem(filePath, route.testName, route.sourceOracleMarker(command))
}

func commandCoverageRouteFilePath(routeFile string) (string, error) {
	if filepath.IsAbs(routeFile) {
		return routeFile, nil
	}
	root, err := repositoryRootFromWorkingDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, filepath.FromSlash(routeFile)), nil
}

func repositoryRootFromWorkingDirectory() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

func goTestFunctionProblem(filePath string, testName string) string {
	return goTestFunctionProblemWithMarker(filePath, testName, "")
}

func goTestSemanticOracleProblem(filePath string, testName string, marker string) string {
	return goTestFunctionProblemWithMarker(filePath, testName, marker)
}

func goTestFunctionProblemWithMarker(filePath string, testName string, marker string) string {
	parsed, err := parser.ParseFile(token.NewFileSet(), filePath, nil, 0)
	if err != nil {
		return "file " + filePath + " is not parseable: " + err.Error()
	}
	if marker != "" && !importsCommandCoverageOracle(parsed) {
		return "missing source-owned semantic oracle import " + commandCoverageSourceOracleImport
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != testName {
			continue
		}
		if !isTestingTFunction(function) {
			return "not a Go test function with *testing.T"
		}
		if function.Body == nil || len(function.Body.List) == 0 {
			return "has no executable body"
		}
		if hasUnconditionalTopLevelSkip(function) {
			return "contains unconditional t.Skip at top level"
		}
		if !hasFailureCapableAssertion(function) {
			return "has no direct failure-capable assertion"
		}
		if marker != "" && !hasSemanticOracleBinding(function, marker) {
			return "missing source-owned semantic oracle binding " + marker
		}
		return ""
	}
	return "missing from " + filePath
}

func importsCommandCoverageOracle(file *ast.File) bool {
	for _, imported := range file.Imports {
		value, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			continue
		}
		if value == commandCoverageSourceOracleImport {
			return true
		}
	}
	return false
}

func isTestingTFunction(function *ast.FuncDecl) bool {
	if function.Type.Params == nil || len(function.Type.Params.List) != 1 {
		return false
	}
	star, ok := function.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := star.X.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "T" {
		return false
	}
	packageName, ok := selector.X.(*ast.Ident)
	return ok && packageName.Name == "testing"
}

func hasFailureCapableAssertion(function *ast.FuncDecl) bool {
	paramName := testingTParamName(function)
	if paramName == "" || function.Body == nil {
		return false
	}
	found := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || receiver.Name != paramName {
			return true
		}
		switch selector.Sel.Name {
		case "Error", "Errorf", "Fail", "FailNow", "Fatal", "Fatalf":
			found = true
			return false
		default:
			return true
		}
	})
	return found
}

func hasSemanticOracleBinding(function *ast.FuncDecl, marker string) bool {
	found := false
	paramName := testingTParamName(function)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "SemanticRoute" {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || receiver.Name != "commandcoverage" {
			return true
		}
		testArg, ok := call.Args[0].(*ast.Ident)
		if !ok || testArg.Name != paramName {
			return true
		}
		literal, ok := call.Args[1].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil {
			return true
		}
		if value == marker {
			found = true
			return false
		}
		return true
	})
	return found
}

func testingTParamName(function *ast.FuncDecl) string {
	if function.Type.Params == nil || len(function.Type.Params.List) != 1 {
		return ""
	}
	if len(function.Type.Params.List[0].Names) != 1 {
		return ""
	}
	return function.Type.Params.List[0].Names[0].Name
}

func hasUnconditionalTopLevelSkip(function *ast.FuncDecl) bool {
	paramName := testingTParamName(function)
	if paramName == "" {
		return false
	}
	for _, statement := range function.Body.List {
		if isUnconditionalTestSkip(statement, paramName) {
			return true
		}
	}
	return false
}

func isUnconditionalTestSkip(statement ast.Stmt, testParamName string) bool {
	expression, ok := statement.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expression.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || receiver.Name != testParamName {
		return false
	}
	switch selector.Sel.Name {
	case "Skip", "Skipf", "SkipNow":
		return true
	default:
		return false
	}
}
