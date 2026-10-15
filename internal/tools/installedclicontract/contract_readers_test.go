package installedclicontract

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestEveryCLIContractReadTakesMaximumContractBytes scans the Go sources under
// cmd, internal and scripts. It fails when a call of DecodeJSON,
// DecodeTypedJSON, LimitReader, ReadBounded or a same-package function
// receives the contract path (a string literal ending in cli-contract.v2.json
// or a name bound to one), directly or through a derived path, file, reader or
// byte value, together with a literal byte limit or a package-level constant
// defined by one. It follows such values into same-package functions through
// their parameters. Such a limit could accept a contract the installed
// carriers refuse, or refuse one they accept. Limits held in function-local
// constants or in variables, calls of other cross-package functions, unbounded
// whole-file reads and archive entries selected by name are outside this
// check.
func TestEveryCLIContractReadTakesMaximumContractBytes(t *testing.T) {
	repositoryRoot := filepath.Join("..", "..", "..")
	for _, scope := range []string{"cmd", "internal", "scripts"} {
		packages := map[string][]*ast.File{}
		fileSet := token.NewFileSet()
		if err := filepath.WalkDir(filepath.Join(repositoryRoot, scope), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" || entry.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Ext(path) != ".go" {
				return nil
			}
			parsed, err := parser.ParseFile(fileSet, path, nil, 0)
			if err != nil {
				return err
			}
			packages[filepath.Dir(path)] = append(packages[filepath.Dir(path)], parsed)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for _, directory := range slices.Sorted(maps.Keys(packages)) {
			for _, finding := range literalContractReadLimits(fileSet, packages[directory]) {
				t.Errorf("%s", finding)
			}
		}
	}

	for _, test := range []struct {
		name   string
		source string
		want   int
	}{
		{name: "literal limit", source: `func read() { file, _ := os.Open("proofkit/cli-contract.v2.json"); admission.DecodeJSON(file, 16<<20) }`, want: 1},
		{name: "named literal limit", source: `const limit = 16 << 20; func read() { file, _ := os.Open(filepath.Join(root, "proofkit", "cli-contract.v2.json")); admission.DecodeTypedJSON[T](file, limit) }`, want: 1},
		{name: "path constant and limit reader", source: `const contractPath = "proofkit/cli-contract.v2.json"; func read() { file, _ := os.Open(contractPath); io.ReadAll(io.LimitReader(file, (8<<20)+1)) }`, want: 1},
		{name: "derived bytes", source: `func read() { content, _ := os.ReadFile("proofkit/cli-contract.v2.json"); admission.DecodeJSON(bytes.NewReader(content), 16<<20) }`, want: 1},
		{name: "helper hides literal limit", source: `func readJSON[T any](path string) { file, _ := os.Open(path); admission.DecodeTypedJSON[T](file, 16<<20) }; func read() { readJSON[contract]("proofkit/cli-contract.v2.json") }`, want: 1},
		{name: "helper given literal limit", source: `func readBounded(path string, limit int64) { file, _ := os.Open(path); admission.DecodeJSON(file, limit) }; func read() { readBounded("proofkit/cli-contract.v2.json", 16<<20) }`, want: 1},
		{name: "owner constant", source: `func read() { file, _ := os.Open("proofkit/cli-contract.v2.json"); io.LimitReader(file, installedclicontract.MaximumContractBytes+1); admission.DecodeJSON(file, installedclicontract.MaximumContractBytes) }`, want: 0},
		{name: "helper given owner constant", source: `func readBounded(path string, limit int64) { file, _ := os.Open(path); admission.DecodeJSON(file, limit) }; func read() { readBounded("proofkit/cli-contract.v2.json", installedclicontract.MaximumContractBytes) }`, want: 0},
		{name: "other file", source: `func read() { file, _ := os.Open("package.json"); admission.DecodeJSON(file, 16<<20) }`, want: 0},
		{name: "command output", source: `func read() { result := binary.Run("--contract", "proofkit/cli-contract.v2.json"); admission.DecodeJSON(bytes.NewReader(result.Stdout), 8<<20) }`, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			fileSet := token.NewFileSet()
			parsed, err := parser.ParseFile(fileSet, "fixture.go", "package fixture; "+test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := literalContractReadLimits(fileSet, []*ast.File{parsed}); len(got) != test.want {
				t.Fatalf("findings=%q, want %d", got, test.want)
			}
		})
	}
}

// literalContractReadLimits follows values derived from the CLI contract path
// through assignments and same-package helper parameters. It reports each call
// of a bounded reader, or of a same-package helper, that receives such a value
// together with a literal byte limit.
func literalContractReadLimits(fileSet *token.FileSet, files []*ast.File) []string {
	scan := contractReadScan{
		fileSet:   fileSet,
		constants: map[string]ast.Expr{},
		paths:     map[string]bool{},
		functions: map[string]*ast.FuncDecl{},
		visited:   map[string]bool{},
	}
	for _, file := range files {
		for _, declaration := range file.Decls {
			switch declaration := declaration.(type) {
			case *ast.GenDecl:
				for _, spec := range declaration.Specs {
					value, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for index, name := range value.Names {
						if index >= len(value.Values) {
							continue
						}
						if declaration.Tok == token.CONST {
							scan.constants[name.Name] = value.Values[index]
						}
						if isContractPathLiteral(value.Values[index]) {
							scan.paths[name.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if declaration.Recv == nil {
					scan.functions[declaration.Name.Name] = declaration
				}
			}
		}
	}
	for _, file := range files {
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Body != nil {
				scan.body(function.Body, map[string]bool{})
			}
		}
	}
	return scan.findings
}

type contractReadScan struct {
	fileSet   *token.FileSet
	constants map[string]ast.Expr
	paths     map[string]bool
	functions map[string]*ast.FuncDecl
	visited   map[string]bool
	findings  []string
}

var boundedContractReaders = map[string]bool{"DecodeJSON": true, "DecodeTypedJSON": true, "LimitReader": true, "ReadBounded": true}

func (scan *contractReadScan) body(body *ast.BlockStmt, derived map[string]bool) {
	ast.Inspect(body, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.AssignStmt:
			if slices.ContainsFunc(node.Rhs, func(value ast.Expr) bool { return scan.derived(value, derived) }) {
				for _, target := range node.Lhs {
					markDerived(target, derived)
				}
			}
		case *ast.ValueSpec:
			if slices.ContainsFunc(node.Values, func(value ast.Expr) bool { return scan.derived(value, derived) }) {
				for _, name := range node.Names {
					markDerived(name, derived)
				}
			}
		case *ast.RangeStmt:
			if scan.derived(node.X, derived) {
				markDerived(node.Key, derived)
				markDerived(node.Value, derived)
			}
		case *ast.CallExpr:
			scan.call(node, derived)
		}
		return true
	})
}

func (scan *contractReadScan) call(call *ast.CallExpr, derived map[string]bool) {
	var derivedArguments []int
	for index, argument := range call.Args {
		if scan.derived(argument, derived) {
			derivedArguments = append(derivedArguments, index)
		}
	}
	if len(derivedArguments) == 0 {
		return
	}
	name, local := calleeName(call.Fun)
	helper := scan.functions[name]
	if !boundedContractReaders[name] && (!local || helper == nil) {
		return
	}
	if slices.ContainsFunc(call.Args, scan.literalLimit) {
		scan.findings = append(scan.findings, fmt.Sprintf("%s: CLI contract read uses a literal byte limit instead of MaximumContractBytes", scan.fileSet.Position(call.Pos())))
	}
	if !local || helper == nil {
		return
	}
	key := name + fmt.Sprint(derivedArguments)
	if scan.visited[key] || helper.Body == nil {
		return
	}
	scan.visited[key] = true
	var parameters []string
	for _, field := range helper.Type.Params.List {
		for _, parameter := range field.Names {
			parameters = append(parameters, parameter.Name)
		}
	}
	helperDerived := map[string]bool{}
	for _, index := range derivedArguments {
		if index < len(parameters) {
			helperDerived[parameters[index]] = true
		}
	}
	scan.body(helper.Body, helperDerived)
}

// Contract bytes pass through paths, files, readers and byte conversions, not
// through the results of arbitrary calls.
var contractTransports = map[string]bool{
	"Clean": true, "FromSlash": true, "Join": true, "LimitReader": true, "MultiReader": true, "NewReader": true, "Open": true,
	"OpenFile": true, "ReadAll": true, "ReadBounded": true, "ReadFile": true, "TeeReader": true, "ToSlash": true,
	"string": true,
}

func (scan *contractReadScan) derived(expression ast.Expr, derived map[string]bool) bool {
	switch expression := expression.(type) {
	case *ast.BasicLit:
		return isContractPathLiteral(expression)
	case *ast.Ident:
		return derived[expression.Name] || scan.paths[expression.Name]
	case *ast.ParenExpr:
		return scan.derived(expression.X, derived)
	case *ast.StarExpr:
		return scan.derived(expression.X, derived)
	case *ast.UnaryExpr:
		return scan.derived(expression.X, derived)
	case *ast.SelectorExpr:
		return scan.derived(expression.X, derived)
	case *ast.SliceExpr:
		return scan.derived(expression.X, derived)
	case *ast.IndexExpr:
		return scan.derived(expression.X, derived) || scan.derived(expression.Index, derived)
	case *ast.BinaryExpr:
		return expression.Op == token.ADD && (scan.derived(expression.X, derived) || scan.derived(expression.Y, derived))
	case *ast.CallExpr:
		name, _ := calleeName(expression.Fun)
		if _, conversion := expression.Fun.(*ast.ArrayType); !conversion && !contractTransports[name] {
			return false
		}
		return slices.ContainsFunc(expression.Args, func(argument ast.Expr) bool { return scan.derived(argument, derived) })
	}
	return false
}

func (scan *contractReadScan) literalLimit(expression ast.Expr) bool {
	switch expression := expression.(type) {
	case *ast.BasicLit:
		return expression.Kind == token.INT
	case *ast.ParenExpr:
		return scan.literalLimit(expression.X)
	case *ast.BinaryExpr:
		return scan.literalLimit(expression.X) && scan.literalLimit(expression.Y)
	case *ast.Ident:
		value, ok := scan.constants[expression.Name]
		return ok && value != expression && scan.literalLimit(value)
	case *ast.CallExpr:
		conversion, ok := expression.Fun.(*ast.Ident)
		return ok && len(expression.Args) == 1 && slices.Contains([]string{"int", "int64", "uint64"}, conversion.Name) && scan.literalLimit(expression.Args[0])
	}
	return false
}

func calleeName(function ast.Expr) (string, bool) {
	switch function := function.(type) {
	case *ast.Ident:
		return function.Name, true
	case *ast.SelectorExpr:
		return function.Sel.Name, false
	case *ast.IndexExpr:
		return calleeName(function.X)
	case *ast.IndexListExpr:
		return calleeName(function.X)
	}
	return "", false
}

func isContractPathLiteral(expression ast.Expr) bool {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	value, err := strconv.Unquote(literal.Value)
	return err == nil && strings.HasSuffix(value, "cli-contract.v2.json")
}

func markDerived(expression ast.Expr, derived map[string]bool) {
	if name, ok := expression.(*ast.Ident); ok && name.Name != "_" && name.Name != "err" {
		derived[name.Name] = true
	}
}
