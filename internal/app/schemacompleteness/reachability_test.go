// Package schemacompleteness holds the route-reachability, class-indicator,
// mutation-witness and execution oracles of the schema completeness manifest
// (internal/app/testdata/schema-completeness-manifest.v1.json). They build
// whole-program call graphs and instrumented CLI binaries, so they run in
// their own test binary instead of the internal/app tests. The package has
// no non-test code, because commandcontractgen digests the non-test,
// non-generated Go sources under internal/app into published CLI contract
// nativeSources.
package schemacompleteness

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/commandroute"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// SCHEMA-01 route reachability oracle for the completeness manifest.
//
// A route's handler is the route-sensitive slice of internal/app: starting at
// RunWithRendererAndCapabilities, only branches consistent with the route's
// command name and runner (app.CommandRouteRunners) are followed, function values passed to app
// functions run only where their parameter is called, and command-keyed
// tables contribute only the route's entry. Every non-app function the slice
// calls, every non-app function value it creates and every method of a type
// it converts to an interface is a root of Rapid Type Analysis, whose
// reachable set closes the route. The manifest is then checked against that
// set: every owner it names for a direction must be reachable from the
// direction's route, no indicator of a class may be reachable from an input
// direction that declares the class absent, every input owner and output
// enforcer of an indicator class other than default must reach an indicator
// of that class through static calls, and every test witness must
// statically reach its owner. The native-owned records are therefore a
// verified lower bound and "absent" is relative to the class indicators: a
// reachable refusal that no indicator classifies is not checked (see the
// manifest nonClaims).

const schemaCompletenessManifestPath = "internal/app/testdata/schema-completeness-manifest.v1.json"

// schemaRouteRoot is the internal/app function every route slice starts at;
// schemaRouteInventory is the exported route-to-runner inventory, which no
// route may reach.
const (
	schemaRouteRoot      = "RunWithRendererAndCapabilities"
	schemaRouteInventory = "CommandRouteRunners"
)

type schemaCompletenessManifest struct {
	ClassIndicators schemaCompletenessClassIndicators  `json:"classIndicators"`
	Directions      []schemaCompletenessDirection      `json:"directions"`
	Owners          map[string]schemaCompletenessOwner `json:"owners"`
}

type schemaCompletenessClassIndicators struct {
	Classes        map[string]schemaCompletenessClassIndicator `json:"classes"`
	ExcludedScopes []string                                    `json:"excludedScopes"`
	Scopes         []string                                    `json:"scopes"`
}

type schemaCompletenessClassIndicator struct {
	Calls   []string `json:"calls"`
	Literal string   `json:"literal"`
}

type schemaCompletenessDirection struct {
	Direction   string                     `json:"direction"`
	NativeOwned map[string]json.RawMessage `json:"nativeOwned"`
	Route       string                     `json:"route"`
}

type schemaCompletenessOwner struct {
	Owner     string                               `json:"owner"`
	Role      string                               `json:"role"`
	Witnesses map[string]schemaCompletenessWitness `json:"witnesses"`
}

type schemaCompletenessWitness struct {
	CLI      string                      `json:"cli"`
	Evidence string                      `json:"evidence"`
	Mutation *schemaCompletenessMutation `json:"mutation"`
	Test     string                      `json:"test"`
}

type schemaCompletenessMutation struct {
	Find    string `json:"find"`
	Replace string `json:"replace"`
}

// schemaSymbol names a top-level function or method. Closures resolve to the
// declaration that contains them and pointer receivers drop the pointer.
type schemaSymbol struct {
	PackagePath string
	Name        string
}

func (symbol schemaSymbol) String() string {
	return symbol.PackagePath + "." + symbol.Name
}

type schemaCompletenessProgram struct {
	indicated      map[string]map[string]map[schemaSymbol]struct{}
	indicatedMutex sync.Mutex
	literals       map[schemaSymbol][]string
	modulePath     string
	routes         map[string]map[schemaSymbol]struct{}
	staticCallees  map[schemaSymbol]map[schemaSymbol]struct{}
	testFunctions  map[string]*ssa.Function
	testGraph      *callgraph.Graph
}

var (
	schemaCompletenessProgramOnce   sync.Once
	schemaCompletenessProgramResult *schemaCompletenessProgram
	schemaCompletenessProgramErr    error
)

func loadSchemaCompletenessProgram(t *testing.T) *schemaCompletenessProgram {
	t.Helper()
	schemaCompletenessProgramOnce.Do(func() {
		schemaCompletenessProgramResult, schemaCompletenessProgramErr = buildSchemaCompletenessProgram(schemaRepoRoot(t))
	})
	if schemaCompletenessProgramErr != nil {
		t.Fatal(schemaCompletenessProgramErr)
	}
	return schemaCompletenessProgramResult
}

func buildSchemaCompletenessProgram(root string) (*schemaCompletenessProgram, error) {
	loaded, err := packages.Load(&packages.Config{Dir: root, Mode: packages.LoadAllSyntax | packages.NeedModule, Tests: true}, "./...")
	if err != nil {
		return nil, fmt.Errorf("load schema completeness program: %w", err)
	}
	if errors := schemaPackageErrors(loaded); len(errors) > 0 {
		return nil, fmt.Errorf("load schema completeness program: %s", strings.Join(errors, "; "))
	}
	program, ssaPackages := ssautil.AllPackages(loaded, ssa.InstantiateGenerics)
	program.Build()

	var appPackage *ssa.Package
	modulePath := ""
	testVariants := map[*ssa.Package]bool{}
	for index, pkg := range loaded {
		if ssaPackages[index] == nil {
			continue
		}
		if pkg.Module != nil && modulePath == "" {
			modulePath = pkg.Module.Path
		}
		if strings.Contains(pkg.ID, " [") || strings.HasSuffix(pkg.ID, ".test") || strings.HasSuffix(pkg.PkgPath, "_test") {
			testVariants[ssaPackages[index]] = true
			continue
		}
		if strings.HasSuffix(pkg.PkgPath, "/internal/app") {
			appPackage = ssaPackages[index]
		}
	}
	if appPackage == nil || modulePath == "" {
		return nil, fmt.Errorf("schema completeness program has no internal/app package")
	}
	if appPackage.Func(schemaRouteRoot) == nil {
		return nil, fmt.Errorf("internal/app declares no route slice root %s", schemaRouteRoot)
	}

	result := &schemaCompletenessProgram{
		indicated:     map[string]map[string]map[schemaSymbol]struct{}{},
		literals:      schemaCompletenessLiterals(loaded, root),
		modulePath:    modulePath,
		routes:        map[string]map[schemaSymbol]struct{}{},
		staticCallees: map[schemaSymbol]map[schemaSymbol]struct{}{},
		testFunctions: map[string]*ssa.Function{},
	}
	slicer, err := newSchemaRouteSlicer(appPackage)
	if err != nil {
		return nil, err
	}
	for _, descriptor := range app.CommandRouteRunners() {
		roots, appFunctions := slicer.route(descriptor.Name, descriptor.Runner)
		reach := map[schemaSymbol]struct{}{}
		for function := range appFunctions {
			reach[schemaFunctionSymbol(function)] = struct{}{}
		}
		if len(roots) > 0 {
			for function := range rta.Analyze(roots, false).Reachable {
				reach[schemaFunctionSymbol(function)] = struct{}{}
			}
		}
		result.routes[commandroute.Text(descriptor.Route)] = reach
	}

	functions := ssautil.AllFunctions(program)
	for function := range functions {
		if function.Pkg != nil && testVariants[function.Pkg] {
			continue
		}
		caller := schemaFunctionSymbol(function)
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				call, ok := instruction.(ssa.CallInstruction)
				if !ok {
					continue
				}
				if callee := call.Common().StaticCallee(); callee != nil {
					if result.staticCallees[caller] == nil {
						result.staticCallees[caller] = map[schemaSymbol]struct{}{}
					}
					result.staticCallees[caller][schemaFunctionSymbol(callee)] = struct{}{}
				}
			}
		}
	}
	result.testGraph = vta.CallGraph(functions, nil)
	for function := range functions {
		if function.Parent() != nil || function.Signature.Recv() != nil || !strings.HasPrefix(function.Name(), "Test") {
			continue
		}
		if function.Pkg == nil || !testVariants[function.Pkg] {
			continue
		}
		filename := program.Fset.Position(function.Pos()).Filename
		if !strings.HasSuffix(filename, "_test.go") {
			continue
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return nil, err
		}
		result.testFunctions[filepath.ToSlash(relative)+"#"+function.Name()] = function
	}
	return result, nil
}

// schemaFunctionSymbol maps closures to their enclosing declaration and
// generic instances to their origin.
func schemaFunctionSymbol(function *ssa.Function) schemaSymbol {
	for function.Parent() != nil {
		function = function.Parent()
	}
	if origin := function.Origin(); origin != nil {
		function = origin
	}
	object, ok := function.Object().(*types.Func)
	if !ok || object.Pkg() == nil {
		return schemaSymbol{Name: function.String()}
	}
	name := object.Name()
	if receiver := object.Type().(*types.Signature).Recv(); receiver != nil {
		name = schemaReceiverTypeName(receiver.Type()) + "." + name
	}
	return schemaSymbol{PackagePath: object.Pkg().Path(), Name: name}
}

// schemaReceiverTypeName names a method receiver type without its pointer
// and type arguments.
func schemaReceiverTypeName(receiver types.Type) string {
	if pointer, ok := receiver.(*types.Pointer); ok {
		receiver = pointer.Elem()
	}
	receiver = types.Unalias(receiver)
	if named, ok := receiver.(*types.Named); ok {
		return named.Obj().Name()
	}
	return types.TypeString(receiver, func(*types.Package) string { return "" })
}

func schemaPackageErrors(loaded []*packages.Package) []string {
	errors := []string{}
	for _, pkg := range loaded {
		for _, packageError := range pkg.Errors {
			errors = append(errors, packageError.Error())
		}
	}
	sort.Strings(errors)
	return errors
}

// schemaRepoRoot is the repository root: this package is internal/app/schemacompleteness.
func schemaRepoRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repo root: %v", err)
	}
	return filepath.Clean(filepath.Join(directory, "../../.."))
}

// schemaRefusalCallee names the calls whose string arguments construct a
// refusal, a failure or a diagnostic: errors.New, fmt.Errorf, fmt.Sprintf,
// append to a failure list, and helpers named for failures, faults or
// violations (Fault is capitalized so that Default does not match).
var schemaRefusalCallee = regexp.MustCompile(`^(Errorf|New|Sprintf|append)$|[Ff]ail|Fault|[Ee]rr|[Bb]lock|[Rr]eject|[Rr]efus|[Dd]iagnos|[Ii]nvalid|[Vv]iolat`)

// schemaCompletenessLiterals records, per non-test function under internal/,
// the string constants its refusal calls spell or reference.
func schemaCompletenessLiterals(loaded []*packages.Package, root string) map[schemaSymbol][]string {
	result := map[schemaSymbol][]string{}
	seen := map[string]bool{}
	for _, pkg := range loaded {
		for _, file := range pkg.Syntax {
			filename := pkg.Fset.Position(file.Pos()).Filename
			if seen[filename] || strings.HasSuffix(filename, "_test.go") || !strings.HasPrefix(filename, filepath.Join(root, "internal")+string(filepath.Separator)) {
				continue
			}
			seen[filename] = true
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}
				object, ok := pkg.TypesInfo.Defs[function.Name].(*types.Func)
				if !ok {
					continue
				}
				name := object.Name()
				if receiver := object.Type().(*types.Signature).Recv(); receiver != nil {
					name = schemaReceiverTypeName(receiver.Type()) + "." + name
				}
				symbol := schemaSymbol{PackagePath: pkg.PkgPath, Name: name}
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok || !schemaIsRefusalCall(call) {
						return true
					}
					for _, argument := range call.Args {
						result[symbol] = append(result[symbol], schemaStringParts(pkg.TypesInfo, argument)...)
					}
					return true
				})
			}
		}
	}
	return result
}

func schemaIsRefusalCall(call *ast.CallExpr) bool {
	switch function := call.Fun.(type) {
	case *ast.Ident:
		return schemaRefusalCallee.MatchString(function.Name)
	case *ast.SelectorExpr:
		return schemaRefusalCallee.MatchString(function.Sel.Name)
	}
	return false
}

// schemaStringParts returns the string constants of an argument, following
// concatenation and parentheses.
func schemaStringParts(info *types.Info, expression ast.Expr) []string {
	switch value := expression.(type) {
	case *ast.BinaryExpr:
		return append(schemaStringParts(info, value.X), schemaStringParts(info, value.Y)...)
	case *ast.ParenExpr:
		return schemaStringParts(info, value.X)
	case *ast.BasicLit, *ast.Ident, *ast.SelectorExpr:
		typed, ok := info.Types[value]
		if ok && typed.Value != nil && typed.Value.Kind() == constant.String {
			return []string{constant.StringVal(typed.Value)}
		}
	}
	return nil
}

type schemaRouteSlicer struct {
	appPackage   *ssa.Package
	commandNames map[string]bool
	runnerType   types.Type
	tables       map[*ssa.Global]map[string]ssa.Value
}

func newSchemaRouteSlicer(appPackage *ssa.Package) (*schemaRouteSlicer, error) {
	runner, ok := appPackage.Pkg.Scope().Lookup("commandRunner").(*types.TypeName)
	if !ok {
		return nil, fmt.Errorf("internal/app declares no commandRunner type")
	}
	slicer := &schemaRouteSlicer{
		appPackage:   appPackage,
		commandNames: map[string]bool{},
		runnerType:   runner.Type(),
		tables:       map[*ssa.Global]map[string]ssa.Value{},
	}
	for _, descriptor := range app.CommandRouteRunners() {
		slicer.commandNames[descriptor.Name] = true
	}
	// A package-level map whose keys are command names is a command table:
	// a route reads only its own entry.
	for _, block := range appPackage.Func("init").Blocks {
		for _, instruction := range block.Instrs {
			store, ok := instruction.(*ssa.Store)
			if !ok {
				continue
			}
			global, ok := store.Addr.(*ssa.Global)
			if !ok {
				continue
			}
			maps := []*ssa.MakeMap{}
			switch value := store.Val.(type) {
			case *ssa.MakeMap:
				maps = append(maps, value)
			case *ssa.Call:
				for _, argument := range value.Call.Args {
					if made, ok := argument.(*ssa.MakeMap); ok {
						maps = append(maps, made)
					}
				}
			}
			for _, made := range maps {
				for _, referrer := range *made.Referrers() {
					update, ok := referrer.(*ssa.MapUpdate)
					if !ok {
						continue
					}
					key, ok := update.Key.(*ssa.Const)
					if !ok || key.Value == nil || key.Value.Kind() != constant.String || !slicer.commandNames[constant.StringVal(key.Value)] {
						continue
					}
					if slicer.tables[global] == nil {
						slicer.tables[global] = map[string]ssa.Value{}
					}
					slicer.tables[global][constant.StringVal(key.Value)] = update.Value
				}
			}
		}
	}
	return slicer, nil
}

// route returns the RTA roots and the app functions of one route's slice.
func (slicer *schemaRouteSlicer) route(name string, runner string) ([]*ssa.Function, map[*ssa.Function]bool) {
	walk := &schemaRouteWalk{
		appFunctions: map[*ssa.Function]bool{},
		name:         name,
		roots:        map[*ssa.Function]bool{},
		runner:       runner,
		slicer:       slicer,
		visited:      map[string]bool{},
	}
	walk.function(slicer.appPackage.Func(schemaRouteRoot), schemaRouteEnvironment{})
	roots := make([]*ssa.Function, 0, len(walk.roots))
	for function := range walk.roots {
		roots = append(roots, function)
	}
	sort.Slice(roots, func(left, right int) bool { return roots[left].String() < roots[right].String() })
	return roots, walk.appFunctions
}

// schemaRouteEnvironment binds parameters and free variables of an app
// function to the function values its live call site passed.
type schemaRouteEnvironment map[ssa.Value][]ssa.Value

type schemaRouteWalk struct {
	appFunctions map[*ssa.Function]bool
	name         string
	roots        map[*ssa.Function]bool
	runner       string
	slicer       *schemaRouteSlicer
	visited      map[string]bool
}

func (walk *schemaRouteWalk) isApp(function *ssa.Function) bool {
	for function.Parent() != nil {
		function = function.Parent()
	}
	if origin := function.Origin(); origin != nil {
		function = origin
	}
	return function.Pkg == walk.slicer.appPackage
}

// decided reports the value of a comparison with a command name or a runner
// constant for this route; any other condition is undecided.
func (walk *schemaRouteWalk) decided(condition ssa.Value) (bool, bool) {
	comparison, ok := condition.(*ssa.BinOp)
	if !ok || (comparison.Op != token.EQL && comparison.Op != token.NEQ) {
		return false, false
	}
	literal, ok := comparison.Y.(*ssa.Const)
	if !ok {
		literal, ok = comparison.X.(*ssa.Const)
	}
	if !ok || literal.Value == nil || literal.Value.Kind() != constant.String {
		return false, false
	}
	value := constant.StringVal(literal.Value)
	var equal bool
	switch {
	case types.Identical(literal.Type(), walk.slicer.runnerType):
		equal = value == walk.runner
	case walk.slicer.commandNames[value]:
		equal = value == walk.name
	default:
		return false, false
	}
	if comparison.Op == token.NEQ {
		equal = !equal
	}
	return equal, true
}

func (walk *schemaRouteWalk) resolve(value ssa.Value, environment schemaRouteEnvironment, seen map[ssa.Value]bool) []ssa.Value {
	if seen[value] {
		return nil
	}
	seen[value] = true
	switch typed := value.(type) {
	case *ssa.Function, *ssa.MakeClosure:
		return []ssa.Value{typed}
	case *ssa.Parameter, *ssa.FreeVar:
		return environment[value]
	case *ssa.ChangeType:
		return walk.resolve(typed.X, environment, seen)
	case *ssa.MakeInterface:
		return walk.resolve(typed.X, environment, seen)
	case *ssa.UnOp:
		if typed.Op == token.MUL {
			return walk.resolve(typed.X, environment, seen)
		}
	case *ssa.Phi:
		var result []ssa.Value
		for _, edge := range typed.Edges {
			result = append(result, walk.resolve(edge, environment, seen)...)
		}
		return result
	case *ssa.Alloc:
		var result []ssa.Value
		for _, referrer := range *typed.Referrers() {
			if store, ok := referrer.(*ssa.Store); ok && store.Addr == typed {
				result = append(result, walk.resolve(store.Val, environment, seen)...)
			}
		}
		return result
	}
	return nil
}

func (walk *schemaRouteWalk) live(value ssa.Value, environment schemaRouteEnvironment) {
	switch typed := value.(type) {
	case *ssa.Function:
		if walk.isApp(typed) {
			walk.function(typed, schemaRouteEnvironment{})
		} else {
			walk.roots[typed] = true
		}
	case *ssa.MakeClosure:
		function := typed.Fn.(*ssa.Function)
		inner := schemaRouteEnvironment{}
		for index, binding := range typed.Bindings {
			if values := walk.resolve(binding, environment, map[ssa.Value]bool{}); len(values) > 0 {
				inner[function.FreeVars[index]] = values
			}
		}
		if walk.isApp(function) {
			walk.function(function, inner)
		} else {
			walk.roots[function] = true
		}
	}
}

func (walk *schemaRouteWalk) liveOperand(value ssa.Value, environment schemaRouteEnvironment) {
	for _, resolved := range walk.resolve(value, environment, map[ssa.Value]bool{}) {
		walk.live(resolved, environment)
	}
}

func (walk *schemaRouteWalk) environmentKey(function *ssa.Function, environment schemaRouteEnvironment) string {
	parts := []string{}
	for key, values := range environment {
		for _, value := range values {
			parts = append(parts, fmt.Sprintf("%p=%p", key, value))
		}
	}
	sort.Strings(parts)
	return fmt.Sprintf("%p|%s", function, strings.Join(parts, ","))
}

func (walk *schemaRouteWalk) function(function *ssa.Function, environment schemaRouteEnvironment) {
	key := walk.environmentKey(function, environment)
	if walk.visited[key] {
		return
	}
	walk.visited[key] = true
	walk.appFunctions[function] = true
	if len(function.Blocks) == 0 {
		return
	}
	live := map[*ssa.BasicBlock]bool{}
	queue := []*ssa.BasicBlock{function.Blocks[0]}
	if function.Recover != nil {
		queue = append(queue, function.Recover)
	}
	for len(queue) > 0 {
		block := queue[0]
		queue = queue[1:]
		if live[block] {
			continue
		}
		live[block] = true
		if branch, ok := block.Instrs[len(block.Instrs)-1].(*ssa.If); ok {
			if value, decided := walk.decided(branch.Cond); decided {
				if value {
					queue = append(queue, block.Succs[0])
				} else {
					queue = append(queue, block.Succs[1])
				}
				continue
			}
		}
		queue = append(queue, block.Succs...)
	}
	for _, block := range function.Blocks {
		if !live[block] {
			continue
		}
		for _, instruction := range block.Instrs {
			walk.instruction(function, instruction, environment)
		}
	}
}

func (walk *schemaRouteWalk) instruction(caller *ssa.Function, instruction ssa.Instruction, environment schemaRouteEnvironment) {
	switch typed := instruction.(type) {
	case ssa.CallInstruction:
		walk.call(typed.Common(), environment)
		return
	case *ssa.MakeClosure:
		if !schemaClosureBoundToAppCall(typed, walk.slicer.appPackage) {
			walk.live(typed, environment)
		}
		for _, binding := range typed.Bindings {
			walk.liveOperand(binding, environment)
		}
		return
	case *ssa.MakeInterface:
		walk.runtimeType(typed.X.Type())
		return
	case *ssa.ChangeType, *ssa.Phi:
		return
	case *ssa.Store:
		if _, local := typed.Addr.(*ssa.Alloc); local {
			return
		}
	case *ssa.UnOp:
		if global, ok := typed.X.(*ssa.Global); ok {
			if entry, ok := walk.slicer.tables[global][walk.name]; ok {
				walk.tableEntry(entry)
			}
		}
	}
	for _, operand := range instruction.Operands(nil) {
		if operand != nil && *operand != nil {
			walk.liveOperand(*operand, environment)
		}
	}
}

func (walk *schemaRouteWalk) call(common *ssa.CallCommon, environment schemaRouteEnvironment) {
	if _, builtin := common.Value.(*ssa.Builtin); builtin || common.IsInvoke() {
		// Interface invocations on app types are closed by runtimeType;
		// on non-app types, by RTA from the roots that created them.
		for _, argument := range common.Args {
			walk.liveOperand(argument, environment)
		}
		return
	}
	if closure, ok := common.Value.(*ssa.MakeClosure); ok {
		walk.live(closure, environment)
	} else if callee := common.StaticCallee(); callee != nil {
		if walk.isApp(callee) {
			inner := schemaRouteEnvironment{}
			for index, argument := range common.Args {
				if values := walk.resolve(argument, environment, map[ssa.Value]bool{}); len(values) > 0 {
					inner[callee.Params[index]] = values
				}
			}
			walk.function(callee, inner)
			return
		}
		walk.roots[callee] = true
	} else {
		// A dynamic call runs a value bound by the caller, created in live
		// code, or read from the route's command-table entry.
		for _, value := range walk.resolve(common.Value, environment, map[ssa.Value]bool{}) {
			walk.live(value, environment)
		}
	}
	for _, argument := range common.Args {
		walk.liveOperand(argument, environment)
	}
}

// schemaClosureBoundToAppCall reports whether a closure is only passed to
// app functions, whose live call of the parameter decides whether it runs.
func schemaClosureBoundToAppCall(closure *ssa.MakeClosure, appPackage *ssa.Package) bool {
	referrers := closure.Referrers()
	if referrers == nil || len(*referrers) == 0 {
		return false
	}
	for _, referrer := range *referrers {
		call, ok := referrer.(ssa.CallInstruction)
		if !ok {
			return false
		}
		common := call.Common()
		callee := common.StaticCallee()
		if common.Value == closure || common.IsInvoke() || callee == nil || callee.Pkg != appPackage {
			return false
		}
	}
	return true
}

// runtimeType makes every method of a concrete type that live app code
// converts to an interface reachable, as RTA does for its own runtime types.
func (walk *schemaRouteWalk) runtimeType(value types.Type) {
	if types.IsInterface(value) {
		return
	}
	program := walk.slicer.appPackage.Prog
	candidates := []types.Type{value}
	if _, pointer := value.(*types.Pointer); !pointer {
		candidates = append(candidates, types.NewPointer(value))
	}
	for _, candidate := range candidates {
		methods := program.MethodSets.MethodSet(candidate)
		for index := 0; index < methods.Len(); index++ {
			method := program.MethodValue(methods.At(index))
			if method == nil {
				continue
			}
			if walk.isApp(method) {
				walk.function(method, schemaRouteEnvironment{})
			} else {
				walk.roots[method] = true
			}
		}
	}
}

// tableEntry follows the route's own command-table value: a function, a
// closure, or a call of an app adapter that wraps a function value.
func (walk *schemaRouteWalk) tableEntry(value ssa.Value) {
	switch typed := value.(type) {
	case *ssa.Function, *ssa.MakeClosure:
		walk.live(typed, schemaRouteEnvironment{})
	case *ssa.ChangeType:
		walk.tableEntry(typed.X)
	case *ssa.MakeInterface:
		walk.tableEntry(typed.X)
	case *ssa.Call:
		walk.call(typed.Common(), schemaRouteEnvironment{})
	}
}

func readSchemaCompletenessManifest(t *testing.T) schemaCompletenessManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(schemaRepoRoot(t), filepath.FromSlash(schemaCompletenessManifestPath)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest schemaCompletenessManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

// ownerSymbol resolves "internal/<dir>/<file>.go#Name" to its symbol.
func (program *schemaCompletenessProgram) ownerSymbol(location string) (schemaSymbol, bool) {
	path, name, ok := strings.Cut(location, "#")
	if !ok || !strings.HasSuffix(path, ".go") || strings.Contains(name, "#") {
		return schemaSymbol{}, false
	}
	return schemaSymbol{PackagePath: program.modulePath + "/" + filepath.ToSlash(filepath.Dir(path)), Name: name}, true
}

func schemaDisposition(raw json.RawMessage) ([]string, bool) {
	var absent string
	if json.Unmarshal(raw, &absent) == nil {
		return nil, absent == "absent"
	}
	var owners []string
	if json.Unmarshal(raw, &owners) != nil {
		return nil, false
	}
	return owners, false
}

func schemaDirectionKey(direction schemaCompletenessDirection) string {
	return direction.Route + "|" + direction.Direction
}

// schemaReachabilityErrors returns every owner the manifest names for a
// direction that is not reachable from the direction's route handler.
func (program *schemaCompletenessProgram) schemaReachabilityErrors(manifest schemaCompletenessManifest) []string {
	errors := []string{}
	for _, direction := range manifest.Directions {
		reach, ok := program.routes[direction.Route]
		if !ok {
			errors = append(errors, schemaDirectionKey(direction)+" has no CLI route")
			continue
		}
		for _, class := range schemaSortedKeys(direction.NativeOwned) {
			owners, _ := schemaDisposition(direction.NativeOwned[class])
			for _, id := range owners {
				record, ok := manifest.Owners[id]
				if !ok {
					errors = append(errors, fmt.Sprintf("%s %s names undeclared owner %s", schemaDirectionKey(direction), class, id))
					continue
				}
				symbol, ok := program.ownerSymbol(record.Owner)
				if !ok {
					errors = append(errors, fmt.Sprintf("owner %s has malformed location %s", id, record.Owner))
					continue
				}
				if _, reachable := reach[symbol]; !reachable {
					errors = append(errors, fmt.Sprintf("%s %s owner %s (%s) is not reachable from the route handler", schemaDirectionKey(direction), class, id, symbol))
				}
			}
		}
	}
	return errors
}

// indicatedSymbols enumerates each class's indicators from the code: every
// in-scope function whose refusal literals match the class literal, plus the
// named helpers that refuse without a message. Results are cached per
// indicator declaration and must not be modified by callers.
func (program *schemaCompletenessProgram) indicatedSymbols(indicators schemaCompletenessClassIndicators) map[string]map[schemaSymbol]struct{} {
	key, err := json.Marshal(indicators)
	if err != nil {
		panic(err)
	}
	program.indicatedMutex.Lock()
	defer program.indicatedMutex.Unlock()
	if cached, ok := program.indicated[string(key)]; ok {
		return cached
	}
	result := program.classIndicatorSymbols(indicators)
	program.indicated[string(key)] = result
	return result
}

func (program *schemaCompletenessProgram) classIndicatorSymbols(indicators schemaCompletenessClassIndicators) map[string]map[schemaSymbol]struct{} {
	inScope := func(symbol schemaSymbol) bool {
		for _, excluded := range indicators.ExcludedScopes {
			if symbol.PackagePath == program.modulePath+"/"+excluded || strings.HasPrefix(symbol.PackagePath, program.modulePath+"/"+excluded+"/") {
				return false
			}
		}
		for _, scope := range indicators.Scopes {
			if strings.HasPrefix(symbol.PackagePath, program.modulePath+"/"+scope+"/") {
				return true
			}
		}
		return false
	}
	result := map[string]map[schemaSymbol]struct{}{}
	for class, indicator := range indicators.Classes {
		result[class] = map[schemaSymbol]struct{}{}
		if indicator.Literal != "" {
			pattern := regexp.MustCompile(indicator.Literal)
			for symbol, literals := range program.literals {
				if !inScope(symbol) {
					continue
				}
				for _, literal := range literals {
					if pattern.MatchString(literal) {
						result[class][symbol] = struct{}{}
						break
					}
				}
			}
		}
		for _, location := range indicator.Calls {
			if symbol, ok := program.ownerSymbol(location); ok {
				result[class][symbol] = struct{}{}
			}
		}
	}
	return result
}

// schemaClassIndicatorErrors returns every input direction that declares a
// class absent although an indicator of that class is reachable from its
// route handler.
func (program *schemaCompletenessProgram) schemaClassIndicatorErrors(manifest schemaCompletenessManifest) []string {
	errors := []string{}
	indicated := program.indicatedSymbols(manifest.ClassIndicators)
	for _, direction := range manifest.Directions {
		if direction.Direction != "input" {
			continue
		}
		reach := program.routes[direction.Route]
		for _, class := range schemaSortedKeys(direction.NativeOwned) {
			if _, absent := schemaDisposition(direction.NativeOwned[class]); !absent {
				continue
			}
			hits := []string{}
			for symbol := range indicated[class] {
				if _, reachable := reach[symbol]; reachable {
					hits = append(hits, symbol.String())
				}
			}
			sort.Strings(hits)
			if len(hits) > 0 {
				errors = append(errors, fmt.Sprintf("%s declares %s absent but reaches %s", schemaDirectionKey(direction), class, strings.Join(hits, ", ")))
			}
		}
	}
	return errors
}

// staticClosure returns the functions a declaration reaches through static
// calls only.
func (program *schemaCompletenessProgram) staticClosure(symbol schemaSymbol) map[schemaSymbol]struct{} {
	seen := map[schemaSymbol]struct{}{symbol: {}}
	queue := []schemaSymbol{symbol}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for callee := range program.staticCallees[current] {
			if _, ok := seen[callee]; !ok {
				seen[callee] = struct{}{}
				queue = append(queue, callee)
			}
		}
	}
	return seen
}

// schemaOwnerClassErrors returns every owner named for a class whose static
// call closure contains no indicator of that class. Producers own every
// class of their output; default and semantic have no refusal indicator that
// an omitted or normalized member must produce.
func (program *schemaCompletenessProgram) schemaOwnerClassErrors(manifest schemaCompletenessManifest) []string {
	errors := []string{}
	indicated := program.indicatedSymbols(manifest.ClassIndicators)
	checked := map[string]bool{}
	for _, direction := range manifest.Directions {
		for _, class := range schemaSortedKeys(direction.NativeOwned) {
			if _, indicatorClass := manifest.ClassIndicators.Classes[class]; !indicatorClass || class == "default" {
				continue
			}
			owners, _ := schemaDisposition(direction.NativeOwned[class])
			for _, id := range owners {
				record := manifest.Owners[id]
				if (direction.Direction == "output" && record.Role == "producer") || checked[id+"|"+class] {
					continue
				}
				checked[id+"|"+class] = true
				symbol, ok := program.ownerSymbol(record.Owner)
				if !ok {
					continue
				}
				found := false
				for reached := range program.staticClosure(symbol) {
					if _, ok := indicated[class][reached]; ok {
						found = true
						break
					}
				}
				if !found {
					errors = append(errors, fmt.Sprintf("owner %s (%s) is named for %s but reaches no %s indicator", id, record.Owner, class, class))
				}
			}
		}
	}
	sort.Strings(errors)
	return errors
}

// schemaWitnessErrors returns every test witness that is not a Go test in
// the owner's package or does not statically reach its owner.
func (program *schemaCompletenessProgram) schemaWitnessErrors(manifest schemaCompletenessManifest) []string {
	errors := []string{}
	for _, id := range schemaSortedKeys(manifest.Owners) {
		record := manifest.Owners[id]
		for _, class := range schemaSortedKeys(record.Witnesses) {
			witness := record.Witnesses[class]
			if witness.Test == "" {
				continue
			}
			test, ok := program.testFunctions[witness.Test]
			ownerPath, _, _ := strings.Cut(record.Owner, "#")
			testPath, _, _ := strings.Cut(witness.Test, "#")
			switch {
			case !ok:
				errors = append(errors, fmt.Sprintf("owner %s %s witness %s is not a Go test function", id, class, witness.Test))
			case filepath.Dir(testPath) != filepath.Dir(ownerPath):
				errors = append(errors, fmt.Sprintf("owner %s %s witness %s is not in the owner's package", id, class, witness.Test))
			default:
				symbol, ok := program.ownerSymbol(record.Owner)
				if !ok || !program.testReaches(test, symbol) {
					errors = append(errors, fmt.Sprintf("owner %s %s witness %s does not reach %s", id, class, witness.Test, record.Owner))
				}
			}
		}
	}
	return errors
}

func (program *schemaCompletenessProgram) testReaches(test *ssa.Function, target schemaSymbol) bool {
	seen := map[*ssa.Function]bool{test: true}
	queue := []*ssa.Function{test}
	for len(queue) > 0 {
		function := queue[0]
		queue = queue[1:]
		if schemaFunctionSymbol(function) == target {
			return true
		}
		node := program.testGraph.Nodes[function]
		if node == nil {
			continue
		}
		for _, edge := range node.Out {
			if !seen[edge.Callee.Func] {
				seen[edge.Callee.Func] = true
				queue = append(queue, edge.Callee.Func)
			}
		}
	}
	return false
}

func (program *schemaCompletenessProgram) schemaManifestErrors(manifest schemaCompletenessManifest) []string {
	errors := program.schemaReachabilityErrors(manifest)
	errors = append(errors, program.schemaClassIndicatorErrors(manifest)...)
	errors = append(errors, program.schemaOwnerClassErrors(manifest)...)
	return append(errors, program.schemaWitnessErrors(manifest)...)
}

func schemaSortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func TestSchemaCompletenessOwnersAreReachableFromTheirRouteHandlers(t *testing.T) {
	program := loadSchemaCompletenessProgram(t)
	manifest := readSchemaCompletenessManifest(t)
	if errors := program.schemaManifestErrors(manifest); len(errors) > 0 {
		t.Fatalf("schema completeness manifest disagrees with the route call graph:\n%s", strings.Join(errors, "\n"))
	}
}

// Every route slice starts at the CLI entry point, and the exported
// route-to-runner inventory that drives the slicing is reachable from no
// route, so reading it cannot change any reach set.
func TestSchemaCompletenessRouteSlicesStartAtTheCLIEntryAndExcludeTheRouteInventory(t *testing.T) {
	program := loadSchemaCompletenessProgram(t)
	appPath := program.modulePath + "/internal/app"
	root := schemaSymbol{PackagePath: appPath, Name: schemaRouteRoot}
	inventory := schemaSymbol{PackagePath: appPath, Name: schemaRouteInventory}
	if _, declared := program.staticCallees[inventory]; !declared {
		t.Fatalf("%s calls nothing in the program, so its exclusion is vacuous", inventory)
	}
	if len(program.routes) != len(app.CommandRouteRunners()) {
		t.Fatalf("%d route reach sets for %d inventory routes", len(program.routes), len(app.CommandRouteRunners()))
	}
	for _, route := range schemaSortedKeys(program.routes) {
		reach := program.routes[route]
		if _, ok := reach[root]; !ok {
			t.Errorf("%s reach set does not start at %s", route, root)
		}
		if _, ok := reach[inventory]; ok {
			t.Errorf("%s reaches %s", route, inventory)
		}
	}
}

// The class indicators must keep enumerating the helpers whose false
// "absent" records the SCHEMA-01 reviews found, including checks that
// refuse with snake_case rule codes (requirementspectree, requirement
// source codec) and the cycle refusal.
func TestSchemaCompletenessClassIndicatorsEnumerateKnownHelpers(t *testing.T) {
	program := loadSchemaCompletenessProgram(t)
	manifest := readSchemaCompletenessManifest(t)
	indicated := program.indicatedSymbols(manifest.ClassIndicators)
	for class, helpers := range map[string][]string{
		"duplicate":        {"internal/command/repositoryinventory/admission.go#admitEntries", "internal/kernel/admit/fields.go#NormalizeSortedText", "internal/kernel/admit/fields.go#preserveSortedCanonical", "internal/kernel/admission/json.go#jsonKeyScanner.parseObject"},
		"numericCanonical": {"internal/kernel/admit/fields.go#JSONNumberEquals", "internal/kernel/admit/fields.go#PositiveInteger", "internal/kernel/admit/fields.go#CanonicalInteger"},
		"referenceClosure": {"internal/kernel/compactproofcontract/compactproofcontract.go#assertReferentialIntegrity", "internal/command/requirementcontext/model.go#validateProjectionSources", "internal/command/readinesscloseout/readinesscloseout.go#buildReport", "internal/command/deploymentevidenceadmission/deployment_evidence_admission.go#validateFacts", "internal/command/requirementspectree/validation.go#treeValidator.indexEdges", "internal/command/requirementspectree/validation.go#treeValidator.indexNodes", "internal/command/requirementspectree/validation.go#treeValidator.validateOverlays", "internal/command/workspaceregistry/workspaceregistry.go#packageScriptPolicyRule"},
		"secretTimestamp":  {"internal/kernel/admit/fields.go#RuleID", "internal/kernel/admit/fields.go#NonEmptyText"},
		"unknownField":     {"internal/kernel/admit/fields.go#KnownKeys", "internal/kernel/jsonshape/admission.go#Shape.admitObject", "internal/kernel/requirementsourcecodec/shape.go#addUnexpectedFieldFault"},
		"default":          {"internal/kernel/requirementsourcecodec/shape.go#shapeNodeFault"},
		"crossField":       {"internal/command/textpolicy/textpolicy.go#admitFiles", "internal/command/requirementspectree/validation.go#treeValidator.detectCycleFrom", "internal/kernel/jsonshape/admission.go#Shape.admit"},
		"enum":             {"internal/kernel/admit/fields.go#Enum", "internal/command/specoverviewclaims/specoverviewclaims.go#enum", "internal/command/scaffoldprofileplan/scaffoldprofileplan.go#enum", "internal/command/scaffoldprofileplan/scaffoldprofileplan.go#admitPreset"},
		"bound":            {"internal/kernel/admit/fields.go#SafeRepoRelativePath"},
		"cardinality":      {"internal/kernel/admit/fields.go#TextArray"},
	} {
		for _, helper := range helpers {
			symbol, ok := program.ownerSymbol(helper)
			if _, indicatedHelper := indicated[class][symbol]; !ok || !indicatedHelper {
				t.Errorf("%s indicators do not enumerate %s", class, helper)
			}
		}
	}
}

// The class indicators must not enumerate helpers whose only matching text
// belongs to another class: non-empty text ("must be non-empty",
// "must be JSON-serializable") is not a value set, display-only command
// text without shell control tokens relates no members, and a present file
// that is missing contentBase64 resolves no reference.
func TestSchemaCompletenessClassIndicatorsExcludeOtherClassHelpers(t *testing.T) {
	program := loadSchemaCompletenessProgram(t)
	manifest := readSchemaCompletenessManifest(t)
	indicated := program.indicatedSymbols(manifest.ClassIndicators)
	for class, helpers := range map[string][]string{
		"enum":             {"internal/kernel/admit/fields.go#TextArray", "internal/kernel/admit/fields.go#PreserveSortedText", "internal/command/specoverviewclaims/specoverviewclaims.go#preserveSortedUnique", "internal/command/readinesscloseout/readinesscloseout.go#sortedTextArray", "internal/command/gradualadoption/bootstrap_input.go#bootstrapSnapshot"},
		"crossField":       {"internal/kernel/admit/fields.go#DisplayOnlyCommandText", "internal/command/requirementdiff/requirementdiff.go#requireContextVersions"},
		"referenceClosure": {"internal/command/textpolicy/textpolicy.go#Evaluate", "internal/command/secretscan/secretscan.go#Build", "internal/command/witnessplan/witnessplan.go#admitInput"},
	} {
		for _, helper := range helpers {
			symbol, ok := program.ownerSymbol(helper)
			if _, indicatedHelper := indicated[class][symbol]; !ok || indicatedHelper {
				t.Errorf("%s indicators enumerate %s", class, helper)
			}
		}
	}
}

// Each tamper restores one record that the SCHEMA-01 review refuted; the
// call-graph checks must reject every one of them.
func TestSchemaCompletenessCallGraphChecksRefuteReviewedRecords(t *testing.T) {
	program := loadSchemaCompletenessProgram(t)
	owner := func(id string, location string) func(*schemaCompletenessManifest) string {
		return func(value *schemaCompletenessManifest) string {
			value.Owners[id] = schemaCompletenessOwner{Owner: location, Role: "enforcer"}
			return id
		}
	}
	cases := []struct {
		name        string
		route       string
		direction   string
		class       string
		disposition func(*schemaCompletenessManifest) string
		want        string
	}{
		{"binding input names the compact resolver", "evidence-graph", "input", "numericCanonical", owner("tamper.BuildResolver", "internal/command/requirementbinding/requirementbinding.go#BuildResolver"), "not reachable"},
		{"shard partition names the changed-package admission", "workspace-shard-partition", "input", "numericCanonical", owner("tamper.admitChangedPlanInput", "internal/command/workspaceplanning/changed_package_plan.go#admitChangedPlanInput"), "not reachable"},
		{"gradual adoption names the bootstrap builder", "gradual-adoption", "input", "numericCanonical", owner("tamper.buildBootstrap", "internal/command/gradualadoption/bootstrap.go#buildBootstrap"), "not reachable"},
		{"gradual adoption names the guidance-only text owner", "gradual-adoption", "input", "duplicate", owner("tamper.preserveText", "internal/command/gradualadoption/guidance.go#preserveText"), "not reachable"},
		{"selective evidence names the decision projection", "selective-gate-evidence", "input", "numericCanonical", owner("tamper.ProjectObligationDecision", "internal/command/selectivegateevidence/obligation_projection.go#ProjectObligationDecision"), "not reachable"},
		{"proof view declares reference closure absent", "requirement-proof-view", "input", "referenceClosure", nil, "absent but reaches"},
		{"semantic diff declares reference closure absent", "requirement-semantic-diff", "input", "referenceClosure", nil, "absent but reaches"},
		{"readiness closeout declares reference closure absent", "readiness-closeout", "input", "referenceClosure", nil, "absent but reaches"},
		{"deployment evidence declares reference closure absent", "deployment-evidence-admission", "input", "referenceClosure", nil, "absent but reaches"},
		{"text policy names policy admission for cross-field relations", "text-policy", "input", "crossField", owner("tamper.admitPolicy", "internal/command/textpolicy/textpolicy.go#admitPolicy"), "reaches no crossField indicator"},
		{"spec tree declares reference closure absent", "requirement-spec-tree", "input", "referenceClosure", nil, "absent but reaches"},
		{"spec tree view declares reference closure absent", "requirement-spec-tree-view", "input", "referenceClosure", nil, "absent but reaches"},
		{"workspace manifest facts names sorted text for enum", "workspace-manifest-facts", "input", "enum", owner("tamper.PreserveSortedText", "internal/kernel/admit/fields.go#PreserveSortedText"), "reaches no enum indicator"},
		{"changed path set names text arrays for enum", "changed-path-set", "input", "enum", owner("tamper.TextArray", "internal/kernel/admit/fields.go#TextArray"), "reaches no enum indicator"},
		{"spec overview claims names sorted unique text for enum", "spec-overview-claims", "input", "enum", owner("tamper.preserveSortedUnique", "internal/command/specoverviewclaims/specoverviewclaims.go#preserveSortedUnique"), "reaches no enum indicator"},
		{"migration plan names display-only command text for cross-field relations", "migration-plan", "input", "crossField", owner("tamper.DisplayOnlyCommandText", "internal/kernel/admit/fields.go#DisplayOnlyCommandText"), "reaches no crossField indicator"},
		{"binding input names binding admission for cross-field relations", "evidence-graph", "input", "crossField", owner("tamper.admitBinding", "internal/command/requirementbinding/requirementbinding.go#admitBinding"), "reaches no crossField indicator"},
		{"text policy names evaluation for reference closure", "text-policy", "input", "referenceClosure", owner("tamper.Evaluate", "internal/command/textpolicy/textpolicy.go#Evaluate"), "reaches no referenceClosure indicator"},
		{"secret scan names its builder for reference closure", "secret-scan", "input", "referenceClosure", owner("tamper.secretScanBuild", "internal/command/secretscan/secretscan.go#Build"), "reaches no referenceClosure indicator"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := readSchemaCompletenessManifest(t)
			for index, direction := range tampered.Directions {
				if direction.Route != tc.route || direction.Direction != tc.direction {
					continue
				}
				value := json.RawMessage(`"absent"`)
				if tc.disposition != nil {
					value, _ = json.Marshal([]string{tc.disposition(&tampered)})
				}
				tampered.Directions[index].NativeOwned[tc.class] = value
			}
			errors := program.schemaManifestErrors(tampered)
			if !strings.Contains(strings.Join(errors, "\n"), tc.want) {
				t.Fatalf("tamper was not refuted with %q: %v", tc.want, errors)
			}
		})
	}
	foreign := readSchemaCompletenessManifest(t)
	for id, record := range foreign.Owners {
		for class, witness := range record.Witnesses {
			if witness.Test != "" {
				witness.Test = "internal/app/authoring_input_guide_test.go#TestAuthoringInputGuideBootstrapCLI"
				record.Witnesses[class] = witness
				foreign.Owners[id] = record
				if errors := program.schemaWitnessErrors(foreign); !strings.Contains(strings.Join(errors, "\n"), "not in the owner's package") {
					t.Fatalf("foreign-package witness was not refuted: %v", errors)
				}
				return
			}
		}
	}
	t.Fatal("manifest declares no test witness")
}

// Every mutation witness names a unique text of its owner's body whose
// replacement makes the named test fail; the test therefore exercises that
// refusal and not merely the owner.
func TestSchemaCompletenessMutationWitnessesFailTheirTests(t *testing.T) {
	root := schemaRepoRoot(t)
	manifest := readSchemaCompletenessManifest(t)
	classes := map[string]bool{}
	for _, id := range schemaSortedKeys(manifest.Owners) {
		record := manifest.Owners[id]
		for _, class := range schemaSortedKeys(record.Witnesses) {
			witness := record.Witnesses[class]
			if witness.Mutation == nil {
				continue
			}
			classes[class] = true
			t.Run(id+"/"+class, func(t *testing.T) {
				ownerPath, ownerName, _ := strings.Cut(record.Owner, "#")
				testPath, testName, _ := strings.Cut(witness.Test, "#")
				source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ownerPath)))
				if err != nil {
					t.Fatal(err)
				}
				start, end, err := schemaFunctionRange(source, ownerName)
				if err != nil {
					t.Fatal(err)
				}
				body := string(source[start:end])
				if strings.Count(body, witness.Mutation.Find) != 1 {
					t.Fatalf("mutation text occurs %d times in %s", strings.Count(body, witness.Mutation.Find), record.Owner)
				}
				mutated := string(source[:start]) + strings.Replace(body, witness.Mutation.Find, witness.Mutation.Replace, 1) + string(source[end:])
				directory := t.TempDir()
				mutant := filepath.Join(directory, "mutant.go")
				if err := os.WriteFile(mutant, []byte(mutated), 0o600); err != nil {
					t.Fatal(err)
				}
				overlay, err := json.Marshal(map[string]map[string]string{"Replace": {filepath.Join(root, filepath.FromSlash(ownerPath)): mutant}})
				if err != nil {
					t.Fatal(err)
				}
				overlayPath := filepath.Join(directory, "overlay.json")
				if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
					t.Fatal(err)
				}
				command := exec.CommandContext(t.Context(), "go", "test", "-count=1", "-overlay", overlayPath, "-run", "^"+testName+"$", "./"+filepath.ToSlash(filepath.Dir(testPath)))
				command.Dir = root
				output, err := command.CombinedOutput()
				if err == nil || !strings.Contains(string(output), "--- FAIL: "+testName) {
					t.Fatalf("mutation of %s did not fail %s: %v\n%s", record.Owner, witness.Test, err, output)
				}
			})
		}
	}
	for _, class := range []string{"bound", "cardinality", "crossField", "default", "duplicate", "enum", "numericCanonical", "referenceClosure", "secretTimestamp", "semantic", "unknownField"} {
		if !classes[class] {
			t.Errorf("no mutation witness samples native-owned class %s", class)
		}
	}
}

// schemaFunctionRange returns the byte range of a top-level declaration
// named Name or Receiver.Name.
func schemaFunctionRange(source []byte, name string) (int, int, error) {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "", source, 0)
	if err != nil {
		return 0, 0, err
	}
	receiver, method, isMethod := strings.Cut(name, ".")
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if isMethod {
			if function.Recv == nil || function.Name.Name != method || schemaReceiverName(function.Recv.List[0].Type) != receiver {
				continue
			}
		} else if function.Recv != nil || function.Name.Name != name {
			continue
		}
		return fileSet.Position(function.Pos()).Offset, fileSet.Position(function.End()).Offset, nil
	}
	return 0, 0, fmt.Errorf("function %s does not exist", name)
}

func schemaReceiverName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.StarExpr:
		return schemaReceiverName(value.X)
	case *ast.IndexExpr:
		return schemaReceiverName(value.X)
	case *ast.IndexListExpr:
		return schemaReceiverName(value.X)
	case *ast.Ident:
		return value.Name
	}
	return ""
}
