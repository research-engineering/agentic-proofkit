package app

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type compactSymbolID struct {
	PackagePath string
	Symbol      string
}

type compactSourceNode struct {
	References     map[compactSymbolID]struct{}
	DecisionDirect bool
	File           string
	Invokes        map[compactSymbolID]struct{}
	OwnerDirect    bool
}

type compactSourceGraph struct {
	Nodes map[compactSymbolID]*compactSourceNode
}

type compactSemanticSink struct {
	RequiredCaller compactSymbolID
	Sink           compactSymbolID
}

type compactTypedSourceFile struct {
	File        *ast.File
	Info        *types.Info
	PackagePath string
	Relative    string
}

type compactNodeAnalysis struct {
	Body ast.Node
	File compactTypedSourceFile
	Node *compactSourceNode
}

type compactSourceBuildContext struct {
	GOARCH string
	GOOS   string
}

var compactSourceUniverseExcludedPaths = map[string]string{
	".git":                 "version-control metadata",
	"artifacts":            "generated local evidence",
	"dist":                 "generated package output",
	"internal/testsupport": "test-only fixture support",
	"node_modules":         "third-party dependencies",
	"vendor":               "third-party Go dependencies",
}

func TestCompactSourceGraphDiscoversTransitiveWrappers(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/kernel/compactproofcontract/owner.go": `package compactproofcontract
func Admit(any) (any, error) { return nil, nil }
`,
		"internal/command/inner/inner.go": `package inner
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
func Build(value any) { _, _ = compact.Admit(value) }
`,
		"internal/app/outer.go": `package app
import "github.com/research-engineering/agentic-proofkit/internal/command/inner"
func route(value any) { inner.Build(value) }
`,
	})
	reviewed := map[string]map[string]struct{}{
		"github.com/research-engineering/agentic-proofkit/internal/command/inner": {"Build": {}},
	}

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, reviewed)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/app/outer.go", "internal/command/inner/inner.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("transitive compact consumers=%v want %v", got, want)
	}
}

func TestCompactSourceGraphHandlesOwnerAndWrapperImportForms(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		reviewed map[string]map[string]struct{}
		want     []string
	}{
		{
			name: "owner alias remains discovered after unrelated selector",
			files: map[string]string{
				"internal/use/use.go": `package use
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
func Build(value any) { _, _ = compact.Admit(value); _ = compact.Contract{} }
`,
			},
			want: []string{"internal/use/use.go"},
		},
		{
			name: "owner dot import remains discovered after unrelated call",
			files: map[string]string{
				"internal/use/use.go": `package use
import . "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
func Build(value any) { _, _ = Admit(value); _ = SurfaceColumns() }
`,
			},
			want: []string{"internal/use/use.go"},
		},
		{
			name: "owner accessor method is discovered without a copied symbol list",
			files: map[string]string{
				"internal/kernel/compactproofcontract/owner.go": `package compactproofcontract
type Contract struct{}
func (Contract) ContractID() string { return "proofkit.contract" }
`,
				"internal/use/use.go": `package use
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
func Render(contract compact.Contract) string { return contract.ContractID() }
`,
			},
			want: []string{"internal/use/use.go"},
		},
		{
			name: "reviewed wrapper alias",
			files: map[string]string{
				"internal/command/wrapper/wrapper.go": `package wrapper
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
func Build(value any) { _, _ = compact.Admit(value) }
`,
				"internal/use/use.go": `package use
import route "github.com/research-engineering/agentic-proofkit/internal/command/wrapper"
func Build(value any) { route.Build(value) }
`,
			},
			reviewed: map[string]map[string]struct{}{
				"github.com/research-engineering/agentic-proofkit/internal/command/wrapper": {"Build": {}},
			},
			want: []string{"internal/command/wrapper/wrapper.go", "internal/use/use.go"},
		},
		{
			name: "reviewed wrapper dot import",
			files: map[string]string{
				"internal/command/wrapper/wrapper.go": `package wrapper
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
func Build(value any) { _, _ = compact.Admit(value) }
`,
				"internal/use/use.go": `package use
import . "github.com/research-engineering/agentic-proofkit/internal/command/wrapper"
func Route(value any) { Build(value) }
`,
			},
			reviewed: map[string]map[string]struct{}{
				"github.com/research-engineering/agentic-proofkit/internal/command/wrapper": {"Build": {}},
			},
			want: []string{"internal/command/wrapper/wrapper.go", "internal/use/use.go"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := compactSourceFixture(t, test.files)
			got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, test.reviewed)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, "\n") != strings.Join(test.want, "\n") {
				t.Fatalf("compact consumers=%v want %v", got, test.want)
			}
		})
	}
}

func TestCompactSourceGraphPreservesPackageFunctionAliasesAcrossDeclarations(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/use/alias.go": `package use
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
var admitCompact = compact.Admit
var unrelated = "value"
`,
		"internal/use/use.go": `package use
func Build(value any) { _, _ = admitCompact(value) }
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/use/alias.go", "internal/use/use.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("package function alias consumers=%v want %v", got, want)
	}
}

func TestCompactSourceGraphClosesChainedFunctionValuesAcrossPackageFiles(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/use/owner_alias.go": `package use
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
var firstAdmit = compact.Admit
`,
		"internal/use/chained_alias.go": `package use
var secondAdmit = firstAdmit
`,
		"internal/use/use.go": `package use
func Build(value any) { _, _ = secondAdmit(value) }
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/use/chained_alias.go", "internal/use/owner_alias.go", "internal/use/use.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("chained function-value consumers=%v want %v", got, want)
	}
}

func TestCompactSourceGraphClosesMethodValuesAndExpressionsForIndirectCallers(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/use/method.go": `package use
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
type builder struct{}
func (builder) Admit(value any) { _, _ = compact.Admit(value) }
`,
		"internal/use/values.go": `package use
var defaultBuilder builder
var admitExpression = builder.Admit
var admitValue = defaultBuilder.Admit
`,
		"internal/use/route.go": `package use
func invokeExpression(admit func(builder, any), value any) { admit(builder{}, value) }
func invokeValue(admit func(any), value any) { admit(value) }
func Route(value any) { invokeExpression(admitExpression, value); invokeValue(admitValue, value) }
`,
		"internal/outer/outer.go": `package outer
import "github.com/research-engineering/agentic-proofkit/internal/use"
func Build(value any) { use.Route(value) }
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/outer/outer.go",
		"internal/use/method.go",
		"internal/use/route.go",
		"internal/use/values.go",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("method function-value consumers=%v want %v", got, want)
	}
}

func TestCompactSourceGraphClosesCrossPackageMethodsValuesAndExpressions(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/command/wrapper/wrapper.go": `package wrapper
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
type Router struct{}
func (Router) Build(value any) { _, _ = compact.Admit(value) }
`,
		"internal/use/use.go": `package use
import "github.com/research-engineering/agentic-proofkit/internal/command/wrapper"
var router wrapper.Router
var routeExpression = wrapper.Router.Build
var routeValue = router.Build
func Route(value any) { router.Build(value); routeExpression(router, value); routeValue(value) }
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/command/wrapper/wrapper.go", "internal/use/use.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("cross-package method consumers=%v want %v", got, want)
	}
}

func TestCompactSourceGraphClosesInterfaceDispatch(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/command/wrapper/wrapper.go": `package wrapper
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
type Runner interface { Build(any) }
type Implementation struct{}
func (Implementation) Build(value any) { _, _ = compact.Admit(value) }
func Route(runner Runner, value any) { runner.Build(value) }
`,
		"internal/use/use.go": `package use
import "github.com/research-engineering/agentic-proofkit/internal/command/wrapper"
func Start(value any) { wrapper.Route(wrapper.Implementation{}, value) }
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/command/wrapper/wrapper.go", "internal/use/use.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("interface-dispatch consumers=%v want %v", got, want)
	}
}

func TestCompactSourceGraphIncludesTypeOnlySchemaConsumers(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/use/types.go": `package use
type declaredRoute struct {
	BindingRecordID string
	DeclaredWitnessRoutes []declaredRoute
	WitnessRouteID string
}
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/use/types.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("type-only compact consumers=%v want %v", got, want)
	}
}

func TestCompactSourceGraphRespectsLexicalImportShadowing(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/command/wrapper/wrapper.go": `package wrapper
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
type Marker struct{}
func Build(value any) { _, _ = compact.Admit(value) }
`,
		"internal/use/use.go": `package use
import route "github.com/research-engineering/agentic-proofkit/internal/command/wrapper"
var _ route.Marker
func Foreign() {
	route := struct{ Build int }{}
	_ = route.Build
}
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/command/wrapper/wrapper.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("shadowed import consumers=%v want %v", got, want)
	}
}

func TestCompactSourceGraphClosesDeclaredSemanticSinkCallers(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/command/inventory/inventory.go": `package inventory
func sortedWitnessRefs(any) {}
func admitEntry(value any) { sortedWitnessRefs(value) }
func Evaluate(value any) { admitEntry(value) }
`,
		"internal/app/route.go": `package app
import "github.com/research-engineering/agentic-proofkit/internal/command/inventory"
func Route(value any) { inventory.Evaluate(value) }
`,
	})
	sinks := []compactSemanticSink{{
		Sink: compactSymbolID{
			PackagePath: "github.com/research-engineering/agentic-proofkit/internal/command/inventory",
			Symbol:      "sortedWitnessRefs",
		},
		RequiredCaller: compactSymbolID{
			PackagePath: "github.com/research-engineering/agentic-proofkit/internal/command/inventory",
			Symbol:      "admitEntry",
		},
	}}

	got, err := discoverCompactSymbolConsumersWithSinks(root, []string{"internal"}, nil, sinks)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/app/route.go", "internal/command/inventory/inventory.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("semantic-sink consumers=%v want %v", got, want)
	}
}

func TestCompactSourceGraphRejectsUncalledSemanticSink(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/command/inventory/inventory.go": `package inventory
func sortedWitnessRefs(any) {}
func admitEntry(any) { _ = sortedWitnessRefs }
`,
	})
	packagePath := "github.com/research-engineering/agentic-proofkit/internal/command/inventory"
	sinks := []compactSemanticSink{{
		Sink:           compactSymbolID{PackagePath: packagePath, Symbol: "sortedWitnessRefs"},
		RequiredCaller: compactSymbolID{PackagePath: packagePath, Symbol: "admitEntry"},
	}}

	_, err := discoverCompactSymbolConsumersWithSinks(root, []string{"internal"}, nil, sinks)
	if err == nil || !strings.Contains(err.Error(), "must directly call") {
		t.Fatalf("dead semantic sink error=%v, want direct-caller rejection", err)
	}
}

func TestCompactSourceGraphRejectsSemanticSinkInsideUninvokedClosure(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/command/inventory/inventory.go": `package inventory
func sortedWitnessRefs(any) {}
func admitEntry(value any) { _ = func() { sortedWitnessRefs(value) } }
`,
	})
	packagePath := "github.com/research-engineering/agentic-proofkit/internal/command/inventory"
	sinks := []compactSemanticSink{{
		Sink:           compactSymbolID{PackagePath: packagePath, Symbol: "sortedWitnessRefs"},
		RequiredCaller: compactSymbolID{PackagePath: packagePath, Symbol: "admitEntry"},
	}}

	_, err := discoverCompactSymbolConsumersWithSinks(root, []string{"internal"}, nil, sinks)
	if err == nil || !strings.Contains(err.Error(), "must directly call") {
		t.Fatalf("nested dead semantic sink error=%v, want direct-caller rejection", err)
	}
}

func TestCompactSourceGraphAcceptsSemanticSinkInsideImmediatelyInvokedClosure(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/command/inventory/inventory.go": `package inventory
func sortedWitnessRefs(any) {}
func admitEntry(value any) { func() { sortedWitnessRefs(value) }() }
`,
	})
	packagePath := "github.com/research-engineering/agentic-proofkit/internal/command/inventory"
	sinks := []compactSemanticSink{{
		Sink:           compactSymbolID{PackagePath: packagePath, Symbol: "sortedWitnessRefs"},
		RequiredCaller: compactSymbolID{PackagePath: packagePath, Symbol: "admitEntry"},
	}}

	if _, err := discoverCompactSymbolConsumersWithSinks(root, []string{"internal"}, nil, sinks); err != nil {
		t.Fatalf("immediately invoked semantic sink rejected: %v", err)
	}
}

func TestCompactSourceGraphIncludesConstantAliasCandidate(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/use/use.go": `package use
const key = "authority_state"
func Read(value map[string]any) any { return value[key] }
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/use/use.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("constant-alias candidates=%v want %v", got, want)
	}
}

func TestCompactSourceGraphConservativelyIncludesForeignFieldCandidate(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/use/use.go": `package use
type Unrelated struct { BindingRecordID string }
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/use/use.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("foreign-field candidates=%v want conservative candidate %v", got, want)
	}
}

func TestCompactSourceGraphDiscoversNewTopLevelPackage(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"pkg/use/use.go": `package use
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
func Build(value any) { _, _ = compact.Admit(value) }
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"."}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"pkg/use/use.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("top-level candidates=%v want %v", got, want)
	}
}

func TestCompactSourceGraphUnionsReleaseBuildContexts(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"pkg/use/use_darwin.go": `//go:build darwin

package use
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
func BuildDarwin(value any) { _, _ = compact.Admit(value) }
`,
		"pkg/use/use_linux.go": `//go:build linux

package use
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
func BuildLinux(value any) { _, _ = compact.Admit(value) }
`,
	})

	got, err := discoverCompactSymbolConsumersAcrossReleaseBuilds(root, []string{"."}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"pkg/use/use_darwin.go", "pkg/use/use_linux.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("release-build candidates=%v want %v", got, want)
	}
}

func TestCompactSourceGraphResolvesDeclaredPackageName(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/command/routeimpl/route.go": `package gateway
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
func Build(value any) { _, _ = compact.Admit(value) }
`,
		"internal/use/use.go": `package use
import "github.com/research-engineering/agentic-proofkit/internal/command/routeimpl"
func Build(value any) { gateway.Build(value) }
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/command/routeimpl/route.go", "internal/use/use.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("declared-package-name consumers=%v want %v", got, want)
	}
}

func TestCompactSourceGraphPreservesMultipleInitFunctions(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/use/use.go": `package use
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
func init() { _, _ = compact.Admit(nil) }
func init() {}
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/use/use.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("multiple-init consumers=%v want %v", got, want)
	}
}

func TestCompactSourceGraphIgnoresInertStringLiterals(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/use/use.go": `package use
const documentation = "bindingRecordId"
func message() string { return "authority_state" }
`,
	})

	got, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("inert literal consumers=%v want none", got)
	}
}

func TestCompactSourceGraphRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "internal"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target.go")
	if err := os.WriteFile(target, []byte("package fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "internal", "linked.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := discoverCompactSymbolConsumers(root, []string{"internal"}, nil); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("consumer discovery error=%v want symlink rejection", err)
	}
}

func TestCompactSourceGraphRejectsDeadReviewedWrapper(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/kernel/compactproofcontract/owner.go": "package compactproofcontract\nfunc Admit(any) (any, error) { return nil, nil }\n",
		"internal/command/dead/dead.go":                 "package dead\nfunc Build(any) {}\n",
	})
	reviewed := map[string]map[string]struct{}{
		"github.com/research-engineering/agentic-proofkit/internal/command/dead": {"Build": {}},
	}

	_, err := discoverCompactSymbolConsumers(root, []string{"internal"}, reviewed)
	if err == nil || !strings.Contains(err.Error(), "does not reach compact owner") {
		t.Fatalf("dead wrapper error=%v, want owner-reachability rejection", err)
	}
}

func TestCompactSourceGraphRejectsReviewedWrapperCycle(t *testing.T) {
	root := compactSourceFixture(t, map[string]string{
		"internal/kernel/compactproofcontract/owner.go": `package compactproofcontract
func Admit(any) (any, error) { return nil, nil }
`,
		"internal/command/cycle/cycle.go": `package cycle
import compact "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
func First(value any) { Second(value) }
func Second(value any) { First(value); _, _ = compact.Admit(value) }
`,
	})
	reviewed := map[string]map[string]struct{}{
		"github.com/research-engineering/agentic-proofkit/internal/command/cycle": {"First": {}, "Second": {}},
	}

	_, err := discoverCompactSymbolConsumers(root, []string{"internal"}, reviewed)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("wrapper-cycle error=%v, want cycle rejection", err)
	}
}

func discoverCompactSymbolConsumers(root string, roots []string, reviewed map[string]map[string]struct{}) ([]string, error) {
	return discoverCompactSymbolConsumersWithSinks(root, roots, reviewed, nil)
}

func discoverCompactSymbolConsumersWithSinks(root string, roots []string, reviewed map[string]map[string]struct{}, sinks []compactSemanticSink) ([]string, error) {
	return discoverCompactSymbolConsumersInBuildContexts(root, roots, reviewed, sinks, []compactSourceBuildContext{{}})
}

func discoverCompactSymbolConsumersAcrossReleaseBuilds(root string, roots []string, reviewed map[string]map[string]struct{}, sinks []compactSemanticSink) ([]string, error) {
	contexts := make([]compactSourceBuildContext, 0, len(releaseplatform.Targets()))
	seen := map[compactSourceBuildContext]struct{}{}
	for _, target := range releaseplatform.Targets() {
		context := compactSourceBuildContext{GOARCH: target.GOARCH, GOOS: target.GOOS}
		if _, duplicate := seen[context]; duplicate {
			continue
		}
		seen[context] = struct{}{}
		contexts = append(contexts, context)
	}
	sort.Slice(contexts, func(left, right int) bool {
		if contexts[left].GOOS != contexts[right].GOOS {
			return contexts[left].GOOS < contexts[right].GOOS
		}
		return contexts[left].GOARCH < contexts[right].GOARCH
	})
	return discoverCompactSymbolConsumersInBuildContexts(root, roots, reviewed, sinks, contexts)
}

func discoverCompactSymbolConsumersInBuildContexts(root string, roots []string, reviewed map[string]map[string]struct{}, sinks []compactSemanticSink, contexts []compactSourceBuildContext) ([]string, error) {
	files := map[string]struct{}{}
	for _, context := range contexts {
		graph, err := buildCompactSourceGraph(root, roots, context)
		if err != nil {
			return nil, err
		}
		candidates, err := discoverCompactGraphConsumers(graph, reviewed, sinks)
		if err != nil {
			return nil, err
		}
		for _, path := range candidates {
			files[path] = struct{}{}
		}
	}
	result := make([]string, 0, len(files))
	for path := range files {
		result = append(result, path)
	}
	sort.Strings(result)
	return result, nil
}

func discoverCompactGraphConsumers(graph *compactSourceGraph, reviewed map[string]map[string]struct{}, sinks []compactSemanticSink) ([]string, error) {
	if err := graph.validateReviewedWrappers(reviewed); err != nil {
		return nil, err
	}
	semanticSeeds, err := graph.validateSemanticSinks(sinks)
	if err != nil {
		return nil, err
	}
	reverse := make(map[compactSymbolID]map[compactSymbolID]struct{})
	queue := append([]compactSymbolID(nil), semanticSeeds...)
	reachable := make(map[compactSymbolID]struct{})
	for _, id := range semanticSeeds {
		reachable[id] = struct{}{}
	}
	for id, node := range graph.Nodes {
		if node.OwnerDirect || node.DecisionDirect {
			if _, seen := reachable[id]; !seen {
				reachable[id] = struct{}{}
				queue = append(queue, id)
			}
		}
		for target := range node.References {
			if reverse[target] == nil {
				reverse[target] = make(map[compactSymbolID]struct{})
			}
			reverse[target][id] = struct{}{}
		}
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for caller := range reverse[current] {
			if _, seen := reachable[caller]; seen {
				continue
			}
			reachable[caller] = struct{}{}
			queue = append(queue, caller)
		}
	}
	files := make(map[string]struct{})
	for id := range reachable {
		node := graph.Nodes[id]
		if node == nil || id.PackagePath == compactOwnerImportPath {
			continue
		}
		files[node.File] = struct{}{}
	}
	result := make([]string, 0, len(files))
	for path := range files {
		result = append(result, path)
	}
	sort.Strings(result)
	return result, nil
}

func buildCompactSourceGraph(root string, roots []string, context compactSourceBuildContext) (*compactSourceGraph, error) {
	patterns := make([]string, 0, len(roots))
	for _, relativeRoot := range roots {
		cleanRoot := filepath.Clean(filepath.FromSlash(relativeRoot))
		absoluteRoot := filepath.Join(root, cleanRoot)
		err := filepath.WalkDir(absoluteRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			if entry.IsDir() && relative != "." {
				if compactSourceUniversePathExcluded(relative) {
					return fs.SkipDir
				}
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("compact consumer source universe rejects symlink %s", relative)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		pattern := "./" + filepath.ToSlash(cleanRoot) + "/..."
		if cleanRoot == "." {
			pattern = "./..."
		}
		patterns = append(patterns, pattern)
	}
	config := &packages.Config{
		Dir:   root,
		Mode:  packages.LoadAllSyntax,
		Tests: false,
	}
	if context.GOOS != "" || context.GOARCH != "" {
		if context.GOOS == "" || context.GOARCH == "" {
			return nil, fmt.Errorf("compact source build context must define both GOOS and GOARCH")
		}
		config.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH="+context.GOARCH, "GOOS="+context.GOOS)
	}
	loaded, err := packages.Load(config, patterns...)
	if err != nil {
		return nil, fmt.Errorf("load compact consumer source universe: %w", err)
	}
	if errors := compactPackageErrors(loaded); len(errors) > 0 {
		return nil, fmt.Errorf("load compact consumer source universe: %s", strings.Join(errors, "; "))
	}

	files := make([]compactTypedSourceFile, 0)
	for _, pkg := range loaded {
		for _, file := range pkg.Syntax {
			relative, err := compactSourceRelative(root, pkg.Fset.Position(file.Pos()).Filename)
			if err != nil {
				return nil, err
			}
			if compactSourceUniversePathExcluded(relative) {
				continue
			}
			files = append(files, compactTypedSourceFile{
				File: file, Info: pkg.TypesInfo, PackagePath: pkg.PkgPath, Relative: relative,
			})
		}
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].PackagePath != files[j].PackagePath {
			return files[i].PackagePath < files[j].PackagePath
		}
		return files[i].Relative < files[j].Relative
	})

	graph := &compactSourceGraph{Nodes: make(map[compactSymbolID]*compactSourceNode)}
	analyses := make([]compactNodeAnalysis, 0)
	for _, file := range files {
		for declarationIndex, declaration := range file.File.Decls {
			switch value := declaration.(type) {
			case *ast.FuncDecl:
				if value.Body == nil {
					continue
				}
				id, ok := compactDeclaredFunctionID(file, value, declarationIndex)
				if !ok {
					return nil, fmt.Errorf("resolve compact consumer function %s:%s", file.Relative, value.Name.Name)
				}
				node := newCompactSourceNode(file.Relative)
				if err := graph.addNode(id, node); err != nil {
					return nil, err
				}
				analyses = append(analyses, compactNodeAnalysis{Body: value.Body, File: file, Node: node})
			case *ast.GenDecl:
				declarationID := compactSymbolID{
					PackagePath: file.PackagePath,
					Symbol:      "$init:" + filepath.Base(file.Relative) + ":" + strconv.Itoa(declarationIndex),
				}
				declarationNode := newCompactSourceNode(file.Relative)
				if err := graph.addNode(declarationID, declarationNode); err != nil {
					return nil, err
				}
				analyses = append(analyses, compactNodeAnalysis{Body: value, File: file, Node: declarationNode})
				for _, specification := range value.Specs {
					if typeSpec, ok := specification.(*ast.TypeSpec); ok {
						id, resolved := compactObjectSymbolID(file.Info.Defs[typeSpec.Name])
						if !resolved {
							return nil, fmt.Errorf("resolve compact consumer type %s:%s", file.Relative, typeSpec.Name.Name)
						}
						node := newCompactSourceNode(file.Relative)
						if err := graph.addNode(id, node); err != nil {
							return nil, err
						}
						analyses = append(analyses, compactNodeAnalysis{Body: typeSpec.Type, File: file, Node: node})
						continue
					}
					valueSpec, ok := specification.(*ast.ValueSpec)
					if !ok || len(valueSpec.Values) == 0 {
						continue
					}
					for nameIndex, name := range valueSpec.Names {
						id, ok := compactObjectSymbolID(file.Info.Defs[name])
						if !ok {
							continue
						}
						node := newCompactSourceNode(file.Relative)
						if err := graph.addNode(id, node); err != nil {
							return nil, err
						}
						if len(valueSpec.Values) == len(valueSpec.Names) {
							analyses = append(analyses, compactNodeAnalysis{Body: valueSpec.Values[nameIndex], File: file, Node: node})
							continue
						}
						for _, expression := range valueSpec.Values {
							analyses = append(analyses, compactNodeAnalysis{Body: expression, File: file, Node: node})
						}
					}
				}
			}
		}
	}
	for _, analysis := range analyses {
		analyzeCompactTypedNode(analysis.Node, analysis.Body, analysis.File.Info)
	}
	addCompactDynamicCallEdges(graph, loaded)
	return graph, nil
}

func compactSourceUniversePathExcluded(relative string) bool {
	for path := range compactSourceUniverseExcludedPaths {
		if relative == path || strings.HasPrefix(relative, path+"/") {
			return true
		}
	}
	return false
}

func compactPackageErrors(loaded []*packages.Package) []string {
	errors := make([]string, 0)
	for _, pkg := range loaded {
		for _, packageError := range pkg.Errors {
			errors = append(errors, packageError.Error())
		}
	}
	sort.Strings(errors)
	return errors
}

func compactSourceRelative(root string, path string) (string, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return "", err
	}
	relative = filepath.ToSlash(relative)
	if relative == ".." || strings.HasPrefix(relative, "../") {
		return "", fmt.Errorf("compact consumer source %s escapes repository root", path)
	}
	return relative, nil
}

func newCompactSourceNode(relative string) *compactSourceNode {
	return &compactSourceNode{
		File:       relative,
		Invokes:    make(map[compactSymbolID]struct{}),
		References: make(map[compactSymbolID]struct{}),
	}
}

func (graph *compactSourceGraph) addNode(id compactSymbolID, node *compactSourceNode) error {
	if prior := graph.Nodes[id]; prior != nil {
		return fmt.Errorf("compact source graph symbol %s.%s is declared in both %s and %s", id.PackagePath, id.Symbol, prior.File, node.File)
	}
	graph.Nodes[id] = node
	return nil
}

func compactDeclaredFunctionID(file compactTypedSourceFile, function *ast.FuncDecl, declarationIndex int) (compactSymbolID, bool) {
	if function.Recv == nil && function.Name.Name == "init" {
		return compactSymbolID{
			PackagePath: file.PackagePath,
			Symbol:      "$init:" + filepath.Base(file.Relative) + ":" + strconv.Itoa(declarationIndex),
		}, true
	}
	return compactObjectSymbolID(file.Info.Defs[function.Name])
}

func compactObjectSymbolID(object types.Object) (compactSymbolID, bool) {
	if object == nil || object.Pkg() == nil {
		return compactSymbolID{}, false
	}
	symbol := object.Name()
	switch value := object.(type) {
	case *types.Func:
		signature, ok := value.Type().(*types.Signature)
		if !ok {
			return compactSymbolID{}, false
		}
		if receiver := signature.Recv(); receiver != nil {
			symbol = compactReceiverTypeName(receiver.Type()) + "." + value.Name()
		}
	case *types.Var, *types.Const, *types.TypeName:
		if object.Parent() != object.Pkg().Scope() {
			return compactSymbolID{}, false
		}
	default:
		return compactSymbolID{}, false
	}
	return compactSymbolID{PackagePath: object.Pkg().Path(), Symbol: symbol}, true
}

func compactReceiverTypeName(receiver types.Type) string {
	prefix := ""
	if pointer, ok := receiver.(*types.Pointer); ok {
		prefix = "*"
		receiver = pointer.Elem()
	}
	receiver = types.Unalias(receiver)
	if named, ok := receiver.(*types.Named); ok {
		return prefix + named.Obj().Name()
	}
	return prefix + types.TypeString(receiver, func(*types.Package) string { return "" })
}

func analyzeCompactTypedNode(node *compactSourceNode, body ast.Node, info *types.Info) {
	invokedLiterals := make(map[*ast.FuncLit]struct{})
	ast.Inspect(body, func(raw ast.Node) bool {
		if raw == nil {
			return true
		}
		switch value := raw.(type) {
		case *ast.FuncLit:
			if _, invoked := invokedLiterals[value]; invoked {
				return false
			}
			nested := newCompactSourceNode(node.File)
			analyzeCompactTypedNode(nested, value.Body, info)
			mergeCompactNestedNode(node, nested, false)
			return false
		case *ast.CallExpr:
			if literal, ok := compactCalledFunctionLiteral(value.Fun); ok {
				invokedLiterals[literal] = struct{}{}
				nested := newCompactSourceNode(node.File)
				analyzeCompactTypedNode(nested, literal.Body, info)
				mergeCompactNestedNode(node, nested, true)
			}
			if target, ok := compactCalledSymbolID(value.Fun, info); ok {
				node.Invokes[target] = struct{}{}
			}
		case *ast.Ident:
			object := info.Uses[value]
			target, ok := compactObjectSymbolID(object)
			if !ok {
				return true
			}
			node.References[target] = struct{}{}
			if target.PackagePath == compactOwnerImportPath {
				node.OwnerDirect = true
			}
		case *ast.Field:
			for _, name := range value.Names {
				if _, ok := compactDistinctiveFieldNames[name.Name]; ok {
					node.DecisionDirect = true
				}
			}
		case *ast.KeyValueExpr:
			node.DecisionDirect = node.DecisionDirect || isCompactDecisionValue(value.Key, info)
		case *ast.IndexExpr:
			node.DecisionDirect = node.DecisionDirect || isCompactDecisionValue(value.Index, info)
		case *ast.BinaryExpr:
			node.DecisionDirect = node.DecisionDirect || isCompactDecisionValue(value.X, info) || isCompactDecisionValue(value.Y, info)
		case *ast.CaseClause:
			for _, expression := range value.List {
				node.DecisionDirect = node.DecisionDirect || isCompactDecisionValue(expression, info)
			}
		}
		return true
	})
}

func compactCalledFunctionLiteral(expression ast.Expr) (*ast.FuncLit, bool) {
	for {
		switch value := expression.(type) {
		case *ast.FuncLit:
			return value, true
		case *ast.ParenExpr:
			expression = value.X
		default:
			return nil, false
		}
	}
}

func mergeCompactNestedNode(parent, nested *compactSourceNode, includeInvocations bool) {
	for target := range nested.References {
		parent.References[target] = struct{}{}
	}
	if includeInvocations {
		for target := range nested.Invokes {
			parent.Invokes[target] = struct{}{}
		}
	}
	parent.DecisionDirect = parent.DecisionDirect || nested.DecisionDirect
	parent.OwnerDirect = parent.OwnerDirect || nested.OwnerDirect
}

func isCompactDecisionValue(expression ast.Expr, info *types.Info) bool {
	value, ok := info.Types[expression]
	if !ok || value.Value == nil || value.Value.Kind() != constant.String {
		return false
	}
	_, ok = compactDistinctiveKeys[constant.StringVal(value.Value)]
	return ok
}

func compactCalledSymbolID(expression ast.Expr, info *types.Info) (compactSymbolID, bool) {
	switch value := expression.(type) {
	case *ast.Ident:
		return compactObjectSymbolID(info.Uses[value])
	case *ast.SelectorExpr:
		if selection := info.Selections[value]; selection != nil {
			return compactObjectSymbolID(selection.Obj())
		}
		return compactObjectSymbolID(info.Uses[value.Sel])
	default:
		return compactSymbolID{}, false
	}
}

func addCompactDynamicCallEdges(graph *compactSourceGraph, loaded []*packages.Package) {
	program, _ := ssautil.AllPackages(loaded, ssa.InstantiateGenerics)
	program.Build()
	callGraph := vta.CallGraph(ssautil.AllFunctions(program), nil)
	for function, callNode := range callGraph.Nodes {
		callerID, ok := compactSSAFunctionID(function)
		if !ok || graph.Nodes[callerID] == nil {
			continue
		}
		for _, edge := range callNode.Out {
			calleeID, ok := compactSSAFunctionID(edge.Callee.Func)
			if !ok || graph.Nodes[calleeID] == nil {
				continue
			}
			graph.Nodes[callerID].References[calleeID] = struct{}{}
			graph.Nodes[callerID].Invokes[calleeID] = struct{}{}
		}
	}
}

func compactSSAFunctionID(function *ssa.Function) (compactSymbolID, bool) {
	if function == nil {
		return compactSymbolID{}, false
	}
	if origin := function.Origin(); origin != nil {
		function = origin
	}
	return compactObjectSymbolID(function.Object())
}

func (graph *compactSourceGraph) validateSemanticSinks(sinks []compactSemanticSink) ([]compactSymbolID, error) {
	result := make([]compactSymbolID, 0, len(sinks))
	seen := make(map[compactSymbolID]struct{}, len(sinks))
	for _, declaration := range sinks {
		if graph.Nodes[declaration.Sink] == nil {
			return nil, fmt.Errorf("compact semantic sink %s.%s does not exist", declaration.Sink.PackagePath, declaration.Sink.Symbol)
		}
		caller := graph.Nodes[declaration.RequiredCaller]
		if caller == nil {
			return nil, fmt.Errorf("compact semantic sink caller %s.%s does not exist", declaration.RequiredCaller.PackagePath, declaration.RequiredCaller.Symbol)
		}
		if _, live := caller.Invokes[declaration.Sink]; !live {
			return nil, fmt.Errorf("compact semantic sink caller %s.%s must directly call %s.%s", declaration.RequiredCaller.PackagePath, declaration.RequiredCaller.Symbol, declaration.Sink.PackagePath, declaration.Sink.Symbol)
		}
		if _, duplicate := seen[declaration.Sink]; duplicate {
			return nil, fmt.Errorf("compact semantic sink %s.%s is declared more than once", declaration.Sink.PackagePath, declaration.Sink.Symbol)
		}
		seen[declaration.Sink] = struct{}{}
		result = append(result, declaration.Sink)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].PackagePath != result[j].PackagePath {
			return result[i].PackagePath < result[j].PackagePath
		}
		return result[i].Symbol < result[j].Symbol
	})
	return result, nil
}

func (graph *compactSourceGraph) validateReviewedWrappers(reviewed map[string]map[string]struct{}) error {
	reviewedIDs := make(map[compactSymbolID]struct{})
	for packagePath, symbols := range reviewed {
		for symbol := range symbols {
			id := compactSymbolID{PackagePath: packagePath, Symbol: symbol}
			if graph.Nodes[id] == nil {
				return fmt.Errorf("reviewed compact wrapper %s.%s does not exist", packagePath, symbol)
			}
			reviewedIDs[id] = struct{}{}
		}
	}
	ids := make([]compactSymbolID, 0, len(reviewedIDs))
	for id := range reviewedIDs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].PackagePath != ids[j].PackagePath {
			return ids[i].PackagePath < ids[j].PackagePath
		}
		return ids[i].Symbol < ids[j].Symbol
	})
	if err := graph.rejectReviewedWrapperCycles(ids, reviewedIDs); err != nil {
		return err
	}
	memo := make(map[compactSymbolID]bool)
	for _, id := range ids {
		found := graph.reachesCompactOwner(id, make(map[compactSymbolID]struct{}), memo)
		if !found {
			return fmt.Errorf("reviewed compact wrapper %s.%s does not reach compact owner", id.PackagePath, id.Symbol)
		}
	}
	return nil
}

func (graph *compactSourceGraph) rejectReviewedWrapperCycles(ids []compactSymbolID, reviewed map[compactSymbolID]struct{}) error {
	state := make(map[compactSymbolID]uint8)
	var visit func(compactSymbolID) error
	visit = func(id compactSymbolID) error {
		if state[id] == 1 {
			return fmt.Errorf("reviewed compact wrapper graph contains cycle at %s.%s", id.PackagePath, id.Symbol)
		}
		if state[id] == 2 {
			return nil
		}
		state[id] = 1
		for target := range graph.Nodes[id].References {
			if _, ok := reviewed[target]; !ok {
				continue
			}
			if err := visit(target); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for _, id := range ids {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func (graph *compactSourceGraph) reachesCompactOwner(id compactSymbolID, visiting map[compactSymbolID]struct{}, memo map[compactSymbolID]bool) bool {
	if result, ok := memo[id]; ok {
		return result
	}
	if _, cycle := visiting[id]; cycle {
		return false
	}
	node := graph.Nodes[id]
	if node == nil {
		return false
	}
	if node.OwnerDirect {
		memo[id] = true
		return true
	}
	visiting[id] = struct{}{}
	defer delete(visiting, id)
	for target := range node.References {
		if target.PackagePath == compactOwnerImportPath {
			memo[id] = true
			return true
		}
		if graph.reachesCompactOwner(target, visiting, memo) {
			memo[id] = true
			return true
		}
	}
	memo[id] = false
	return false
}

func compactSourceFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	fixtureFiles := make(map[string]string, len(files)+1)
	for relative, content := range files {
		fixtureFiles[relative] = content
	}
	if _, exists := fixtureFiles["internal/kernel/compactproofcontract/owner.go"]; !exists {
		fixtureFiles["internal/kernel/compactproofcontract/owner.go"] = `package compactproofcontract
type Contract struct{}
func Admit(any) (any, error) { return nil, nil }
func SurfaceColumns() []string { return nil }
`
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module "+proofkitModuleImportPath+"\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for relative, content := range fixtureFiles {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
