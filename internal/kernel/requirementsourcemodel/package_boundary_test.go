package requirementsourcemodel

import (
	"go/ast"
	"reflect"
	"sort"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestRepresentationNeutralPackageBoundaryIsExact(t *testing.T) {
	loaded, err := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedImports,
	}, ".")
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(loaded) != 0 || len(loaded) != 1 {
		t.Fatalf("loaded production packages = %d", len(loaded))
	}

	actualExports := []string{}
	for _, name := range loaded[0].Types.Scope().Names() {
		if ast.IsExported(name) {
			actualExports = append(actualExports, name)
		}
	}
	expectedExports := []string{
		"AtomicProjection", "AtomicRequirement", "ByteRange",
		"ClaimAdvisory", "ClaimBlocking", "ClaimDeferred", "ClaimLevel",
		"DefaultLimits", "Deferral", "Derivation", "Draft",
		"EntityDerivation", "EntityGroup", "EntityKind", "EntityNonClaim", "EntityProfile", "EntityRequirement", "EntityScenario", "EntitySource", "EntityTerm",
		"ErrorCode", "Example", "Field", "FieldOwner", "GitBlobRef", "Group",
		"LayoutProjection", "Lifecycle", "LifecycleActive", "LifecycleDeprecated", "LifecycleRemoved", "LifecycleState", "LifecycleSuperseded", "Limits",
		"Member", "MetadataFieldID", "MetadataFields", "MetadataOwnerKind", "MetadataOwnerMember", "MetadataOwnerProfile", "Model",
		"NonClaimDefinition", "Normalize", "NormalizeWithLimits",
		"ObjectFormat", "ObjectSHA1", "ObjectSHA256", "Origin", "Own", "Profile",
		"ReferenceDerivationNonClaim", "ReferenceDerivationRequirement", "ReferenceEdge", "ReferenceEndpoint", "ReferenceGroupMember", "ReferenceGroupProfile", "ReferenceKind", "ReferenceLifecycleReplacement", "ReferenceProjection", "ReferenceRequirementNonClaim", "ReferenceScenarioNonClaim", "ReferenceScenarioRequirement", "ReferenceScenarioVocabulary", "ReferenceSourceNonClaim",
		"RiskClass", "RiskCritical", "RiskHigh", "RiskLow", "RiskMedium",
		"Scenario", "ScenarioValue", "SourceClarification", "SourceCodeSnapshot", "SourceDesign", "SourceKind", "SourceOwnerDecision", "SourcePlan",
		"TermAction", "TermKind", "TermObservable", "TermState", "TermSubject", "TermValue",
		"UpdatePolicy", "ValidateLimits", "ValidationError", "VocabularyTerm",
	}
	sort.Strings(actualExports)
	sort.Strings(expectedExports)
	if !reflect.DeepEqual(actualExports, expectedExports) {
		t.Fatalf("production exports = %v, exact model boundary = %v", actualExports, expectedExports)
	}

	actualImports := make([]string, 0, len(loaded[0].Imports))
	for path := range loaded[0].Imports {
		actualImports = append(actualImports, path)
	}
	sort.Strings(actualImports)
	expectedImports := []string{
		"fmt",
		"github.com/research-engineering/agentic-proofkit/internal/kernel/admit",
		"reflect",
		"regexp",
		"sort",
		"strings",
	}
	if !reflect.DeepEqual(actualImports, expectedImports) {
		t.Fatalf("production direct imports = %v, representation-neutral allowlist = %v", actualImports, expectedImports)
	}
}
