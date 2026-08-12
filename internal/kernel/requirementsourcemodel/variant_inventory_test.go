package requirementsourcemodel

import (
	"go/constant"
	"go/types"
	"reflect"
	"sort"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestIndependentManifestMatchesExactProductionEnumInventory(t *testing.T) {
	manifest := readStrictJSON[completenessManifest](t, "testdata/field-projection-manifest.v1.json")
	manifestValues := map[string][]string{}
	for _, variant := range manifest.Variants {
		manifestValues[variant.VariantID] = variant.Values
	}
	expected := map[string]string{
		"claimLevel":     "ClaimLevel",
		"riskClass":      "RiskClass",
		"lifecycleState": "LifecycleState",
		"termKind":       "TermKind",
		"sourceKind":     "SourceKind",
		"objectFormat":   "ObjectFormat",
		"metadataOwner":  "MetadataOwnerKind",
		"entityKind":     "EntityKind",
		"referenceKind":  "ReferenceKind",
	}
	accepted := map[string][]string{
		"claimLevel":     variantStrings(claimLevelVariants),
		"riskClass":      variantStrings(riskClassVariants),
		"lifecycleState": variantStrings(lifecycleStateVariants),
		"termKind":       variantStrings(termKindVariants),
		"sourceKind":     variantStrings(sourceKindVariants),
		"objectFormat":   variantStrings(objectFormatVariants),
	}
	for variantID, values := range accepted {
		sort.Strings(values)
		if !reflect.DeepEqual(values, manifestValues[variantID]) {
			t.Fatalf("validator variants %s = %v, manifest = %v", variantID, values, manifestValues[variantID])
		}
	}
	production := productionEnumValues(t)
	for variantID, typeName := range expected {
		actual := append([]string(nil), production[typeName]...)
		sort.Strings(actual)
		if !reflect.DeepEqual(actual, manifestValues[variantID]) {
			t.Fatalf("production enum %s = %v, manifest %s = %v", typeName, actual, variantID, manifestValues[variantID])
		}
		delete(production, typeName)
	}
	if len(production) != 0 {
		t.Fatalf("unclassified production enum types: %v", production)
	}
}

func variantStrings[T ~string](values []T) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func productionEnumValues(t *testing.T) map[string][]string {
	t.Helper()
	loaded, err := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax | packages.NeedFiles,
	}, ".")
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(loaded) != 0 || len(loaded) != 1 {
		t.Fatalf("loaded production packages = %d", len(loaded))
	}
	checked := loaded[0].Types
	result := map[string][]string{}
	for _, name := range checked.Scope().Names() {
		value, ok := checked.Scope().Lookup(name).(*types.Const)
		if !ok {
			continue
		}
		named, ok := value.Type().(*types.Named)
		if !ok || named.Obj().Pkg() != checked || named.Underlying().String() != "string" || value.Val().Kind() != constant.String {
			continue
		}
		result[named.Obj().Name()] = append(result[named.Obj().Name()], constant.StringVal(value.Val()))
	}
	return result
}
