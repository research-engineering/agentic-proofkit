package requirementsourcemodel

import (
	"go/types"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// This inventory is intentionally independent of the production normalizer and
// the JSON completeness manifest. A new typed input field must be classified
// here and in the manifest before the completeness gate can pass.
var inputFieldManifestIDs = map[string][]string{
	"ByteRange.End":                           {"derivation.selector.end"},
	"ByteRange.Start":                         {"derivation.selector.start"},
	"Deferral.EvidenceRefs":                   {"metadata.deferral.evidenceRefs"},
	"Deferral.ExpiryRef":                      {"metadata.deferral.expiryRef"},
	"Deferral.MergePolicy":                    {"metadata.deferral.mergePolicy"},
	"Deferral.OwnerID":                        {"metadata.deferral.ownerId"},
	"Deferral.ReviewCondition":                {"metadata.deferral.reviewCondition"},
	"Deferral.RiskAcceptedBy":                 {"metadata.deferral.riskAcceptedBy"},
	"Derivation.DerivationID":                 {"derivation.id"},
	"Derivation.NonClaimRefs":                 {"derivation.nonClaimRefs"},
	"Derivation.RequirementIDs":               {"derivation.requirementIds"},
	"Derivation.Selector":                     nil,
	"Derivation.SourceKind":                   {"derivation.sourceKind"},
	"Derivation.SourceRef":                    nil,
	"Draft.Derivations":                       nil,
	"Draft.Groups":                            nil,
	"Draft.NonClaimDefinitions":               nil,
	"Draft.Profiles":                          nil,
	"Draft.Scenarios":                         nil,
	"Draft.SourceID":                          {"source.id"},
	"Draft.SourceNonClaimRefs":                {"source.nonClaimRefs"},
	"Draft.SpecPackagePath":                   {"source.specPackagePath"},
	"Draft.Vocabulary":                        nil,
	"Example.ExampleID":                       {"scenario.example.id"},
	"Example.Values":                          {"scenario.example.values"},
	"GitBlobRef.CommitOID":                    {"derivation.sourceRef.commitOid"},
	"GitBlobRef.ObjectFormat":                 {"derivation.sourceRef.objectFormat"},
	"GitBlobRef.Path":                         {"derivation.sourceRef.path"},
	"GitBlobRef.SHA256":                       {"derivation.sourceRef.sha256"},
	"Group.GroupID":                           {"group.id"},
	"Group.Members":                           {"group.memberRefs"},
	"Group.ProfileID":                         {"group.profileRef"},
	"Group.SharedPremises":                    {"group.sharedPremises"},
	"Group.StatementStem":                     {"group.statementStem"},
	"Lifecycle.EvidenceRefs":                  {"metadata.lifecycle.evidenceRefs"},
	"Lifecycle.ReplacementRequirementIDs":     {"metadata.lifecycle.replacementRequirementIds"},
	"Lifecycle.State":                         {"metadata.lifecycle.state"},
	"Member.Fields":                           nil,
	"Member.RequirementID":                    {"member.requirementId"},
	"Member.StatementCompletion":              {"member.statementCompletion"},
	"MetadataFields.ClaimLevel":               {"metadata.claimLevel"},
	"MetadataFields.Deferral":                 {"metadata.deferral.presence"},
	"MetadataFields.Lifecycle":                nil,
	"MetadataFields.NonClaimRefs":             {"metadata.nonClaimRefs"},
	"MetadataFields.OwnerID":                  {"metadata.ownerId"},
	"MetadataFields.RiskClass":                {"metadata.riskClass"},
	"MetadataFields.UpdatePolicy":             nil,
	"NonClaimDefinition.NonClaimID":           {"nonClaim.id"},
	"NonClaimDefinition.Statement":            {"nonClaim.statement"},
	"Profile.Fields":                          nil,
	"Profile.ProfileID":                       {"profile.id"},
	"Scenario.ActionSequence":                 {"scenario.actionSequence"},
	"Scenario.Examples":                       nil,
	"Scenario.ExpectedObservations":           {"scenario.expectedObservations"},
	"Scenario.ForbiddenObservations":          {"scenario.forbiddenObservations"},
	"Scenario.NonClaimRefs":                   {"scenario.nonClaimRefs"},
	"Scenario.Parameters":                     {"scenario.parameters"},
	"Scenario.Preconditions":                  {"scenario.preconditions"},
	"Scenario.RequirementIDs":                 {"scenario.requirementIds"},
	"Scenario.ScenarioID":                     {"scenario.id"},
	"Scenario.VocabularyRefs":                 {"scenario.vocabularyRefs"},
	"UpdatePolicy.RequiresImpactDeclaration":  {"metadata.updatePolicy.requiresImpactDeclaration"},
	"UpdatePolicy.RequiresProofBindingReview": {"metadata.updatePolicy.requiresProofBindingReview"},
	"UpdatePolicy.ReviewOwnerID":              {"metadata.updatePolicy.reviewOwnerId"},
	"VocabularyTerm.Definition":               {"vocabulary.definition"},
	"VocabularyTerm.Kind":                     {"vocabulary.kind"},
	"VocabularyTerm.Label":                    {"vocabulary.label"},
	"VocabularyTerm.TermID":                   {"vocabulary.id"},
}

func TestIndependentManifestMatchesExactTypedInputFieldInventory(t *testing.T) {
	assertExactFieldWrapperShape(t)
	assertRepresentationNeutralModelShape(t)
	manifest := readStrictJSON[completenessManifest](t, "testdata/field-projection-manifest.v1.json")
	actualPaths := typedInputFieldPaths(reflect.TypeOf(Draft{}))
	expectedPaths := make([]string, 0, len(inputFieldManifestIDs))
	for path := range inputFieldManifestIDs {
		expectedPaths = append(expectedPaths, path)
	}
	sort.Strings(expectedPaths)
	if !reflect.DeepEqual(actualPaths, expectedPaths) {
		t.Fatalf("typed input fields = %v, classified fields = %v", actualPaths, expectedPaths)
	}

	manifestIDs := make([]string, 0, len(manifest.Fields))
	for _, field := range manifest.Fields {
		manifestIDs = append(manifestIDs, field.FieldID)
	}
	sort.Strings(manifestIDs)
	mappedIDs := []string{}
	seen := map[string]struct{}{}
	for _, ids := range inputFieldManifestIDs {
		for _, id := range ids {
			if _, exists := seen[id]; exists {
				continue
			}
			seen[id] = struct{}{}
			mappedIDs = append(mappedIDs, id)
		}
	}
	sort.Strings(mappedIDs)
	if !reflect.DeepEqual(manifestIDs, mappedIDs) {
		t.Fatalf("manifest fields = %v, typed input mapping = %v", manifestIDs, mappedIDs)
	}
}

func assertExactFieldWrapperShape(t *testing.T) {
	t.Helper()
	wrapper := reflect.TypeOf(Field[string]{})
	actual := make([]string, wrapper.NumField())
	for index := 0; index < wrapper.NumField(); index++ {
		field := wrapper.Field(index)
		actual[index] = field.Name + ":" + field.Type.String() + ":" + string(field.Tag)
		if field.Anonymous || !field.IsExported() {
			t.Fatalf("Field[T].%s must remain exported and non-anonymous", field.Name)
		}
	}
	expected := []string{"Present:bool:", "Value:string:"}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Field[T] structural inventory = %v, want %v", actual, expected)
	}
	assertMethodNames(t, wrapper, nil)
	assertMethodNames(t, reflect.PointerTo(wrapper), nil)
}

func assertRepresentationNeutralModelShape(t *testing.T) {
	t.Helper()
	roots := []reflect.Type{
		reflect.TypeOf(Draft{}),
		reflect.TypeOf(AtomicProjection{}),
		reflect.TypeOf(LayoutProjection{}),
		reflect.TypeOf(ReferenceProjection{}),
		reflect.TypeOf(Limits{}),
	}
	seen := map[reflect.Type]struct{}{}
	for _, root := range roots {
		inspectRepresentationNeutralType(t, root, seen)
	}
	assertExactProductionMethodSets(t, seen)

	model := reflect.TypeOf(Model{})
	expectedFields := []string{
		"atomic:" + reflect.TypeOf(AtomicProjection{}).String(),
		"layout:" + reflect.TypeOf(LayoutProjection{}).String(),
		"references:" + reflect.TypeOf(ReferenceProjection{}).String(),
	}
	actualFields := make([]string, model.NumField())
	for index := 0; index < model.NumField(); index++ {
		field := model.Field(index)
		actualFields[index] = field.Name + ":" + field.Type.String()
		if field.Anonymous || field.Tag != "" || field.IsExported() {
			t.Fatalf("Model.%s must remain private, untagged, and non-anonymous", field.Name)
		}
	}
	if !reflect.DeepEqual(actualFields, expectedFields) {
		t.Fatalf("Model structural inventory = %v, want %v", actualFields, expectedFields)
	}
	assertMethodNames(t, model, []string{"Atomic", "Layout", "References"})
	assertMethodNames(t, reflect.PointerTo(model), []string{"Atomic", "Layout", "References"})
	assertAccessorSignature(t, model, "Atomic", reflect.TypeOf(AtomicProjection{}))
	assertAccessorSignature(t, model, "Layout", reflect.TypeOf(LayoutProjection{}))
	assertAccessorSignature(t, model, "References", reflect.TypeOf(ReferenceProjection{}))
}

func inspectRepresentationNeutralType(t *testing.T, value reflect.Type, seen map[reflect.Type]struct{}) {
	t.Helper()
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		value = value.Elem()
	}
	if value.Kind() == reflect.Map {
		inspectRepresentationNeutralType(t, value.Key(), seen)
		inspectRepresentationNeutralType(t, value.Elem(), seen)
		return
	}
	if value.PkgPath() != reflect.TypeOf(Draft{}).PkgPath() {
		return
	}
	if _, exists := seen[value]; exists {
		return
	}
	seen[value] = struct{}{}
	assertMethodNames(t, value, nil)
	assertMethodNames(t, reflect.PointerTo(value), nil)
	if value.Kind() != reflect.Struct {
		return
	}
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		if field.Anonymous || field.Tag != "" || !field.IsExported() {
			t.Fatalf("%s.%s must remain exported, untagged, and non-anonymous", value.Name(), field.Name)
		}
		inspectRepresentationNeutralType(t, field.Type, seen)
	}
}

func assertMethodNames(t *testing.T, value reflect.Type, expected []string) {
	t.Helper()
	actual := make([]string, value.NumMethod())
	for index := 0; index < value.NumMethod(); index++ {
		actual[index] = value.Method(index).Name
	}
	if len(actual) != len(expected) {
		t.Fatalf("%s method set = %v, want %v", value, actual, expected)
	}
	for index := range actual {
		if actual[index] != expected[index] {
			t.Fatalf("%s method set = %v, want %v", value, actual, expected)
		}
	}
}

func assertAccessorSignature(t *testing.T, receiver reflect.Type, name string, output reflect.Type) {
	t.Helper()
	method, exists := receiver.MethodByName(name)
	if !exists || method.Type.NumIn() != 1 || method.Type.NumOut() != 1 || method.Type.Out(0) != output || method.Type.IsVariadic() {
		t.Fatalf("Model.%s has unexpected signature", name)
	}
}

func assertExactProductionMethodSets(t *testing.T, reflected map[reflect.Type]struct{}) {
	t.Helper()
	loaded, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedTypes}, ".")
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(loaded) != 0 || len(loaded) != 1 {
		t.Fatalf("loaded production packages = %d", len(loaded))
	}
	typeNames := map[string]struct{}{"Model": {}}
	for value := range reflected {
		name := value.Name()
		if generic := strings.IndexByte(name, '['); generic >= 0 {
			name = name[:generic]
		}
		if name != "" {
			typeNames[name] = struct{}{}
		}
	}
	for name := range typeNames {
		object, ok := loaded[0].Types.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			t.Fatalf("production type %s is unavailable", name)
		}
		named, ok := object.Type().(*types.Named)
		if !ok {
			t.Fatalf("production type %s is not named", name)
		}
		expected := []string{}
		if name == "Model" {
			expected = []string{"Atomic", "Layout", "References"}
		}
		assertGoMethodSet(t, name, types.NewMethodSet(named), expected)
		assertGoMethodSet(t, "*"+name, types.NewMethodSet(types.NewPointer(named)), expected)
	}
}

func assertGoMethodSet(t *testing.T, owner string, methods *types.MethodSet, expected []string) {
	t.Helper()
	actual := make([]string, methods.Len())
	for index := 0; index < methods.Len(); index++ {
		actual[index] = methods.At(index).Obj().Name()
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("%s production method set = %v, want %v", owner, actual, expected)
	}
}

func typedInputFieldPaths(root reflect.Type) []string {
	seen := map[reflect.Type]struct{}{}
	paths := []string{}
	var visit func(reflect.Type)
	visit = func(value reflect.Type) {
		for value.Kind() == reflect.Pointer || value.Kind() == reflect.Slice || value.Kind() == reflect.Array || value.Kind() == reflect.Map {
			value = value.Elem()
		}
		if value.Kind() != reflect.Struct || value.PkgPath() != reflect.TypeOf(Draft{}).PkgPath() {
			return
		}
		if strings.HasPrefix(value.Name(), "Field[") {
			field, exists := value.FieldByName("Value")
			if exists {
				visit(field.Type)
			}
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			paths = append(paths, value.Name()+"."+field.Name)
			visit(field.Type)
		}
	}
	visit(root)
	sort.Strings(paths)
	return paths
}
