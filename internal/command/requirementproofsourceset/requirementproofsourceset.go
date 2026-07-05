package requirementproofsourceset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
)

var sourceRoles = map[string]struct{}{
	"requirement_proof_binding_contract": {},
	"requirement_proof_binding_fragment": {},
}

var projectionKinds = map[string]struct{}{
	"canonical_contract": {},
	"resolver_input":     {},
}

var sourceSetColumns = []string{"source_id", "path", "sha256", "role", "non_claims"}

var canonicalSurfaceColumns = []string{
	"surface_id",
	"proof_families",
	"rollout_claim_allowed",
	"rollout_claim_state",
	"rollout_claim_scope",
	"required_environment_classes",
	"preconditioned_environment_classes",
	"mutation_resistance_state",
}

var canonicalBindingColumns = []string{
	"requirement_id",
	"surface_id",
	"scenario_id",
	"invariant_role",
	"owned_invariant",
	"proof_contract_state",
	"blocking_status",
	"required_environment_classes",
	"positive_witness",
	"falsification_witness",
	"verify_commands",
	"mutation_resistance_state",
}

var canonicalWitnessColumns = []string{
	"selector",
	"environment_classes",
	"verify_commands",
	"resolution_order_index",
}

type Input struct {
	SourceSet         map[string]any
	Sources           []SourceText
	CanonicalEnvelope Envelope
	Projection        Projection
}

type SourceText struct {
	Path string
	Text string
}

type Projection struct {
	Kind              string
	SelectedSourceIDs []string
}

type Envelope struct {
	SchemaVersion        int
	ContractKind         string
	ContractID           string
	AuthorityState       string
	NormalizationProfile string
	NonClaims            []string
	SurfaceColumns       []string
	BindingColumns       []string
	WitnessColumns       []string
}

type sourceRow struct {
	SourceID  string
	Path      string
	SHA256    string
	Role      string
	NonClaims []string
}

func Build(raw any) (any, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return nil, 1, err
	}
	textByPath, err := admitSourceTexts(input.Sources)
	if err != nil {
		return nil, 1, err
	}
	allSources, err := admitSourceSet(input.SourceSet)
	if err != nil {
		return nil, 1, err
	}
	sources, err := selectSources(allSources, input.Projection.SelectedSourceIDs)
	if err != nil {
		return nil, 1, err
	}
	payloads := make([]map[string]any, 0, len(sources))
	for _, source := range sources {
		sourceText, ok := textByPath[source.Path]
		if !ok {
			return nil, 1, fmt.Errorf("requirement proof binding source %s text is missing for %s", source.SourceID, source.Path)
		}
		if sha256Hex(sourceText) != source.SHA256 {
			return nil, 1, fmt.Errorf("requirement proof binding source %s sha256 drift", source.SourceID)
		}
		payload, err := parseJSONObject(sourceText, "requirement proof binding source "+source.SourceID)
		if err != nil {
			return nil, 1, err
		}
		if isSourceSetPayload(payload) {
			return nil, 1, fmt.Errorf("requirement proof binding source %s must not reference another source set", source.SourceID)
		}
		if source.Role == "requirement_proof_binding_fragment" {
			if !isFragmentPayload(payload) {
				return nil, 1, fmt.Errorf("requirement proof binding source %s.role must match compact fragment payload", source.SourceID)
			}
			inflated, err := inflateFragment(payload, source.SourceID, input.CanonicalEnvelope)
			if err != nil {
				return nil, 1, err
			}
			payloads = append(payloads, inflated)
			continue
		}
		if isFragmentPayload(payload) {
			return nil, 1, fmt.Errorf("requirement proof binding source %s.role must match compact fragment payload", source.SourceID)
		}
		admitted, err := admitCanonicalContract(payload, input.CanonicalEnvelope, "requirement proof binding source "+source.SourceID)
		if err != nil {
			return nil, 1, err
		}
		payloads = append(payloads, admitted)
	}
	sourceSetPaths := map[string]struct{}{}
	for _, source := range allSources {
		sourceSetPaths[source.Path] = struct{}{}
	}
	selectedPaths := map[string]struct{}{}
	for _, source := range sources {
		selectedPaths[source.Path] = struct{}{}
	}
	for path := range textByPath {
		if _, ok := sourceSetPaths[path]; !ok {
			return nil, 1, fmt.Errorf("requirement proof binding source text is not referenced by source set: %s", path)
		}
	}
	combined, err := combineCanonicalContracts(payloads, input.CanonicalEnvelope)
	if err != nil {
		return nil, 1, err
	}
	inputPaths := make([]string, 0, len(selectedPaths))
	for path := range selectedPaths {
		inputPaths = append(inputPaths, path)
	}
	sort.Strings(inputPaths)
	output := map[string]any{
		"inputPaths":        stringSliceToAny(inputPaths),
		"projectionKind":    "proofkit.requirement-proof-source-set." + input.Projection.Kind,
		"selectedSourceIds": stringSliceToAny(project(sources, func(row sourceRow) string { return row.SourceID })),
		"sourceCount":       len(sources),
		"sourceSetCount":    len(allSources),
	}
	if input.Projection.Kind == "resolver_input" {
		resolverInput, err := resolverProjection(combined, input.CanonicalEnvelope)
		if err != nil {
			return nil, 1, err
		}
		output["resolverInput"] = resolverInput
		return output, 0, nil
	}
	output["contract"] = combined
	return output, 0, nil
}

func admitInput(raw any) (Input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Input{}, fmt.Errorf("requirement proof binding source-set normalization input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"canonicalEnvelope", "projection", "sourceSet", "sources"}, "requirement proof binding source-set normalization input"); err != nil {
		return Input{}, err
	}
	envelope, err := admitCanonicalEnvelope(record["canonicalEnvelope"])
	if err != nil {
		return Input{}, err
	}
	sources, err := sourceTexts(record["sources"])
	if err != nil {
		return Input{}, err
	}
	sourceSet, ok := record["sourceSet"].(map[string]any)
	if !ok {
		return Input{}, fmt.Errorf("requirement proof binding source set must be an object")
	}
	projection, err := admitProjection(record["projection"])
	if err != nil {
		return Input{}, err
	}
	return Input{SourceSet: sourceSet, Sources: sources, CanonicalEnvelope: envelope, Projection: projection}, nil
}

func admitProjection(raw any) (Projection, error) {
	if raw == nil {
		return Projection{Kind: "canonical_contract"}, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return Projection{}, fmt.Errorf("requirement proof binding source-set projection must be an object")
	}
	if err := admit.KnownKeys(record, []string{"kind", "selectedSourceIds"}, "requirement proof binding source-set projection"); err != nil {
		return Projection{}, err
	}
	kind := "canonical_contract"
	var err error
	if record["kind"] != nil {
		kind, err = admit.Enum(record["kind"], projectionKinds, "requirement proof binding source-set projection.kind")
		if err != nil {
			return Projection{}, err
		}
	}
	selected, err := sourceIDArray(record["selectedSourceIds"], "requirement proof binding source-set projection.selectedSourceIds", true)
	if err != nil {
		return Projection{}, err
	}
	if err := assertUnique(selected, "requirement proof binding selected source_id"); err != nil {
		return Projection{}, err
	}
	return Projection{Kind: kind, SelectedSourceIDs: selected}, nil
}

func admitCanonicalEnvelope(raw any) (Envelope, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Envelope{}, fmt.Errorf("requirement proof binding canonical envelope must be an object")
	}
	if err := admit.KnownKeys(record, []string{"authorityState", "bindingColumns", "contractId", "contractKind", "nonClaims", "normalizationProfile", "schemaVersion", "surfaceColumns", "witnessColumns"}, "requirement proof binding canonical envelope"); err != nil {
		return Envelope{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Envelope{}, fmt.Errorf("requirement proof binding canonical envelope schemaVersion must be 1")
	}
	envelope := Envelope{SchemaVersion: 1}
	var err error
	if envelope.ContractKind, err = strictText(record["contractKind"], "canonical envelope contractKind"); err != nil {
		return Envelope{}, err
	}
	if envelope.ContractID, err = strictText(record["contractId"], "canonical envelope contractId"); err != nil {
		return Envelope{}, err
	}
	if envelope.AuthorityState, err = strictText(record["authorityState"], "canonical envelope authorityState"); err != nil {
		return Envelope{}, err
	}
	if envelope.NormalizationProfile, err = strictText(record["normalizationProfile"], "canonical envelope normalizationProfile"); err != nil {
		return Envelope{}, err
	}
	if envelope.NonClaims, err = stringArray(record["nonClaims"], "canonical envelope nonClaims"); err != nil {
		return Envelope{}, err
	}
	if envelope.SurfaceColumns, err = stringArray(record["surfaceColumns"], "canonical envelope surfaceColumns"); err != nil {
		return Envelope{}, err
	}
	if envelope.BindingColumns, err = stringArray(record["bindingColumns"], "canonical envelope bindingColumns"); err != nil {
		return Envelope{}, err
	}
	if envelope.WitnessColumns, err = stringArray(record["witnessColumns"], "canonical envelope witnessColumns"); err != nil {
		return Envelope{}, err
	}
	if err := assertExactArray(envelope.SurfaceColumns, canonicalSurfaceColumns, "canonical envelope surfaceColumns"); err != nil {
		return Envelope{}, err
	}
	if err := assertExactArray(envelope.BindingColumns, canonicalBindingColumns, "canonical envelope bindingColumns"); err != nil {
		return Envelope{}, err
	}
	if err := assertExactArray(envelope.WitnessColumns, canonicalWitnessColumns, "canonical envelope witnessColumns"); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func sourceTexts(raw any) ([]SourceText, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("requirement proof binding source texts must be an array")
	}
	result := make([]SourceText, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		context := fmt.Sprintf("requirement proof binding source text #%d", index+1)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", context)
		}
		if err := admit.KnownKeys(record, []string{"path", "text"}, context); err != nil {
			return nil, err
		}
		pathText, err := strictText(record["path"], context+".path")
		if err != nil {
			return nil, err
		}
		path, err := admit.SafeRepoRelativePath(pathText, context+".path")
		if err != nil {
			return nil, err
		}
		text, ok := record["text"].(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("requirement proof binding source text %s.text must be non-empty text", path)
		}
		result = append(result, SourceText{Path: path, Text: text})
	}
	return result, nil
}

func admitSourceTexts(sources []SourceText) (map[string]string, error) {
	result := map[string]string{}
	for _, source := range sources {
		if _, ok := result[source.Path]; ok {
			return nil, fmt.Errorf("duplicate requirement proof binding source text path=%s", source.Path)
		}
		result[source.Path] = source.Text
	}
	return result, nil
}

func admitSourceSet(record map[string]any) ([]sourceRow, error) {
	if err := admit.KnownKeys(record, []string{"authority_state", "contract_id", "contract_kind", "non_claims", "normalization_profile", "schema_version", "source_columns", "sources"}, "requirement proof binding source set"); err != nil {
		return nil, err
	}
	if !admit.JSONNumberEquals(record["schema_version"], 1) {
		return nil, fmt.Errorf("requirement proof binding source set schema_version must be 1")
	}
	required := map[string]string{
		"contract_kind":         "requirement_proof_binding_source_set",
		"contract_id":           "requirement-proof-bindings/source-set/v1",
		"authority_state":       "requirement_proof_binding_source_index",
		"normalization_profile": "json/v1:utf8+lf+ordered-source-refs",
	}
	for key, expected := range required {
		value, err := strictText(record[key], "requirement proof binding source set "+key)
		if err != nil {
			return nil, err
		}
		if value != expected {
			return nil, fmt.Errorf("requirement proof binding source set %s must be %s", key, expected)
		}
	}
	columns, err := stringArray(record["source_columns"], "requirement proof binding source set source_columns")
	if err != nil {
		return nil, err
	}
	if err := assertExactArray(columns, sourceSetColumns, "source_columns"); err != nil {
		return nil, err
	}
	if _, err := stringArray(record["non_claims"], "requirement proof binding source set non_claims"); err != nil {
		return nil, err
	}
	values, ok := record["sources"].([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("requirement proof binding source set sources must be a non-empty array")
	}
	result := make([]sourceRow, 0, len(values))
	for index, value := range values {
		row, err := admitSourceRow(value, index)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	if err := assertUnique(project(result, func(row sourceRow) string { return row.SourceID }), "requirement proof binding source_id"); err != nil {
		return nil, err
	}
	if err := assertUnique(project(result, func(row sourceRow) string { return row.Path }), "requirement proof binding source path"); err != nil {
		return nil, err
	}
	return result, nil
}

func admitSourceRow(raw any, index int) (sourceRow, error) {
	values, ok := raw.([]any)
	if !ok || len(values) != len(sourceSetColumns) {
		return sourceRow{}, fmt.Errorf("requirement proof binding source row #%d must use source_columns", index+1)
	}
	sourceID, err := admit.RuleID(values[0], fmt.Sprintf("requirement proof binding source row #%d.source_id", index+1))
	if err != nil {
		return sourceRow{}, err
	}
	pathText, err := strictText(values[1], "requirement proof binding source "+sourceID+".path")
	if err != nil {
		return sourceRow{}, err
	}
	path, err := admit.SafeRepoRelativePath(pathText, "source "+sourceID+".path")
	if err != nil {
		return sourceRow{}, err
	}
	sha, err := strictText(values[2], "requirement proof binding source "+sourceID+".sha256")
	if err != nil {
		return sourceRow{}, err
	}
	if len(sha) != 64 || strings.ToLower(sha) != sha || strings.Trim(sha, "0123456789abcdef") != "" {
		return sourceRow{}, fmt.Errorf("requirement proof binding source %s.sha256 must be lowercase sha256", sourceID)
	}
	role, err := admit.Enum(values[3], sourceRoles, "requirement proof binding source "+sourceID+".role")
	if err != nil {
		return sourceRow{}, err
	}
	nonClaims, err := stringArray(values[4], "requirement proof binding source "+sourceID+".non_claims")
	if err != nil {
		return sourceRow{}, err
	}
	return sourceRow{SourceID: sourceID, Path: path, SHA256: sha, Role: role, NonClaims: nonClaims}, nil
}

func selectSources(sources []sourceRow, selectedSourceIDs []string) ([]sourceRow, error) {
	if len(selectedSourceIDs) == 0 {
		return sources, nil
	}
	selected := map[string]struct{}{}
	for _, sourceID := range selectedSourceIDs {
		selected[sourceID] = struct{}{}
	}
	result := make([]sourceRow, 0, len(selectedSourceIDs))
	for _, source := range sources {
		if _, ok := selected[source.SourceID]; ok {
			result = append(result, source)
		}
	}
	if len(result) == len(selectedSourceIDs) {
		return result, nil
	}
	known := map[string]struct{}{}
	for _, source := range sources {
		known[source.SourceID] = struct{}{}
	}
	missing := []string{}
	for _, sourceID := range selectedSourceIDs {
		if _, ok := known[sourceID]; !ok {
			missing = append(missing, sourceID)
		}
	}
	sort.Strings(missing)
	return nil, fmt.Errorf("requirement proof binding source set does not contain selected source_id(s): %s", strings.Join(missing, ", "))
}

func inflateFragment(payload map[string]any, expectedSourceID string, envelope Envelope) (map[string]any, error) {
	if err := admit.KnownKeys(payload, []string{"authority_state", "bindings", "contract_id", "contract_kind", "normalization_profile", "schema_version", "source_id", "surfaces"}, "requirement proof binding fragment "+expectedSourceID); err != nil {
		return nil, err
	}
	if !admit.JSONNumberEquals(payload["schema_version"], 1) {
		return nil, fmt.Errorf("requirement proof binding fragment %s schema_version must be 1", expectedSourceID)
	}
	if payload["contract_kind"] != "requirement_proof_binding_fragment" {
		return nil, fmt.Errorf("requirement proof binding fragment %s contract_kind must be requirement_proof_binding_fragment", expectedSourceID)
	}
	contractID, err := strictText(payload["contract_id"], "requirement proof binding fragment "+expectedSourceID+".contract_id")
	if err != nil {
		return nil, err
	}
	if contractID != "requirement-proof-bindings/fragment/v1" && contractID != "requirement-proof-bindings/fragment/v2" {
		return nil, fmt.Errorf("requirement proof binding fragment %s.contract_id must be requirement-proof-bindings/fragment/v1 or requirement-proof-bindings/fragment/v2", expectedSourceID)
	}
	if payload["authority_state"] != "canonical_requirement_to_proof_binding_fragment" {
		return nil, fmt.Errorf("requirement proof binding fragment %s authority_state must be canonical_requirement_to_proof_binding_fragment", expectedSourceID)
	}
	expectedProfile := "json/v1:utf8+lf+compact-owner-row-arrays"
	if contractID == "requirement-proof-bindings/fragment/v2" {
		expectedProfile = "json/v1:utf8+lf+owner-defaulted-row-arrays"
	}
	if payload["normalization_profile"] != expectedProfile {
		return nil, fmt.Errorf("requirement proof binding fragment %s normalization_profile must be %s", expectedSourceID, expectedProfile)
	}
	sourceID, err := strictText(payload["source_id"], "requirement proof binding fragment "+expectedSourceID+".source_id")
	if err != nil {
		return nil, err
	}
	if _, err := admit.RuleID(sourceID, "requirement proof binding fragment "+expectedSourceID+".source_id"); err != nil {
		return nil, err
	}
	if sourceID != expectedSourceID {
		return nil, fmt.Errorf("requirement proof binding fragment source_id must match source set id %s", expectedSourceID)
	}
	bindings := payload["bindings"]
	if contractID == "requirement-proof-bindings/fragment/v2" {
		values, ok := bindings.([]any)
		if !ok {
			return nil, fmt.Errorf("requirement proof binding fragment %s.bindings must be an array", sourceID)
		}
		converted := make([]any, 0, len(values))
		for index, value := range values {
			row, err := compactV2BindingToCanonical(value, sourceID, index+1)
			if err != nil {
				return nil, err
			}
			converted = append(converted, row)
		}
		bindings = converted
	}
	return admitCanonicalContract(canonicalContract(envelope, payload["surfaces"], bindings), envelope, "requirement proof binding fragment "+sourceID)
}

func compactV2BindingToCanonical(raw any, sourceID string, rowIndex int) ([]any, error) {
	row, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("fragment v2 binding row #%d must be an array", rowIndex)
	}
	if len(row) != 10 && len(row) != 11 {
		return nil, fmt.Errorf("fragment v2 binding row #%d must use compact binding columns", rowIndex)
	}
	var requirementID, scenarioID, ownedInvariant, invariantRole, proofContractState, blockingStatus, requiredClasses, positive, falsification, verifyCommands, mutationState any
	if len(row) == 10 {
		requirementID, ownedInvariant, invariantRole, proofContractState, blockingStatus, requiredClasses, positive, falsification, verifyCommands, mutationState = row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9]
		ownedText, err := strictText(ownedInvariant, fmt.Sprintf("fragment v2 binding row #%d.owned_invariant", rowIndex))
		if err != nil {
			return nil, err
		}
		scenarioID = sourceID + "::" + ownedText
	} else {
		requirementID, scenarioID, ownedInvariant, invariantRole, proofContractState, blockingStatus, requiredClasses, positive, falsification, verifyCommands, mutationState = row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10]
		if _, err := strictText(scenarioID, fmt.Sprintf("fragment v2 binding row #%d.scenario_id", rowIndex)); err != nil {
			return nil, err
		}
		if _, err := strictText(ownedInvariant, fmt.Sprintf("fragment v2 binding row #%d.owned_invariant", rowIndex)); err != nil {
			return nil, err
		}
	}
	requiredArray, ok := requiredClasses.([]any)
	if !ok {
		return nil, fmt.Errorf("fragment v2 binding row #%d.required_environment_classes must be an array", rowIndex)
	}
	verifyArray, ok := verifyCommands.([]any)
	if !ok {
		return nil, fmt.Errorf("fragment v2 binding row #%d.verify_commands must be an array", rowIndex)
	}
	positiveWitness, err := compactV2Witness(positive, fmt.Sprintf("fragment v2 binding row #%d.positive_witness", rowIndex), requiredArray, verifyArray)
	if err != nil {
		return nil, err
	}
	falsificationWitness, err := compactV2Witness(falsification, fmt.Sprintf("fragment v2 binding row #%d.falsification_witness", rowIndex), requiredArray, verifyArray)
	if err != nil {
		return nil, err
	}
	return []any{requirementID, sourceID, scenarioID, invariantRole, ownedInvariant, proofContractState, blockingStatus, requiredArray, positiveWitness, falsificationWitness, verifyArray, mutationState}, nil
}

func compactV2Witness(raw any, context string, requiredClasses []any, verifyCommands []any) ([]any, error) {
	row, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	if len(row) == len(canonicalWitnessColumns) {
		return row, nil
	}
	if len(row) != 2 {
		return nil, fmt.Errorf("%s must use full witness columns or compact v2 witness row", context)
	}
	selector, err := strictText(row[0], context+".selector")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(selector, "::") {
		return nil, fmt.Errorf("%s.selector must use '<path>::<selector>'", context)
	}
	if _, ok := row[1].(json.Number); !ok {
		return nil, fmt.Errorf("%s.resolution_order_index must be an integer", context)
	}
	return []any{selector, append([]any{}, requiredClasses...), append([]any{}, verifyCommands...), row[1]}, nil
}

func admitCanonicalContract(raw map[string]any, envelope Envelope, context string) (map[string]any, error) {
	if err := admit.KnownKeys(raw, []string{"authority_state", "binding_columns", "bindings", "contract_id", "contract_kind", "non_claims", "normalization_profile", "schema_version", "surface_columns", "surfaces", "witness_columns"}, context); err != nil {
		return nil, err
	}
	checks := []struct {
		key      string
		expected any
	}{
		{"contract_kind", envelope.ContractKind},
		{"contract_id", envelope.ContractID},
		{"authority_state", envelope.AuthorityState},
		{"normalization_profile", envelope.NormalizationProfile},
	}
	if !admit.JSONNumberEquals(raw["schema_version"], int64(envelope.SchemaVersion)) {
		return nil, fmt.Errorf("%s schema_version must be %d", context, envelope.SchemaVersion)
	}
	for _, check := range checks {
		if raw[check.key] != check.expected {
			return nil, fmt.Errorf("%s %s must be %v", context, check.key, check.expected)
		}
	}
	nonClaims, err := stringArray(raw["non_claims"], context+" non_claims")
	if err != nil {
		return nil, err
	}
	if err := assertExactArray(nonClaims, envelope.NonClaims, context+" non_claims"); err != nil {
		return nil, err
	}
	surfaceColumns, err := stringArray(raw["surface_columns"], context+" surface_columns")
	if err != nil {
		return nil, err
	}
	if err := assertExactArray(surfaceColumns, envelope.SurfaceColumns, context+" surface_columns"); err != nil {
		return nil, err
	}
	bindingColumns, err := stringArray(raw["binding_columns"], context+" binding_columns")
	if err != nil {
		return nil, err
	}
	if err := assertExactArray(bindingColumns, envelope.BindingColumns, context+" binding_columns"); err != nil {
		return nil, err
	}
	witnessColumns, err := stringArray(raw["witness_columns"], context+" witness_columns")
	if err != nil {
		return nil, err
	}
	if err := assertExactArray(witnessColumns, envelope.WitnessColumns, context+" witness_columns"); err != nil {
		return nil, err
	}
	resolverInput, err := resolverProjection(raw, envelope)
	if err != nil {
		return nil, err
	}
	if _, _, err := requirementbinding.BuildResolver(resolverInput, requirementbinding.ResolverOptions{}); err != nil {
		return nil, err
	}
	return raw, nil
}

func resolverProjection(raw map[string]any, envelope Envelope) (map[string]any, error) {
	surfaceValues, ok := raw["surfaces"].([]any)
	if !ok {
		return nil, fmt.Errorf("source surfaces must be an array")
	}
	surfaceColumnIndex := map[string]int{}
	for index, column := range envelope.SurfaceColumns {
		surfaceColumnIndex[column] = index
	}
	requiredColumns := compactproofcontract.SurfaceColumns
	projectedSurfaces := make([]any, 0, len(surfaceValues))
	for rowIndex, value := range surfaceValues {
		row, ok := value.([]any)
		if !ok || len(row) != len(envelope.SurfaceColumns) {
			return nil, fmt.Errorf("source surface row #%d must use canonical surface columns", rowIndex+1)
		}
		projected := make([]any, 0, len(requiredColumns))
		for _, column := range requiredColumns {
			index, ok := surfaceColumnIndex[column]
			if !ok {
				return nil, fmt.Errorf("canonical surface columns missing resolver column %s", column)
			}
			projected = append(projected, row[index])
		}
		projectedSurfaces = append(projectedSurfaces, projected)
	}
	return map[string]any{
		"authority_state":       compactproofcontract.AuthorityState,
		"binding_columns":       raw["binding_columns"],
		"bindings":              raw["bindings"],
		"contract_id":           raw["contract_id"],
		"contract_kind":         compactproofcontract.ContractKind,
		"normalization_profile": compactproofcontract.NormalizationProfile,
		"non_claims":            raw["non_claims"],
		"schema_version":        json.Number("1"),
		"surface_columns":       stringSliceToAny(compactproofcontract.SurfaceColumns),
		"surfaces":              projectedSurfaces,
		"witness_columns":       raw["witness_columns"],
	}, nil
}

func combineCanonicalContracts(payloads []map[string]any, envelope Envelope) (map[string]any, error) {
	if len(payloads) == 0 {
		return nil, fmt.Errorf("requirement proof binding source set must define at least one source")
	}
	surfaces := []any{}
	bindings := []any{}
	for _, payload := range payloads {
		surfaceValues, ok := payload["surfaces"].([]any)
		if !ok {
			return nil, fmt.Errorf("source surfaces must be an array")
		}
		bindingValues, ok := payload["bindings"].([]any)
		if !ok {
			return nil, fmt.Errorf("source bindings must be an array")
		}
		surfaces = append(surfaces, surfaceValues...)
		bindings = append(bindings, bindingValues...)
	}
	return admitCanonicalContract(canonicalContract(envelope, surfaces, bindings), envelope, "merged requirement proof binding source set contract")
}

func canonicalContract(envelope Envelope, surfaces any, bindings any) map[string]any {
	return map[string]any{
		"authority_state":       envelope.AuthorityState,
		"binding_columns":       stringSliceToAny(envelope.BindingColumns),
		"bindings":              bindings,
		"contract_id":           envelope.ContractID,
		"contract_kind":         envelope.ContractKind,
		"non_claims":            stringSliceToAny(envelope.NonClaims),
		"normalization_profile": envelope.NormalizationProfile,
		"schema_version":        json.Number("1"),
		"surface_columns":       stringSliceToAny(envelope.SurfaceColumns),
		"surfaces":              surfaces,
		"witness_columns":       stringSliceToAny(envelope.WitnessColumns),
	}
}

func isSourceSetPayload(payload map[string]any) bool {
	return payload["contract_id"] == "requirement-proof-bindings/source-set/v1" || payload["sources"] != nil || payload["source_columns"] != nil
}

func isFragmentPayload(payload map[string]any) bool {
	return payload["contract_id"] == "requirement-proof-bindings/fragment/v1" || payload["contract_id"] == "requirement-proof-bindings/fragment/v2"
}

func parseJSONObject(text string, context string) (map[string]any, error) {
	value, err := admission.DecodeJSON(strings.NewReader(text), int64(len(text)))
	if err != nil {
		return nil, err
	}
	record, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a JSON object", context)
	}
	return record, nil
}

func sha256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func strictText(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", context)
	}
	if value == "" {
		return "", fmt.Errorf("%s must not be blank", context)
	}
	if value != strings.TrimSpace(value) {
		return "", fmt.Errorf("%s must not contain leading or trailing whitespace", context)
	}
	return value, nil
}

func stringArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := strictText(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	return result, nil
}

func sourceIDArray(raw any, context string, allowMissing bool) ([]string, error) {
	if raw == nil && allowMissing {
		return nil, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty array when provided", context)
	}
	result := make([]string, 0, len(values))
	for index, value := range values {
		sourceID, err := admit.RuleID(value, fmt.Sprintf("%s[%d]", context, index))
		if err != nil {
			return nil, err
		}
		result = append(result, sourceID)
	}
	return result, nil
}

func assertExactArray(actual []string, expected []string, context string) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("%s drift", context)
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return fmt.Errorf("%s drift", context)
		}
	}
	return nil
}

func assertUnique(values []string, context string) error {
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return fmt.Errorf("duplicate %s", context)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func project[T any](values []T, fn func(T) string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, fn(value))
	}
	return result
}

func stringSliceToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
