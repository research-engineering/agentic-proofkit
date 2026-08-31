package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	cliContractPath     = "proofkit/cli-contract.v2.json"
	appGeneratedPath    = "internal/app/command_contract_generated.go"
	presetGeneratedPath = "internal/command/stackpreset/preset_ids_generated.go"
	maxContractBytes    = 16 << 20
)

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	testNamePattern = regexp.MustCompile(`^Test[A-Z0-9_][A-Za-z0-9_]*$`)
)

type definitionRecord struct {
	Content    map[string]any
	ID         string
	Digest     string
	References []string
}

type generatedMetadata struct {
	InputContractDigest  string
	InputSummary         []string
	OutputContractDigest string
	FlagChoices          map[string][]string
}

func main() {
	check := flag.Bool("check", false, "verify both generated command-contract projections")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "commandcontractgen accepts only --check")
		os.Exit(1)
	}
	root, err := os.Getwd()
	if err == nil {
		err = run(root, *check)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(root string, check bool) error {
	appContent, presetContent, err := render(root)
	if err != nil {
		return err
	}
	outputs := []struct {
		label   string
		path    string
		content []byte
	}{
		{label: "application", path: appGeneratedPath, content: appContent},
		{label: "preset", path: presetGeneratedPath, content: presetContent},
	}
	for _, output := range outputs {
		path := filepath.Join(root, filepath.FromSlash(output.path))
		if check {
			current, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read generated %s projection: %w", output.label, err)
			}
			if !bytes.Equal(current, output.content) {
				return fmt.Errorf("%s projection is stale; run go run ./internal/tools/commandcontractgen", output.label)
			}
			continue
		}
		if err := writeAtomic(path, output.content); err != nil {
			return fmt.Errorf("write generated %s projection: %w", output.label, err)
		}
	}
	return nil
}

func render(root string) ([]byte, []byte, error) {
	source, contract, err := readContract(filepath.Join(root, filepath.FromSlash(cliContractPath)))
	if err != nil {
		return nil, nil, err
	}
	definitions, err := admitDefinitions(contract)
	if err != nil {
		return nil, nil, err
	}
	metadata, presets, err := admitCommands(root, contract, definitions)
	if err != nil {
		return nil, nil, err
	}
	sourceSum := sha256.Sum256(source)
	appContent, err := renderApp(hex.EncodeToString(sourceSum[:]), metadata)
	if err != nil {
		return nil, nil, err
	}
	presetContent, err := renderPresets(hex.EncodeToString(sourceSum[:]), presets)
	if err != nil {
		return nil, nil, err
	}
	return appContent, presetContent, nil
}

func readContract(path string) ([]byte, map[string]any, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read CLI contract: %w", err)
	}
	if len(content) > maxContractBytes {
		return nil, nil, errors.New("CLI contract exceeds size limit")
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), maxContractBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("admit CLI contract: %w", err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		return nil, nil, errors.New("CLI contract must be an object")
	}
	if number, ok := record["schemaVersion"].(json.Number); !ok || number.String() != "2" {
		return nil, nil, errors.New("CLI contract schemaVersion must be 2")
	}
	if record["contractId"] != "proofkit.cli-contract.v2" {
		return nil, nil, errors.New("CLI contract identity is invalid")
	}
	if err := rejectUnknownKeys(record, []string{"commands", "contractDefinitions", "contractId", "packageName", "processContract", "schemaVersion"}, "CLI contract"); err != nil {
		return nil, nil, err
	}
	return content, record, nil
}

func admitDefinitions(contract map[string]any) (map[string]definitionRecord, error) {
	rawDefinitions, ok := contract["contractDefinitions"].([]any)
	if !ok || len(rawDefinitions) == 0 {
		return nil, errors.New("CLI contract contractDefinitions must be a non-empty array")
	}
	definitions := make(map[string]definitionRecord, len(rawDefinitions))
	previousID := ""
	for index, raw := range rawDefinitions {
		record, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("contract definition %d must be an object", index)
		}
		id, ok := record["definitionId"].(string)
		if !ok || id == "" {
			return nil, fmt.Errorf("contract definition %d has invalid definitionId", index)
		}
		if previousID != "" && previousID >= id {
			return nil, errors.New("CLI contract definitions must be sorted and unique")
		}
		previousID = id
		if _, duplicate := definitions[id]; duplicate {
			return nil, fmt.Errorf("duplicate contract definition id %s", id)
		}
		digest, ok := record["canonicalDigest"].(string)
		if !ok || !digestPattern.MatchString(digest) {
			return nil, fmt.Errorf("contract definition %s has invalid canonicalDigest", id)
		}
		canonicalRecord := cloneRecord(record)
		delete(canonicalRecord, "canonicalDigest")
		encoded, err := canonicalJSON(canonicalRecord)
		if err != nil {
			return nil, fmt.Errorf("canonicalize contract definition %s: %w", id, err)
		}
		if actual := sha256Digest(encoded); actual != digest {
			return nil, fmt.Errorf("contract definition %s canonical digest mismatch: got %s want %s", id, actual, digest)
		}
		references, err := stringList(record["definitionRefs"], "contract definition "+id+" definitionRefs")
		if err != nil {
			return nil, err
		}
		if !sort.StringsAreSorted(references) || hasDuplicate(references) {
			return nil, fmt.Errorf("contract definition %s definitionRefs must be sorted and unique", id)
		}
		if err := admitStructuralDefinition(id, record); err != nil {
			return nil, err
		}
		definitions[id] = definitionRecord{Content: cloneRecord(record), ID: id, Digest: digest, References: references}
	}
	for _, definition := range definitions {
		for _, reference := range definition.References {
			if _, ok := definitions[reference]; !ok {
				return nil, fmt.Errorf("contract definition %s references unknown definition %s", definition.ID, reference)
			}
		}
	}
	return definitions, nil
}

func admitStructuralDefinition(id string, record map[string]any) error {
	if err := rejectUnknownKeys(record, []string{"canonicalDigest", "closed", "definitionId", "definitionRefs", "fieldTree", "rootType", "schemaVersion"}, "contract definition "+id); err != nil {
		return err
	}
	if version, ok := positiveJSONInteger(record["schemaVersion"]); !ok || version < 1 {
		return fmt.Errorf("contract definition %s has invalid schemaVersion", id)
	}
	rootType, ok := record["rootType"].(string)
	if !ok || (rootType != "json_value" && rootType != "object" && rootType != "union") {
		return fmt.Errorf("contract definition %s rootType must be json_value, object, or union", id)
	}
	if record["closed"] != true {
		return fmt.Errorf("contract definition %s must be closed", id)
	}
	references, err := stringList(record["definitionRefs"], "contract definition "+id+" definitionRefs")
	if err != nil {
		return err
	}
	if len(references) != 0 {
		return fmt.Errorf("contract definition %s root-shape-only definitions must not reference nested definitions", id)
	}
	shape, ok := record["fieldTree"].(map[string]any)
	if !ok {
		return fmt.Errorf("contract definition %s is missing fieldTree", id)
	}
	if shape["kind"] != "root_shape_only" {
		return fmt.Errorf("contract definition %s must use root_shape_only", id)
	}
	if err := rejectUnknownKeys(shape, []string{"conditionModel", "kind", "nonClaims", "variants"}, "contract definition "+id+" fieldTree"); err != nil {
		return err
	}
	conditionModel := ""
	if rawConditionModel, present := shape["conditionModel"]; present {
		var ok bool
		conditionModel, ok = rawConditionModel.(string)
		if !ok || conditionModel != "cli_flag_conjunction_v1" {
			return fmt.Errorf("contract definition %s has invalid conditionModel", id)
		}
		if id != cliFlagConditionModelDefinitionID {
			return fmt.Errorf("contract definition %s conditionModel has no admitted native closure owner", id)
		}
	}
	nonClaims, err := stringList(shape["nonClaims"], "contract definition "+id+" fieldTree.nonClaims")
	if err != nil || !slices.Equal(nonClaims, []string{
		"Root-shape definitions do not claim nested field shapes, leaf types, cardinalities, or semantic validity.",
		"Root-shape definitions do not replace direct public-CLI runtime witnesses for variant selection.",
	}) {
		return fmt.Errorf("contract definition %s must declare the exact root-shape non-claims", id)
	}
	rawVariants, ok := shape["variants"].([]any)
	if !ok || len(rawVariants) == 0 {
		return fmt.Errorf("contract definition %s variants must be a non-empty array", id)
	}
	previousID := ""
	rootKinds := map[string]struct{}{}
	conditionOwners := map[string]string{}
	var conditionCases []rootShapeConditionCase
	for index, raw := range rawVariants {
		variant, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("contract definition %s variant %d must be an object", id, index)
		}
		if err := rejectUnknownKeys(variant, []string{"allowedFields", "requiredFields", "rootKind", "variantId", "when"}, "contract definition "+id+" variant"); err != nil {
			return err
		}
		variantID, ok := variant["variantId"].(string)
		if !ok || variantID == "" || (previousID != "" && previousID >= variantID) {
			return fmt.Errorf("contract definition %s variant ids must be non-empty, sorted, and unique", id)
		}
		previousID = variantID
		conditions, err := rootShapeStringList(variant["when"], "contract definition "+id+" variant "+variantID+" when", false)
		if err != nil {
			return err
		}
		for _, condition := range conditions {
			if previousVariant, duplicate := conditionOwners[condition]; duplicate {
				return fmt.Errorf("contract definition %s condition %q is duplicated across variants %s and %s", id, condition, previousVariant, variantID)
			}
			conditionOwners[condition] = variantID
			if conditionModel != "" {
				dimensions, err := parseCLIFlagCondition(condition)
				if err != nil {
					return fmt.Errorf("contract definition %s variant %s condition %q: %w", id, variantID, condition, err)
				}
				conditionCases = append(conditionCases, rootShapeConditionCase{
					Dimensions: dimensions,
					Raw:        condition,
					VariantID:  variantID,
				})
			}
		}
		rootKind, ok := variant["rootKind"].(string)
		if !ok || (rootKind != "array" && rootKind != "json_value" && rootKind != "object") {
			return fmt.Errorf("contract definition %s variant %s has invalid rootKind", id, variantID)
		}
		rootKinds[rootKind] = struct{}{}
		if rootType == "object" && rootKind != "object" {
			return fmt.Errorf("contract definition %s object root cannot declare %s variant %s", id, rootKind, variantID)
		}
		if rootType == "json_value" && rootKind != "json_value" {
			return fmt.Errorf("contract definition %s json_value root cannot declare bounded %s variant %s", id, rootKind, variantID)
		}
		if rootType == "union" && rootKind == "json_value" {
			return fmt.Errorf("contract definition %s union cannot include unconstrained json_value variant %s", id, variantID)
		}
		allowed, err := rootShapeStringList(variant["allowedFields"], "contract definition "+id+" variant "+variantID+" allowedFields", true)
		if err != nil {
			return err
		}
		required, err := rootShapeStringList(variant["requiredFields"], "contract definition "+id+" variant "+variantID+" requiredFields", true)
		if err != nil {
			return err
		}
		if rootKind != "object" && (len(allowed) != 0 || len(required) != 0) {
			return fmt.Errorf("contract definition %s variant %s non-object root must not declare fields", id, variantID)
		}
		allowedSet := make(map[string]struct{}, len(allowed))
		for _, field := range allowed {
			allowedSet[field] = struct{}{}
		}
		for _, field := range required {
			if _, ok := allowedSet[field]; !ok {
				return fmt.Errorf("contract definition %s variant %s required field %s is not allowed", id, variantID, field)
			}
		}
	}
	if conditionModel == "cli_flag_conjunction_v1" {
		if err := admitCLIFlagConditionCases(id, conditionCases); err != nil {
			return err
		}
	}
	if rootType == "json_value" && (len(rawVariants) != 1 || len(rootKinds) != 1) {
		return fmt.Errorf("contract definition %s json_value root must have exactly one unconstrained variant", id)
	}
	if rootType == "union" && len(rootKinds) < 2 {
		return fmt.Errorf("contract definition %s union must enumerate at least two distinct root kinds", id)
	}
	return nil
}

func rootShapeStringList(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := stringList(raw, context)
	if err != nil {
		return nil, err
	}
	if !sort.StringsAreSorted(values) || hasDuplicate(values) {
		return nil, fmt.Errorf("%s must be sorted and unique", context)
	}
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	return values, nil
}

func rejectUnknownKeys(record map[string]any, allowed []string, context string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key := range record {
		if _, ok := allowedSet[key]; !ok {
			return fmt.Errorf("%s has unknown field %s", context, key)
		}
	}
	return nil
}

func positiveJSONInteger(raw any) (int64, bool) {
	number, ok := raw.(json.Number)
	if !ok {
		return 0, false
	}
	value, err := number.Int64()
	return value, err == nil && value > 0
}

func resolveDefinition(id string, definitions map[string]definitionRecord) (map[string]any, error) {
	definition, ok := definitions[id]
	if !ok {
		return nil, fmt.Errorf("unknown definition %s", id)
	}
	resolved := cloneRecord(definition.Content)
	children := make([]any, 0, len(definition.References))
	for _, ref := range definition.References {
		child, err := resolveDefinition(ref, definitions)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	resolved["resolvedDefinitionRefs"] = children
	return resolved, nil
}

func admitCommands(root string, contract map[string]any, definitions map[string]definitionRecord) (map[string]generatedMetadata, []string, error) {
	rawCommands, ok := contract["commands"].([]any)
	if !ok || len(rawCommands) == 0 {
		return nil, nil, errors.New("CLI contract commands must be a non-empty array")
	}
	metadata := make(map[string]generatedMetadata, len(rawCommands))
	contractIDs := map[string]string{}
	activeTestFiles := map[string]map[string]struct{}{}
	var presets []string
	previous := ""
	for index, raw := range rawCommands {
		command, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("CLI command %d must be an object", index)
		}
		name, ok := command["command"].(string)
		if !ok || name == "" {
			return nil, nil, fmt.Errorf("CLI command %d has invalid command", index)
		}
		if previous != "" && previous >= name {
			return nil, nil, errors.New("CLI commands must be sorted and unique")
		}
		previous = name
		item := generatedMetadata{FlagChoices: map[string][]string{}}
		allowedFlags, err := stringList(command["allowedFlags"], "command "+name+" allowedFlags")
		if err != nil || !sort.StringsAreSorted(allowedFlags) || hasDuplicate(allowedFlags) {
			return nil, nil, fmt.Errorf("command %s allowedFlags must be sorted and unique", name)
		}
		inputMode, _ := command["input"].(string)
		inputContract, hasInputContract := command["inputContract"].(map[string]any)
		if inputMode == "required" && !hasInputContract {
			return nil, nil, fmt.Errorf("required-input command %s is missing inputContract", name)
		}
		if hasInputContract {
			if err := admitUniqueContractID(name, "input", inputContract, contractIDs); err != nil {
				return nil, nil, err
			}
			digest, summary, err := admitCommandContract(root, name, "input", inputContract, definitions, activeTestFiles, allowedFlags)
			if err != nil {
				return nil, nil, err
			}
			item.InputContractDigest = digest
			item.InputSummary = summary
		}
		outputModes, err := stringList(command["outputModes"], "command "+name+" outputModes")
		if err != nil {
			return nil, nil, err
		}
		outputContract, hasOutputContract := command["outputContract"].(map[string]any)
		if slices.Contains(outputModes, "json") && !hasOutputContract {
			return nil, nil, fmt.Errorf("JSON-output command %s is missing outputContract", name)
		}
		if hasOutputContract {
			if err := admitUniqueContractID(name, "output", outputContract, contractIDs); err != nil {
				return nil, nil, err
			}
			digest, _, err := admitCommandContract(root, name, "output", outputContract, definitions, activeTestFiles, allowedFlags)
			if err != nil {
				return nil, nil, err
			}
			item.OutputContractDigest = digest
			if rawChoices, ok := outputContract["flagChoices"].(map[string]any); ok {
				flags := make([]string, 0, len(rawChoices))
				for flag := range rawChoices {
					flags = append(flags, flag)
				}
				sort.Strings(flags)
				for _, flag := range flags {
					choices, err := stringList(rawChoices[flag], "command "+name+" flag choices "+flag)
					if err != nil {
						return nil, nil, err
					}
					if len(choices) == 0 || !sort.StringsAreSorted(choices) || hasDuplicate(choices) {
						return nil, nil, fmt.Errorf("command %s flag choices %s must be non-empty, sorted, and unique", name, flag)
					}
					item.FlagChoices[flag] = choices
				}
			}
		}
		if name == "stack-preset" {
			presets = append([]string(nil), item.FlagChoices["--preset"]...)
			if len(presets) == 0 {
				return nil, nil, errors.New("stack-preset outputContract must own non-empty --preset flag choices")
			}
		}
		metadata[name] = item
	}
	return metadata, presets, nil
}

func admitUniqueContractID(command string, direction string, contract map[string]any, seen map[string]string) error {
	id, ok := contract["contractId"].(string)
	if !ok || id == "" {
		return fmt.Errorf("%s %sContract has invalid contractId", command, direction)
	}
	if previous, duplicate := seen[id]; duplicate {
		return fmt.Errorf("duplicate command contract id %s used by %s and %s %sContract", id, previous, command, direction)
	}
	seen[id] = command + " " + direction + "Contract"
	return nil
}

func admitCommandContract(root string, command string, direction string, contract map[string]any, definitions map[string]definitionRecord, activeTestFiles map[string]map[string]struct{}, allowedFlags []string) (string, []string, error) {
	context := command + " " + direction + "Contract"
	contractID, ok := contract["contractId"].(string)
	if !ok || contractID == "" {
		return "", nil, fmt.Errorf("%s has invalid contractId", context)
	}
	if version, ok := positiveJSONInteger(contract["schemaVersion"]); !ok || version < 1 {
		return "", nil, fmt.Errorf("%s has invalid schemaVersion", context)
	}
	if contract["closed"] != true {
		return "", nil, fmt.Errorf("%s must declare a closed root", context)
	}
	ownerRequirements, err := stringList(contract["ownerRequirementRefs"], context+" ownerRequirementRefs")
	if err != nil || len(ownerRequirements) == 0 || !sort.StringsAreSorted(ownerRequirements) || hasDuplicate(ownerRequirements) {
		return "", nil, fmt.Errorf("%s ownerRequirementRefs must be non-empty, sorted, and unique", context)
	}
	definitionID, ok := contract["rootDefinitionRef"].(string)
	if !ok || definitionID == "" {
		return "", nil, fmt.Errorf("%s has invalid rootDefinitionRef", context)
	}
	definition, ok := definitions[definitionID]
	if !ok {
		return "", nil, fmt.Errorf("%s references unknown definition %s", context, definitionID)
	}
	if contract["rootDefinitionDigest"] != definition.Digest {
		return "", nil, fmt.Errorf("%s definition digest mismatch for %s", context, definitionID)
	}
	if contract["rootType"] != definition.Content["rootType"] {
		return "", nil, fmt.Errorf("%s rootType does not match definition %s", context, definitionID)
	}
	if err := admitConditionModelFlags(command, direction, definitionID, definition.Content, allowedFlags); err != nil {
		return "", nil, err
	}
	if err := admitNativeSources(root, context, contract); err != nil {
		return "", nil, err
	}
	selectorKey := "nativeAdmissionWitnessSelector"
	if direction == "output" {
		selectorKey = "nativeOutputWitnessSelector"
	}
	selector, ok := contract[selectorKey].(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("%s is missing %s", context, selectorKey)
	}
	if err := admitSelector(root, context, selector, activeTestFiles); err != nil {
		return "", nil, err
	}
	summary, err := stringList(contract["compatibilitySummary"], context+" compatibilitySummary")
	if err != nil || len(summary) == 0 {
		return "", nil, fmt.Errorf("%s compatibilitySummary must be a non-empty string array", context)
	}
	resolvedDefinition, err := resolveDefinition(definitionID, definitions)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", context, err)
	}
	resolvedRecord := map[string]any{
		"contract":               contract,
		"resolvedRootDefinition": resolvedDefinition,
	}
	encoded, err := canonicalJSON(resolvedRecord)
	if err != nil {
		return "", nil, err
	}
	return sha256Digest(encoded), summary, nil
}

func admitNativeSources(root string, context string, contract map[string]any) error {
	rawSource, hasSource := contract["nativeSource"]
	rawSourcesValue, hasSources := contract["nativeSources"]
	if hasSource == hasSources {
		return fmt.Errorf("%s must declare exactly one of nativeSource or nativeSources", context)
	}
	if hasSource {
		source, ok := rawSource.(map[string]any)
		if !ok {
			return fmt.Errorf("%s nativeSource must be an object", context)
		}
		return admitNativeSource(root, context+" nativeSource", source)
	}
	rawSources, ok := rawSourcesValue.([]any)
	if !ok {
		return fmt.Errorf("%s nativeSources must be an array", context)
	}
	if len(rawSources) == 0 {
		return fmt.Errorf("%s nativeSources must be non-empty", context)
	}
	previousPath := ""
	for index, rawSource := range rawSources {
		itemContext := fmt.Sprintf("%s nativeSources[%d]", context, index)
		source, ok := rawSource.(map[string]any)
		if !ok {
			return fmt.Errorf("%s must be an object", itemContext)
		}
		path, _ := source["path"].(string)
		if previousPath != "" && previousPath >= path {
			return fmt.Errorf("%s nativeSources must be sorted and unique by path", context)
		}
		if err := admitNativeSource(root, itemContext, source); err != nil {
			return err
		}
		previousPath = path
	}
	return nil
}

func admitNativeSource(root string, context string, source map[string]any) error {
	if err := rejectUnknownKeys(source, []string{"canonicalDigest", "evidenceClass", "path"}, context); err != nil {
		return err
	}
	if source["evidenceClass"] != "source_checkout" {
		return fmt.Errorf("%s evidenceClass must be source_checkout", context)
	}
	path, ok := source["path"].(string)
	if !ok || !safeRelativePath(path) {
		return fmt.Errorf("%s path is invalid", context)
	}
	expected, ok := source["canonicalDigest"].(string)
	if !ok || !digestPattern.MatchString(expected) {
		return fmt.Errorf("%s canonicalDigest is invalid", context)
	}
	actual, err := digestSourcePath(root, path)
	if err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	if actual != expected {
		return fmt.Errorf("%s native source digest mismatch: got %s want %s", context, actual, expected)
	}
	return nil
}

func admitSelector(root string, context string, selector map[string]any, activeTestFiles map[string]map[string]struct{}) error {
	if err := rejectUnknownKeys(selector, []string{"command", "evidenceClass", "path", "test"}, context+" selector"); err != nil {
		return err
	}
	if selector["evidenceClass"] != "source_checkout" {
		return fmt.Errorf("%s selector evidenceClass must be source_checkout", context)
	}
	path, ok := selector["path"].(string)
	if !ok || !safeRelativePath(path) || !strings.HasSuffix(path, "_test.go") {
		return fmt.Errorf("%s selector path must identify a tracked _test.go file", context)
	}
	tracked, err := trackedPath(root, path)
	if err != nil {
		return fmt.Errorf("%s selector tracked inventory: %w", context, err)
	}
	if !tracked {
		return fmt.Errorf("%s selector path must identify a Git-index-tracked _test.go file", context)
	}
	info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return fmt.Errorf("%s selector path is unavailable: %w", context, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s selector path must identify a regular non-symlink file", context)
	}
	testName, ok := selector["test"].(string)
	if !ok || !testNamePattern.MatchString(testName) {
		return fmt.Errorf("%s selector test is invalid", context)
	}
	packagePath := "./" + filepath.ToSlash(filepath.Dir(path))
	active, err := activePackageTestFiles(root, packagePath, activeTestFiles)
	if err != nil {
		return fmt.Errorf("%s selector active test inventory: %w", context, err)
	}
	if _, ok := active[path]; !ok {
		return fmt.Errorf("%s selector path is not active in the current Go build", context)
	}
	expectedCommand := "go test " + packagePath + " -run '^" + testName + "$'"
	if selector["command"] != expectedCommand {
		return fmt.Errorf("%s selector command must select exactly %s", context, testName)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, filepath.FromSlash(path)), nil, 0)
	if err != nil {
		return fmt.Errorf("%s parse selector source: %w", context, err)
	}
	testingAliases := map[string]struct{}{}
	dotTesting := false
	for _, imported := range parsed.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil || importPath != "testing" {
			continue
		}
		switch {
		case imported.Name == nil:
			testingAliases["testing"] = struct{}{}
		case imported.Name.Name == ".":
			dotTesting = true
		case imported.Name.Name != "_":
			testingAliases[imported.Name.Name] = struct{}{}
		}
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv != nil || function.Name.Name != testName {
			continue
		}
		if validTestSignature(function, testingAliases, dotTesting) {
			return nil
		}
		return fmt.Errorf("%s test function %s has invalid test signature", context, testName)
	}
	return fmt.Errorf("%s test function %s does not exist", context, testName)
}

func activePackageTestFiles(root string, packagePath string, cache map[string]map[string]struct{}) (map[string]struct{}, error) {
	if files, ok := cache[packagePath]; ok {
		return files, nil
	}
	command := exec.Command("go", "list", "-json", packagePath)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("go list %s failed: %w: %s", packagePath, err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("go list %s failed: %w", packagePath, err)
	}
	var inventory struct {
		Dir          string
		TestGoFiles  []string
		XTestGoFiles []string
	}
	if err := json.Unmarshal(output, &inventory); err != nil {
		return nil, fmt.Errorf("decode go list %s: %w", packagePath, err)
	}
	packageRelative, err := filepath.Rel(root, inventory.Dir)
	packageRelative = filepath.ToSlash(packageRelative)
	if err != nil || (packageRelative != "." && !safeRelativePath(packageRelative)) {
		return nil, fmt.Errorf("go list %s returned an invalid package directory", packagePath)
	}
	if packageRelative == "." {
		packageRelative = ""
	}
	files := map[string]struct{}{}
	for _, name := range append(inventory.TestGoFiles, inventory.XTestGoFiles...) {
		files[filepath.ToSlash(filepath.Join(packageRelative, name))] = struct{}{}
	}
	cache[packagePath] = files
	return files, nil
}

func trackedPath(root string, path string) (bool, error) {
	command := exec.Command("git", "-C", root, "ls-files", "--error-unmatch", "--", path)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("git ls-files failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return true, nil
}

func validTestSignature(function *ast.FuncDecl, testingAliases map[string]struct{}, dotTesting bool) bool {
	if function.Body == nil || function.Type.TypeParams != nil {
		return false
	}
	if function.Type.Results != nil && len(function.Type.Results.List) != 0 {
		return false
	}
	if function.Type.Params == nil || len(function.Type.Params.List) != 1 {
		return false
	}
	parameter := function.Type.Params.List[0]
	if len(parameter.Names) > 1 {
		return false
	}
	pointer, ok := parameter.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	if selector, ok := pointer.X.(*ast.SelectorExpr); ok {
		if selector.Sel.Name != "T" {
			return false
		}
		identifier, ok := selector.X.(*ast.Ident)
		if !ok {
			return false
		}
		_, ok = testingAliases[identifier.Name]
		return ok
	}
	identifier, ok := pointer.X.(*ast.Ident)
	return ok && dotTesting && identifier.Name == "T"
}

func digestSourcePath(root string, relative string) (string, error) {
	absolute := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Stat(absolute)
	if err != nil {
		return "", err
	}
	paths := []string{}
	if info.IsDir() {
		err = filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") && !strings.HasSuffix(entry.Name(), "_generated.go") {
				relativePath, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				paths = append(paths, filepath.ToSlash(relativePath))
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	} else {
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return "", errors.New("native source contains no admitted Go files")
	}
	hash := sha256.New()
	for _, path := range paths {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return "", err
		}
		hash.Write([]byte(path))
		hash.Write([]byte{0})
		hash.Write(content)
		hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func renderApp(sourceDigest string, metadata map[string]generatedMetadata) ([]byte, error) {
	var output strings.Builder
	output.WriteString("// Code generated by internal/tools/commandcontractgen; DO NOT EDIT.\n")
	output.WriteString("package app\n\n")
	fmt.Fprintf(&output, "const commandContractSourceSHA256 = %q\n\n", sourceDigest)
	output.WriteString("type generatedCommandContractMetadata struct {\n")
	output.WriteString("\tInputContractSHA256 string\n\tInputSchemaSummary []string\n\tOutputContractSHA256 string\n\tFlagChoices map[string][]string\n}\n\n")
	output.WriteString("var generatedCommandContractMetadataByName = map[string]generatedCommandContractMetadata{\n")
	for _, name := range sortedKeys(metadata) {
		item := metadata[name]
		fmt.Fprintf(&output, "\t%q: {InputContractSHA256: %q, InputSchemaSummary: %#v, OutputContractSHA256: %q, FlagChoices: %#v},\n",
			name, item.InputContractDigest, item.InputSummary, item.OutputContractDigest, item.FlagChoices)
	}
	output.WriteString("}\n")
	formatted, err := format.Source([]byte(output.String()))
	if err != nil {
		return nil, fmt.Errorf("format application command-contract projection: %w", err)
	}
	return formatted, nil
}

func renderPresets(sourceDigest string, presets []string) ([]byte, error) {
	var output strings.Builder
	output.WriteString("// Code generated by internal/tools/commandcontractgen; DO NOT EDIT.\n")
	output.WriteString("package stackpreset\n\n")
	fmt.Fprintf(&output, "const presetContractSourceSHA256 = %q\n\n", sourceDigest)
	fmt.Fprintf(&output, "var presetIDs = %#v\n", presets)
	formatted, err := format.Source([]byte(output.String()))
	if err != nil {
		return nil, fmt.Errorf("format preset command-contract projection: %w", err)
	}
	return formatted, nil
}

func canonicalJSON(value any) ([]byte, error) {
	encoded, err := stablejson.MarshalLayout(value, stablejson.LayoutCompact)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded, []byte{'\n'}), nil
}

func sha256Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func stringList(raw any, context string) ([]string, error) {
	if raw == nil {
		return []string{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	for index, value := range values {
		text, ok := value.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("%s item %d must be non-empty text", context, index)
		}
		result = append(result, text)
	}
	return result, nil
}

func safeRelativePath(path string) bool {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, `\`) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	return clean == path && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func cloneRecord(record map[string]any) map[string]any {
	out := make(map[string]any, len(record))
	for key, value := range record {
		out[key] = value
	}
	return out
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func hasDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return true
		}
	}
	return false
}

func writeAtomic(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".command-contract-*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(0o644); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
