package requirementsourcecodec

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

type shapeKind uint8

const (
	shapeObject shapeKind = iota + 1
	shapeArray
	shapeString
	shapeInteger
	shapeBoolean
)

type shapeField struct {
	shape    *shape
	required bool
}

type shape struct {
	kind        shapeKind
	fields      map[string]shapeField
	dynamic     *shape
	element     *shape
	nullable    bool
	maxItems    int
	exactString string
	exactInt    *int64
}

func documentShape(limits requirementsourcemodel.Limits) *shape {
	stringValue := scalar(shapeString)
	booleanValue := scalar(shapeBoolean)
	integerValue := scalar(shapeInteger)
	stringsValue := array(stringValue, limits.MaxCollectionItems)
	lifecycleValue := object(requiredFields(map[string]*shape{
		"state": stringValue, "replacementRequirementIds": stringsValue, "evidenceRefs": stringsValue,
	}))
	deferralValue := object(requiredFields(map[string]*shape{
		"ownerId": stringValue, "riskAcceptedBy": stringValue, "reviewCondition": stringValue,
		"expiryRef": stringValue, "mergePolicy": stringValue, "evidenceRefs": stringsValue,
	}))
	deferralValue.nullable = true
	updatePolicyValue := object(requiredFields(map[string]*shape{
		"reviewOwnerId": stringValue, "requiresImpactDeclaration": booleanValue, "requiresProofBindingReview": booleanValue,
	}))
	metadataValue := object(map[string]shapeField{
		"ownerId": {shape: stringValue}, "claimLevel": {shape: stringValue}, "riskClass": {shape: stringValue},
		"nonClaimRefs": {shape: stringsValue}, "lifecycle": {shape: lifecycleValue}, "deferral": {shape: deferralValue}, "updatePolicy": {shape: updatePolicyValue},
	})
	nonClaimValue := object(requiredFields(map[string]*shape{"nonClaimId": stringValue, "statement": stringValue}))
	termValue := object(requiredFields(map[string]*shape{"termId": stringValue, "kind": stringValue, "label": stringValue, "definition": stringValue}))
	gitRefValue := object(requiredFields(map[string]*shape{"objectFormat": stringValue, "commitOid": stringValue, "path": stringValue, "sha256": stringValue}))
	rangeValue := object(requiredFields(map[string]*shape{"start": integerValue, "end": integerValue}))
	derivationValue := object(requiredFields(map[string]*shape{
		"derivationId": stringValue, "sourceKind": stringValue, "sourceRef": gitRefValue, "selector": rangeValue,
		"requirementIds": stringsValue, "nonClaimRefs": stringsValue,
	}))
	profileValue := object(requiredFields(map[string]*shape{"profileId": stringValue, "fields": metadataValue}))
	memberValue := object(requiredFields(map[string]*shape{"requirementId": stringValue, "statementCompletion": stringValue, "fields": metadataValue}))
	groupValue := object(requiredFields(map[string]*shape{
		"groupId": stringValue, "profileId": stringValue, "statementStem": stringValue, "sharedPremises": stringsValue,
		"members": array(memberValue, limits.MaxMembersPerGroup),
	}))
	valuesValue := &shape{kind: shapeObject, dynamic: stringValue, maxItems: limits.MaxCollectionItems}
	exampleValue := object(requiredFields(map[string]*shape{"exampleId": stringValue, "values": valuesValue}))
	scenarioValue := object(requiredFields(map[string]*shape{
		"scenarioId": stringValue, "requirementIds": stringsValue, "parameters": stringsValue,
		"preconditions": stringsValue, "actionSequence": stringsValue, "expectedObservations": stringsValue,
		"forbiddenObservations": stringsValue, "examples": array(exampleValue, limits.MaxExamplesPerScenario),
		"vocabularyRefs": stringsValue, "nonClaimRefs": stringsValue,
	}))
	version := int64(SchemaVersion)
	versionShape := scalar(shapeInteger)
	versionShape.exactInt = &version
	kindShape := scalar(shapeString)
	kindShape.exactString = DocumentKind
	return object(requiredFields(map[string]*shape{
		"schemaVersion":       versionShape,
		"kind":                kindShape,
		"sourceId":            stringValue,
		"specPackagePath":     stringValue,
		"sourceNonClaimRefs":  stringsValue,
		"nonClaimDefinitions": array(nonClaimValue, limits.MaxDefinitions),
		"vocabulary":          array(termValue, limits.MaxTerms),
		"derivations":         array(derivationValue, limits.MaxDerivations),
		"profiles":            array(profileValue, limits.MaxProfiles),
		"groups":              array(groupValue, limits.MaxGroups),
		"scenarios":           array(scenarioValue, limits.MaxScenarios),
	}))
}

func validateShape(value any, expected *shape, path string, locations map[string]rawLocation, source []byte) error {
	if value == nil {
		if expected.nullable {
			return nil
		}
		return shapeError(source, locations, "invalid_null", path)
	}
	switch expected.kind {
	case shapeObject:
		record, ok := value.(map[string]any)
		if !ok {
			return shapeError(source, locations, "invalid_type", path)
		}
		if expected.maxItems > 0 && len(record) > expected.maxItems {
			return shapeError(source, locations, "collection_limit_exceeded", path)
		}
		if expected.dynamic != nil {
			for _, key := range orderedRecordKeys(record, path, locations) {
				childPath := joinPointer(path, key)
				if _, ok := record[key].(string); !ok {
					return shapeErrorAt(source, locations, "invalid_type", joinPointer(path, "<entry>"), childPath)
				}
			}
			return nil
		}
		for _, key := range orderedRecordKeys(record, path, locations) {
			field, exists := expected.fields[key]
			if !exists {
				for canonical := range expected.fields {
					if strings.EqualFold(key, canonical) {
						return shapeErrorAt(source, locations, "noncanonical_field", joinPointer(path, canonical), joinPointer(path, key))
					}
				}
				return shapeErrorAt(source, locations, "unknown_field", joinPointer(path, "<unknown>"), joinPointer(path, key))
			}
			if err := validateShape(record[key], field.shape, joinPointer(path, key), locations, source); err != nil {
				return err
			}
		}
		for _, key := range sortedShapeFieldKeys(expected.fields) {
			field := expected.fields[key]
			if field.required {
				if _, exists := record[key]; !exists {
					return shapeError(source, locations, "missing_field", joinPointer(path, key))
				}
			}
		}
	case shapeArray:
		values, ok := value.([]any)
		if !ok {
			return shapeError(source, locations, "invalid_type", path)
		}
		if len(values) > expected.maxItems {
			return shapeError(source, locations, "collection_limit_exceeded", path)
		}
		for index, child := range values {
			if err := validateShape(child, expected.element, joinPointer(path, strconv.Itoa(index)), locations, source); err != nil {
				return err
			}
		}
	case shapeString:
		text, ok := value.(string)
		if !ok {
			return shapeError(source, locations, "invalid_type", path)
		}
		if expected.exactString != "" && text != expected.exactString {
			return shapeError(source, locations, "invalid_identity", path)
		}
	case shapeInteger:
		number, ok := value.(json.Number)
		if !ok {
			return shapeError(source, locations, "invalid_type", path)
		}
		integer, err := strconv.ParseInt(string(number), 10, 64)
		if err != nil || strconv.FormatInt(integer, 10) != string(number) {
			return shapeError(source, locations, "invalid_integer", path)
		}
		if expected.exactInt != nil && integer != *expected.exactInt {
			return shapeError(source, locations, "invalid_identity", path)
		}
	case shapeBoolean:
		if _, ok := value.(bool); !ok {
			return shapeError(source, locations, "invalid_type", path)
		}
	default:
		return shapeError(source, locations, "invalid_shape", path)
	}
	return nil
}

func shapeError(source []byte, locations map[string]rawLocation, code string, path string) error {
	return shapeErrorAt(source, locations, code, path, path)
}

func shapeErrorAt(source []byte, locations map[string]rawLocation, code string, path string, locationPath string) error {
	location, exists := locations[locationPath]
	if !exists {
		parent := locationPath
		for parent != "" {
			index := strings.LastIndex(parent, "/")
			if index < 0 {
				break
			}
			parent = parent[:index]
			if location, exists = locations[parent]; exists {
				break
			}
		}
	}
	span := location.value
	if location.key != nil && (code == "unknown_field" || code == "noncanonical_field") {
		span = *location.key
	}
	return diagnosticError(source, code, path, span, true)
}

func orderedRecordKeys(record map[string]any, path string, locations map[string]rawLocation) []string {
	keys := make([]string, 0, len(record))
	for key := range record {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		leftLocation, leftExists := locations[joinPointer(path, keys[left])]
		rightLocation, rightExists := locations[joinPointer(path, keys[right])]
		if leftExists != rightExists {
			return leftExists
		}
		if leftExists && leftLocation.key != nil && rightLocation.key != nil && leftLocation.key.Start != rightLocation.key.Start {
			return leftLocation.key.Start < rightLocation.key.Start
		}
		return keys[left] < keys[right]
	})
	return keys
}

func sortedShapeFieldKeys(fields map[string]shapeField) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func requiredFields(values map[string]*shape) map[string]shapeField {
	result := make(map[string]shapeField, len(values))
	for key, value := range values {
		result[key] = shapeField{shape: value, required: true}
	}
	return result
}

func object(fields map[string]shapeField) *shape {
	return &shape{kind: shapeObject, fields: fields}
}

func array(element *shape, maxItems int) *shape {
	return &shape{kind: shapeArray, element: element, maxItems: maxItems}
}

func scalar(kind shapeKind) *shape {
	return &shape{kind: kind}
}
