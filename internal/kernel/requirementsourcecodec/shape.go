package requirementsourcecodec

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

type shapeKind uint8

type collectionLimitID string

const (
	shapeObject shapeKind = iota + 1
	shapeArray
	shapeString
	shapeInteger
	shapeBoolean
	shapeDecimalInteger
)

const (
	limitCollectionItems     collectionLimitID = "max_collection_items"
	limitDefinitions         collectionLimitID = "max_definitions"
	limitDerivations         collectionLimitID = "max_derivations"
	limitExamplesPerScenario collectionLimitID = "max_examples_per_scenario"
	limitGroups              collectionLimitID = "max_groups"
	limitMembersPerGroup     collectionLimitID = "max_members_per_group"
	limitProfiles            collectionLimitID = "max_profiles"
	limitScenarios           collectionLimitID = "max_scenarios"
	limitTerms               collectionLimitID = "max_terms"
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
	limitOwner  collectionLimitID
	exactString string
	exactInt    *int64
}

func documentShape(limits requirementsourcemodel.Limits) *shape {
	stringValue := scalar(shapeString)
	booleanValue := scalar(shapeBoolean)
	coordinateValue := scalar(shapeDecimalInteger)
	stringsValue := array(stringValue, limitCollectionItems, limits)
	lifecycleValue := object(map[string]shapeField{
		"state":                     {shape: stringValue, required: true},
		"replacementRequirementIds": {shape: stringsValue}, "evidenceRefs": {shape: stringsValue},
	})
	deferralValue := object(requiredFields(map[string]*shape{
		"ownerId": stringValue, "riskAcceptedBy": stringValue, "reviewCondition": stringValue,
		"expiryRef": stringValue, "mergePolicy": stringValue, "evidenceRefs": stringsValue,
	}))
	deferralValue.nullable = true
	updatePolicyValue := object(map[string]shapeField{
		"reviewOwnerId": {shape: stringValue, required: true}, "requiresImpactDeclaration": {shape: booleanValue},
		"requiresProofBindingReview": {shape: booleanValue},
	})
	metadataValue := object(map[string]shapeField{
		"ownerId": {shape: stringValue}, "claimLevel": {shape: stringValue}, "riskClass": {shape: stringValue},
		"nonClaimRefs": {shape: stringsValue}, "lifecycle": {shape: lifecycleValue}, "deferral": {shape: deferralValue}, "updatePolicy": {shape: updatePolicyValue},
		"nonClaims": {shape: stringsValue}, "externalNonClaimRefs": {shape: stringsValue}, "proofBindingRefs": {shape: stringsValue},
	})
	nonClaimValue := object(requiredFields(map[string]*shape{"nonClaimId": stringValue, "statement": stringValue}))
	termValue := object(requiredFields(map[string]*shape{"termId": stringValue, "kind": stringValue, "label": stringValue, "definition": stringValue}))
	gitRefValue := object(requiredFields(map[string]*shape{"objectFormat": stringValue, "commitOid": stringValue, "path": stringValue, "sha256": stringValue}))
	rangeValue := object(requiredFields(map[string]*shape{"start": coordinateValue, "end": coordinateValue}))
	derivationValue := object(requiredFields(map[string]*shape{
		"derivationId": stringValue, "sourceKind": stringValue, "sourceRef": gitRefValue, "selector": rangeValue,
		"requirementIds": stringsValue, "nonClaimRefs": stringsValue,
	}))
	profileValue := object(requiredFields(map[string]*shape{"profileId": stringValue, "fields": metadataValue}))
	memberValue := object(requiredFields(map[string]*shape{"requirementId": stringValue, "statementCompletion": stringValue, "fields": metadataValue}))
	groupValue := object(requiredFields(map[string]*shape{
		"groupId": stringValue, "profileId": stringValue, "statementStem": stringValue, "sharedPremises": stringsValue,
		"members": array(memberValue, limitMembersPerGroup, limits),
	}))
	valuesValue := dynamicMap(stringValue, limitCollectionItems, limits)
	exampleValue := object(requiredFields(map[string]*shape{"exampleId": stringValue, "values": valuesValue}))
	scenarioValue := object(requiredFields(map[string]*shape{
		"scenarioId": stringValue, "requirementIds": stringsValue, "parameters": stringsValue,
		"preconditions": stringsValue, "actionSequence": stringsValue, "expectedObservations": stringsValue,
		"forbiddenObservations": stringsValue, "examples": array(exampleValue, limitExamplesPerScenario, limits),
		"vocabularyRefs": stringsValue, "nonClaimRefs": stringsValue,
	}))
	version := int64(SchemaVersion)
	versionShape := scalar(shapeInteger)
	versionShape.exactInt = &version
	kindShape := scalar(shapeString)
	kindShape.exactString = DocumentKind
	return object(map[string]shapeField{
		"schemaVersion":       {shape: versionShape, required: true},
		"kind":                {shape: kindShape, required: true},
		"sourceId":            {shape: stringValue, required: true},
		"specPackagePath":     {shape: stringValue, required: true},
		"sourceNonClaimRefs":  {shape: stringsValue},
		"sourceNonClaims":     {shape: stringsValue, required: true},
		"nonClaimDefinitions": {shape: array(nonClaimValue, limitDefinitions, limits)},
		"vocabulary":          {shape: array(termValue, limitTerms, limits)},
		"derivations":         {shape: array(derivationValue, limitDerivations, limits)},
		"profiles":            {shape: array(profileValue, limitProfiles, limits)},
		"groups":              {shape: array(groupValue, limitGroups, limits), required: true},
		"scenarios":           {shape: array(scenarioValue, limitScenarios, limits)},
	})
}

// validateShape reports every independent shape fault in source order. A
// faulty node is not descended into, so one fault never implies another.
func validateShape(value any, expected *shape, path string, locations map[string]rawLocation, source []byte) error {
	var problems diagnosticCollector
	collectShapeFaults(value, expected, path, locations, &problems)
	return problems.locatedErr(source)
}

func collectShapeFaults(value any, expected *shape, path string, locations map[string]rawLocation, problems *diagnosticCollector) {
	if code := shapeNodeFault(value, expected, path, locations, problems); code != "" {
		addShapeFault(problems, locations, code, path, path)
	}
}

// shapeNodeFault returns the code of a fault at the node itself; faults in
// its children are added to problems directly.
func shapeNodeFault(value any, expected *shape, path string, locations map[string]rawLocation, problems *diagnosticCollector) string {
	if value == nil {
		if expected.nullable {
			return ""
		}
		return "invalid_null"
	}
	switch expected.kind {
	case shapeObject:
		record, ok := value.(map[string]any)
		if !ok {
			return "invalid_type"
		}
		if expected.maxItems > 0 && len(record) > expected.maxItems {
			return "collection_limit_exceeded"
		}
		if expected.dynamic != nil {
			for _, key := range orderedRecordKeys(record, path, locations) {
				childPath := joinPointer(path, key)
				if _, ok := record[key].(string); !ok {
					addShapeFault(problems, locations, "invalid_type", joinPointer(path, "<entry>"), childPath)
				}
			}
			return ""
		}
		// A case-folded spelling already reports its canonical field.
		misspelled := map[string]struct{}{}
		for _, key := range orderedRecordKeys(record, path, locations) {
			field, exists := expected.fields[key]
			if !exists {
				if canonical := addUnexpectedFieldFault(problems, expected, path, key, locations); canonical != "" {
					misspelled[canonical] = struct{}{}
				}
				continue
			}
			collectShapeFaults(record[key], field.shape, joinPointer(path, key), locations, problems)
		}
		for _, key := range sortedShapeFieldKeys(expected.fields) {
			field := expected.fields[key]
			if field.required {
				_, exists := record[key]
				_, reported := misspelled[key]
				if !exists && !reported {
					addShapeFault(problems, locations, "missing_field", joinPointer(path, key), joinPointer(path, key))
				}
			}
		}
	case shapeArray:
		values, ok := value.([]any)
		if !ok {
			return "invalid_type"
		}
		if len(values) > expected.maxItems {
			return "collection_limit_exceeded"
		}
		for index, child := range values {
			collectShapeFaults(child, expected.element, joinPointer(path, strconv.Itoa(index)), locations, problems)
		}
	case shapeString:
		text, ok := value.(string)
		if !ok {
			return "invalid_type"
		}
		if expected.exactString != "" && text != expected.exactString {
			return "invalid_identity"
		}
	case shapeInteger:
		number, ok := value.(json.Number)
		if !ok {
			return "invalid_type"
		}
		integer, canonical := parseCanonicalInt64(string(number))
		if !canonical {
			return "invalid_integer"
		}
		if expected.exactInt != nil && integer != *expected.exactInt {
			return "invalid_identity"
		}
	case shapeDecimalInteger:
		text, ok := value.(string)
		if !ok {
			return "invalid_type"
		}
		if _, canonical := parseCanonicalInt64(text); !canonical {
			return "invalid_integer"
		}
	case shapeBoolean:
		if _, ok := value.(bool); !ok {
			return "invalid_type"
		}
	default:
		return "invalid_shape"
	}
	return ""
}

// addUnexpectedFieldFault returns the canonical field a case-folded key spells.
func addUnexpectedFieldFault(problems *diagnosticCollector, expected *shape, path string, key string, locations map[string]rawLocation) string {
	for canonical := range expected.fields {
		if strings.EqualFold(key, canonical) {
			addShapeFault(problems, locations, "noncanonical_field", joinPointer(path, canonical), joinPointer(path, key))
			return canonical
		}
	}
	addShapeFault(problems, locations, "unknown_field", joinPointer(path, "<unknown>"), joinPointer(path, key))
	return ""
}

// addShapeFault locates a fault at locationPath, or at its nearest located
// ancestor, and reports it under path.
func addShapeFault(problems *diagnosticCollector, locations map[string]rawLocation, code string, path string, locationPath string) {
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
	problems.addLocated(code, path, span)
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

func array(element *shape, owner collectionLimitID, limits requirementsourcemodel.Limits) *shape {
	return &shape{kind: shapeArray, element: element, maxItems: collectionLimit(owner, limits), limitOwner: owner}
}

func dynamicMap(element *shape, owner collectionLimitID, limits requirementsourcemodel.Limits) *shape {
	return &shape{kind: shapeObject, dynamic: element, maxItems: collectionLimit(owner, limits), limitOwner: owner}
}

func collectionLimit(owner collectionLimitID, limits requirementsourcemodel.Limits) int {
	switch owner {
	case limitCollectionItems:
		return limits.MaxCollectionItems
	case limitDefinitions:
		return limits.MaxDefinitions
	case limitDerivations:
		return limits.MaxDerivations
	case limitExamplesPerScenario:
		return limits.MaxExamplesPerScenario
	case limitGroups:
		return limits.MaxGroups
	case limitMembersPerGroup:
		return limits.MaxMembersPerGroup
	case limitProfiles:
		return limits.MaxProfiles
	case limitScenarios:
		return limits.MaxScenarios
	case limitTerms:
		return limits.MaxTerms
	default:
		panic("unknown collection limit owner")
	}
}

func scalar(kind shapeKind) *shape {
	return &shape{kind: kind}
}
