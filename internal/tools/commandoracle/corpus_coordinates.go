package commandoracle

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func schemaCoordinates(target reflect.Type, prefix string) []string {
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	coordinates := []string{}
	switch target.Kind() {
	case reflect.Struct:
		for index := 0; index < target.NumField(); index++ {
			field := target.Field(index)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			coordinates = append(coordinates, schemaCoordinates(field.Type, prefix+"."+name)...)
		}
	case reflect.Slice, reflect.Array:
		element := target.Elem()
		for element.Kind() == reflect.Pointer {
			element = element.Elem()
		}
		if element.Kind() == reflect.Struct {
			coordinates = append(coordinates, schemaCoordinates(element, prefix+"[]")...)
		} else {
			coordinates = append(coordinates, prefix+"[]")
		}
	default:
		coordinates = append(coordinates, prefix)
	}
	sort.Strings(coordinates)
	return coordinates
}

func syntheticRecordValue() (map[string]any, error) {
	candidates := syntheticCandidates()
	candidateDigest, err := CandidateSetDigest(candidates)
	if err != nil {
		return nil, err
	}
	imports := map[string]string{"./internal/sample": "example.test/proofkit/internal/sample"}
	entries := make([]JoinedEntry, 0, len(candidates))
	for _, candidate := range candidates {
		entries = append(entries, JoinedEntry{
			Candidate:         candidate,
			ExecutionState:    "passed",
			PackageImportPath: imports[candidate.PackagePath],
		})
	}
	record := Record{
		ArtifactKind:            ArtifactKind,
		CandidateSetDigest:      candidateDigest,
		CommandID:               CommandID,
		CounterfeitCorpusDigest: strings.Repeat("2", 64),
		Entries:                 entries,
		ExecutionCommands:       executionCommands(candidates),
		GoVersion:               "go1.27.1",
		NonClaims:               RecordNonClaims(),
		Platform:                "darwin/arm64",
		SchemaVersion:           SchemaVersion,
		SourceRevision:          strings.Repeat("a", 40),
		SourceSnapshotDigest:    strings.Repeat("3", 64),
		State:                   "passed",
	}
	if err := validateRecordShape(record); err != nil {
		return nil, err
	}
	return recordValue(record), nil
}

func mutateCoordinate(root map[string]any, coordinate string) bool {
	parts := strings.Split(coordinate, ".")
	var current any = root
	for index, part := range parts {
		isArray := strings.HasSuffix(part, "[]")
		key := strings.TrimSuffix(part, "[]")
		record, ok := current.(map[string]any)
		if !ok {
			return false
		}
		value, ok := record[key]
		if !ok {
			return false
		}
		if isArray {
			values, ok := value.([]any)
			if !ok || len(values) == 0 {
				return false
			}
			if index == len(parts)-1 {
				values[0] = counterfeitScalar(values[0])
				return true
			}
			current = values[0]
			continue
		}
		if index == len(parts)-1 {
			record[key] = counterfeitScalar(value)
			return true
		}
		current = value
	}
	return false
}

func counterfeitScalar(value any) any {
	switch typed := value.(type) {
	case string:
		return ""
	case json.Number:
		return json.Number("0")
	case bool:
		return !typed
	default:
		return nil
	}
}

func admitMutatedRecord(value map[string]any) string {
	content, err := stableRecordBytes(value)
	if err != nil {
		return "internal_error"
	}
	_, err = admitRecordBytes(content)
	return decisionOrAdmit(err)
}

func stableRecordBytes(value map[string]any) ([]byte, error) {
	return stablejson.Marshal(value)
}
