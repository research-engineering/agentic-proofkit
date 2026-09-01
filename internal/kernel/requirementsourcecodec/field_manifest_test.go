package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

type codecFieldManifest struct {
	SchemaVersion int              `json:"schemaVersion"`
	Kind          string           `json:"kind"`
	RootRecordID  string           `json:"rootRecordId"`
	Records       []manifestRecord `json:"records"`
}

type manifestRecord struct {
	RecordID string          `json:"recordId"`
	Fields   []manifestField `json:"fields"`
}

type manifestField struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Nullable bool   `json:"nullable"`
	Constant string `json:"constant,omitempty"`
}

func TestFieldManifestMatchesWireDTOAndClosedShape(t *testing.T) {
	manifest := readCodecFieldManifest(t)
	if manifest.SchemaVersion != 1 || manifest.Kind != "proofkit.requirement-source-codec-field-manifest" || manifest.RootRecordID != "document" {
		t.Fatalf("manifest identity = %#v", manifest)
	}
	actual := wireRecordManifest(t)
	if !reflect.DeepEqual(manifest.Records, actual) {
		t.Fatalf("manifest records do not match wire DTO\nmanifest: %#v\nwire: %#v", manifest.Records, actual)
	}
	byID := make(map[string]manifestRecord, len(manifest.Records))
	for _, record := range manifest.Records {
		byID[record.RecordID] = record
	}
	seen := map[string]struct{}{}
	assertShapeRecord(t, manifest.RootRecordID, documentShape(requirementsourcemodel.DefaultLimits()), byID, seen)
	if len(seen) != len(byID) {
		t.Fatalf("shape reached %d/%d manifest records", len(seen), len(byID))
	}
}

func readCodecFieldManifest(t *testing.T) codecFieldManifest {
	t.Helper()
	payload, err := os.ReadFile("testdata/codec-field-manifest.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := admission.DecodeTypedJSON[codecFieldManifest](bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var strict codecFieldManifest
	if err := decoder.Decode(&strict); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func wireRecordManifest(t *testing.T) []manifestRecord {
	t.Helper()
	recordTypes := []reflect.Type{
		reflect.TypeOf(byteRange{}), reflect.TypeOf(deferral{}), reflect.TypeOf(derivation{}),
		reflect.TypeOf(document{}), reflect.TypeOf(example{}), reflect.TypeOf(gitBlobRef{}),
		reflect.TypeOf(group{}), reflect.TypeOf(lifecycle{}), reflect.TypeOf(member{}),
		reflect.TypeOf(metadataFields{}), reflect.TypeOf(nonClaimDefinition{}), reflect.TypeOf(profile{}),
		reflect.TypeOf(scenario{}), reflect.TypeOf(updatePolicy{}), reflect.TypeOf(vocabularyTerm{}),
	}
	records := make([]manifestRecord, len(recordTypes))
	for recordIndex, recordType := range recordTypes {
		fields := make([]manifestField, 0, recordType.NumField())
		for fieldIndex := 0; fieldIndex < recordType.NumField(); fieldIndex++ {
			field := recordType.Field(fieldIndex)
			name, options := parseJSONTag(field.Tag.Get("json"))
			if name == "" || name == "-" {
				t.Fatalf("%s.%s has invalid JSON tag", recordType.Name(), field.Name)
			}
			fieldType, nullable := manifestType(field.Type, recordType.Name(), name)
			item := manifestField{Name: name, Type: fieldType, Required: !options["omitempty"], Nullable: nullable}
			if recordType == reflect.TypeOf(document{}) && name == "schemaVersion" {
				item.Constant = "2"
			}
			if recordType == reflect.TypeOf(document{}) && name == "kind" {
				item.Constant = DocumentKind
			}
			fields = append(fields, item)
		}
		records[recordIndex] = manifestRecord{RecordID: recordType.Name(), Fields: fields}
	}
	sort.Slice(records, func(left, right int) bool { return records[left].RecordID < records[right].RecordID })
	return records
}

func manifestType(value reflect.Type, recordID string, fieldName string) (string, bool) {
	if value == rawMessageType && recordID == "metadataFields" && fieldName == "deferral" {
		return "record:deferral", true
	}
	for value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.String:
		return "string", false
	case reflect.Bool:
		return "boolean", false
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "integer", false
	case reflect.Slice:
		child, _ := manifestType(value.Elem(), recordID, fieldName)
		return "array:" + child, false
	case reflect.Map:
		if value.Key().Kind() == reflect.String && value.Elem().Kind() == reflect.String {
			return "map:string", false
		}
	case reflect.Struct:
		return "record:" + value.Name(), false
	}
	return "unsupported:" + value.String(), false
}

func assertShapeRecord(t *testing.T, recordID string, actual *shape, records map[string]manifestRecord, seen map[string]struct{}) {
	t.Helper()
	if _, exists := seen[recordID]; exists {
		return
	}
	record, exists := records[recordID]
	if !exists {
		t.Fatalf("shape references unclassified record %q", recordID)
	}
	seen[recordID] = struct{}{}
	if actual.kind != shapeObject || actual.dynamic != nil || len(actual.fields) != len(record.Fields) {
		t.Fatalf("shape for %s is not an exact closed record", recordID)
	}
	for _, field := range record.Fields {
		shapeField, exists := actual.fields[field.Name]
		if !exists || shapeField.required != field.Required || shapeField.shape.nullable != field.Nullable {
			t.Fatalf("shape field %s.%s mismatch", recordID, field.Name)
		}
		assertShapeType(t, field.Type, shapeField.shape, records, seen)
		if field.Constant != "" {
			switch shapeField.shape.kind {
			case shapeString:
				if shapeField.shape.exactString != field.Constant {
					t.Fatalf("shape constant %s.%s mismatch", recordID, field.Name)
				}
			case shapeInteger:
				if shapeField.shape.exactInt == nil || field.Constant != "2" || *shapeField.shape.exactInt != SchemaVersion {
					t.Fatalf("shape constant %s.%s mismatch", recordID, field.Name)
				}
			default:
				t.Fatalf("unsupported constant type at %s.%s", recordID, field.Name)
			}
		}
	}
}

func assertShapeType(t *testing.T, expected string, actual *shape, records map[string]manifestRecord, seen map[string]struct{}) {
	t.Helper()
	switch {
	case expected == "string" && actual.kind == shapeString:
		return
	case expected == "boolean" && actual.kind == shapeBoolean:
		return
	case expected == "integer" && actual.kind == shapeInteger:
		return
	case expected == "map:string" && actual.kind == shapeObject && actual.dynamic != nil && actual.dynamic.kind == shapeString:
		return
	case strings.HasPrefix(expected, "array:") && actual.kind == shapeArray:
		assertShapeType(t, strings.TrimPrefix(expected, "array:"), actual.element, records, seen)
		return
	case strings.HasPrefix(expected, "record:") && actual.kind == shapeObject:
		assertShapeRecord(t, strings.TrimPrefix(expected, "record:"), actual, records, seen)
		return
	default:
		t.Fatalf("shape type mismatch: expected %s, actual kind %d", expected, actual.kind)
	}
}
