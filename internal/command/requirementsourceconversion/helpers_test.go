package requirementsourceconversion

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const fixtureBytesLimit = 32 << 20

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// fixture decodes a fresh caller-owned value; mutations never leak between cases.
func fixture(t *testing.T, name string) map[string]any {
	t.Helper()
	return decode(t, fixtureBytes(t, name))
}

func decode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	value, err := admission.DecodeJSON(bytes.NewReader(data), fixtureBytesLimit)
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}

func canonicalJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := stablejson.MarshalLayout(value, stablejson.LayoutCompact)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// clone round-trips through JSON text so a case owns every nested container.
func clone(t *testing.T, value any) map[string]any {
	t.Helper()
	return decode(t, []byte(canonicalJSON(t, value)))
}

// groupedModel parses grouped bytes through the codec alone, independently of
// every conversion function under test.
func groupedModel(t *testing.T, value any) requirementsourcemodel.Model {
	t.Helper()
	result, err := requirementsourcecodec.Parse([]byte(canonicalJSON(t, value)))
	if err != nil {
		t.Fatalf("grouped expectation is not an admitted source: %v", err)
	}
	return result.Model
}

// at resolves a JSON pointer of object keys and array indexes in a fixture.
func at(t *testing.T, root any, pointer string) any {
	t.Helper()
	current := root
	for _, segment := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		switch typed := current.(type) {
		case map[string]any:
			current = typed[segment]
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(typed) {
				t.Fatalf("pointer %s has no element %s", pointer, segment)
			}
			current = typed[index]
		default:
			t.Fatalf("pointer %s crosses a scalar at %s", pointer, segment)
		}
	}
	return current
}

// set replaces or adds one value addressed by a JSON pointer.
func set(t *testing.T, root any, pointer string, value any) {
	t.Helper()
	index := strings.LastIndex(pointer, "/")
	parent := root
	if pointer[:index] != "" {
		parent = at(t, root, pointer[:index])
	}
	key := pointer[index+1:]
	switch typed := parent.(type) {
	case map[string]any:
		typed[key] = value
	case []any:
		position, err := strconv.Atoi(key)
		if err != nil || position < 0 || position >= len(typed) {
			t.Fatalf("pointer %s has no element %s", pointer, key)
		}
		typed[position] = value
	default:
		t.Fatalf("pointer %s parent is a scalar", pointer)
	}
}

func remove(t *testing.T, root any, pointer string) {
	t.Helper()
	index := strings.LastIndex(pointer, "/")
	parent := root
	if pointer[:index] != "" {
		parent = at(t, root, pointer[:index])
	}
	record, ok := parent.(map[string]any)
	if !ok {
		t.Fatalf("pointer %s does not name an object member", pointer)
	}
	delete(record, pointer[index+1:])
}

func refusalOf(t *testing.T, err error) *Error {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("expected a typed conversion refusal, got %v", err)
	}
	return typed
}

func values(items ...any) []any { return items }

func jsonNumber(value int) json.Number { return json.Number(strconv.Itoa(value)) }
