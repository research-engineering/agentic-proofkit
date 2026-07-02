package jsonpointer

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func FuzzSelectMatchesReferenceOracle(f *testing.F) {
	for _, seed := range []string{
		"",
		"/items/0/id",
		"/a~1b",
		"/a~0b",
		"/items/01",
		"/missing",
		"/items/0/missing",
		"items/0",
	} {
		f.Add(seed)
	}
	input := map[string]any{
		"items": []any{
			map[string]any{"id": "first"},
			map[string]any{"id": "second"},
		},
		"a/b": "slash",
		"a~b": "tilde",
	}
	f.Fuzz(func(t *testing.T, pointer string) {
		got, gotErr := Select(input, pointer)
		want, wantInvalid := referenceSelect(input, pointer)
		if (gotErr == nil) == wantInvalid {
			t.Fatalf("Select(%q) error=%v, reference invalid=%v", pointer, gotErr, wantInvalid)
		}
		if gotErr == nil && !reflect.DeepEqual(got, want) {
			t.Fatalf("Select(%q)=%#v, want %#v", pointer, got, want)
		}
	})
}

func referenceSelect(input any, pointer string) (any, bool) {
	if pointer == "" {
		return input, false
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, true
	}
	current := input
	for _, rawPart := range strings.Split(pointer[1:], "/") {
		part, invalid := referenceDecodePointerToken(rawPart)
		if invalid {
			return nil, true
		}
		switch typed := current.(type) {
		case []any:
			index, invalid := referenceArrayIndex(part)
			if invalid || index >= len(typed) {
				return nil, true
			}
			current = typed[index]
		case map[string]any:
			value, ok := typed[part]
			if !ok {
				return nil, true
			}
			current = value
		default:
			return nil, true
		}
	}
	return current, false
}

func referenceDecodePointerToken(raw string) (string, bool) {
	var builder strings.Builder
	for index := 0; index < len(raw); index++ {
		if raw[index] != '~' {
			builder.WriteByte(raw[index])
			continue
		}
		if index+1 >= len(raw) {
			return "", true
		}
		switch raw[index+1] {
		case '0':
			builder.WriteByte('~')
		case '1':
			builder.WriteByte('/')
		default:
			return "", true
		}
		index++
	}
	return builder.String(), false
}

func referenceArrayIndex(part string) (int, bool) {
	if part == "" || len(part) > 1 && part[0] == '0' {
		return 0, true
	}
	for _, char := range part {
		if char < '0' || char > '9' {
			return 0, true
		}
	}
	index, err := strconv.Atoi(part)
	return index, err != nil
}
