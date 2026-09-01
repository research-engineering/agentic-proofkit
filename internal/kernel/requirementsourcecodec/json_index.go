package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type rawLocation struct {
	key   *ByteSpan
	value ByteSpan
}

type indexedValue struct {
	value     any
	locations map[string]rawLocation
}

type jsonIndexer struct {
	source    []byte
	decoder   *json.Decoder
	limits    Limits
	locations map[string]rawLocation
}

func indexJSON(source []byte, limits Limits, expected *shape) (indexedValue, error) {
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	indexer := &jsonIndexer{source: source, decoder: decoder, limits: limits, locations: map[string]rawLocation{}}
	value, _, err := indexer.parseValue("", "", 1, expected)
	if err != nil {
		return indexedValue{}, err
	}
	before := decoder.InputOffset()
	_, err = decoder.Token()
	if err == nil {
		after := decoder.InputOffset()
		return indexedValue{}, diagnosticError(source, "multiple_values", "", tokenSpan(source, before, after), true)
	}
	if !errors.Is(err, io.EOF) {
		return indexedValue{}, syntaxError(source, decoder.InputOffset())
	}
	return indexedValue{value: value, locations: indexer.locations}, nil
}

func (indexer *jsonIndexer) parseValue(rawPath string, safePath string, depth int, expected *shape) (any, ByteSpan, error) {
	if depth > indexer.limits.MaxNesting {
		offset := indexer.decoder.InputOffset()
		return nil, ByteSpan{}, diagnosticError(indexer.source, "nesting_limit_exceeded", safePath, ByteSpan{Start: offset, End: offset}, true)
	}
	token, span, err := indexer.nextToken(safePath)
	if err != nil {
		return nil, ByteSpan{}, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		indexer.locations[rawPath] = rawLocation{value: span}
		return token, span, nil
	}
	switch delimiter {
	case '{':
		return indexer.parseObject(rawPath, safePath, depth, span, expected)
	case '[':
		return indexer.parseArray(rawPath, safePath, depth, span, expected)
	default:
		return nil, ByteSpan{}, diagnosticError(indexer.source, "invalid_syntax", safePath, span, true)
	}
}

func (indexer *jsonIndexer) parseObject(rawPath string, safePath string, depth int, opening ByteSpan, expected *shape) (any, ByteSpan, error) {
	result := map[string]any{}
	seen := map[string]struct{}{}
	for indexer.decoder.More() {
		keyToken, keySpan, err := indexer.nextToken(safePath)
		if err != nil {
			return nil, ByteSpan{}, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, ByteSpan{}, diagnosticError(indexer.source, "invalid_object_key", safePath, keySpan, true)
		}
		if _, exists := seen[key]; exists {
			return nil, ByteSpan{}, diagnosticError(indexer.source, "duplicate_field", safePath, keySpan, true)
		}
		seen[key] = struct{}{}
		rawChildPath := joinPointer(rawPath, key)
		safeKey, childShape := safeObjectChild(expected, key)
		safeChildPath := joinPointer(safePath, safeKey)
		value, _, err := indexer.parseValue(rawChildPath, safeChildPath, depth+1, childShape)
		if err != nil {
			return nil, ByteSpan{}, err
		}
		location := indexer.locations[rawChildPath]
		location.key = &keySpan
		indexer.locations[rawChildPath] = location
		result[key] = value
	}
	closingToken, closingSpan, err := indexer.nextToken(safePath)
	if err != nil {
		return nil, ByteSpan{}, err
	}
	if closingToken != json.Delim('}') {
		return nil, ByteSpan{}, diagnosticError(indexer.source, "invalid_syntax", safePath, closingSpan, true)
	}
	span := ByteSpan{Start: opening.Start, End: closingSpan.End}
	location := indexer.locations[rawPath]
	location.value = span
	indexer.locations[rawPath] = location
	return result, span, nil
}

func (indexer *jsonIndexer) parseArray(rawPath string, safePath string, depth int, opening ByteSpan, expected *shape) (any, ByteSpan, error) {
	result := []any{}
	var childShape *shape
	if expected != nil && expected.kind == shapeArray {
		childShape = expected.element
	}
	for index := 0; indexer.decoder.More(); index++ {
		indexValue := strconv.Itoa(index)
		rawChildPath := joinPointer(rawPath, indexValue)
		safeChildPath := joinPointer(safePath, indexValue)
		value, _, err := indexer.parseValue(rawChildPath, safeChildPath, depth+1, childShape)
		if err != nil {
			return nil, ByteSpan{}, err
		}
		result = append(result, value)
	}
	closingToken, closingSpan, err := indexer.nextToken(safePath)
	if err != nil {
		return nil, ByteSpan{}, err
	}
	if closingToken != json.Delim(']') {
		return nil, ByteSpan{}, diagnosticError(indexer.source, "invalid_syntax", safePath, closingSpan, true)
	}
	span := ByteSpan{Start: opening.Start, End: closingSpan.End}
	location := indexer.locations[rawPath]
	location.value = span
	indexer.locations[rawPath] = location
	return result, span, nil
}

func (indexer *jsonIndexer) nextToken(path string) (any, ByteSpan, error) {
	before := indexer.decoder.InputOffset()
	token, err := indexer.decoder.Token()
	if err != nil {
		return nil, ByteSpan{}, syntaxError(indexer.source, indexer.decoder.InputOffset())
	}
	after := indexer.decoder.InputOffset()
	span := tokenSpan(indexer.source, before, after)
	if _, ok := token.(string); ok && !validJSONStringToken(indexer.source[span.Start:span.End]) {
		return nil, ByteSpan{}, diagnosticError(indexer.source, "invalid_unicode_escape", path, span, true)
	}
	return token, span, nil
}

func preflightTokenLimit(source []byte, limit int) error {
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	for count := 1; ; count++ {
		before := decoder.InputOffset()
		_, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return syntaxError(source, decoder.InputOffset())
		}
		if count > limit {
			return diagnosticError(source, "token_limit_exceeded", "", tokenSpan(source, before, decoder.InputOffset()), true)
		}
	}
}

func safeObjectChild(expected *shape, key string) (string, *shape) {
	if expected == nil || expected.kind != shapeObject {
		return "<unknown>", nil
	}
	if expected.dynamic != nil {
		return "<entry>", expected.dynamic
	}
	if field, exists := expected.fields[key]; exists {
		return key, field.shape
	}
	for canonical, field := range expected.fields {
		if strings.EqualFold(key, canonical) {
			return canonical, field.shape
		}
	}
	return "<unknown>", nil
}

func validJSONStringToken(token []byte) bool {
	if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' {
		return false
	}
	for index := 1; index < len(token)-1; index++ {
		if token[index] != '\\' {
			continue
		}
		index++
		if index >= len(token)-1 {
			return false
		}
		if token[index] != 'u' {
			continue
		}
		value, ok := hexQuad(token, index+1)
		if !ok {
			return false
		}
		index += 4
		switch {
		case value >= 0xd800 && value <= 0xdbff:
			if index+6 >= len(token) || token[index+1] != '\\' || token[index+2] != 'u' {
				return false
			}
			low, lowOK := hexQuad(token, index+3)
			if !lowOK || low < 0xdc00 || low > 0xdfff {
				return false
			}
			index += 6
		case value >= 0xdc00 && value <= 0xdfff:
			return false
		}
	}
	return true
}

func hexQuad(source []byte, offset int) (uint16, bool) {
	if offset < 0 || offset+4 > len(source) {
		return 0, false
	}
	value := uint16(0)
	for _, character := range source[offset : offset+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func tokenSpan(source []byte, before int64, after int64) ByteSpan {
	start := before
	for start < after {
		switch source[start] {
		case ' ', '\t', '\r', '\n', ',', ':':
			start++
		default:
			return ByteSpan{Start: start, End: after}
		}
	}
	return ByteSpan{Start: before, End: after}
}

func sourceMap(source []byte, locations map[string]rawLocation) SourceMap {
	offsets := make([]int64, 0, len(locations)*3)
	for _, location := range locations {
		offsets = append(offsets, location.value.Start, location.value.End)
		if location.key != nil {
			offsets = append(offsets, location.key.Start, location.key.End)
		}
	}
	positions := positionsAt(source, offsets)
	entries := make(map[string]Location, len(locations))
	for path, raw := range locations {
		entries[path] = Location{KeySpan: raw.key, ValueSpan: raw.value, Start: positions[raw.value.Start], End: positions[raw.value.End]}
	}
	return SourceMap{entries: entries}
}

func positionsAt(source []byte, offsets []int64) map[int64]Position {
	sort.Slice(offsets, func(left, right int) bool { return offsets[left] < offsets[right] })
	unique := offsets[:0]
	for _, offset := range offsets {
		if len(unique) == 0 || unique[len(unique)-1] != offset {
			unique = append(unique, offset)
		}
	}
	result := make(map[int64]Position, len(unique))
	line := 1
	column := 1
	byteOffset := 0
	index := 0
	previousCR := false
	for index < len(unique) && unique[index] == 0 {
		result[unique[index]] = Position{Line: line, ScalarColumn: column}
		index++
	}
	for byteOffset < len(source) {
		value, width := utf8.DecodeRune(source[byteOffset:])
		byteOffset += width
		if value == '\r' {
			line++
			column = 1
			previousCR = true
		} else if value == '\n' {
			if !previousCR {
				line++
			}
			column = 1
			previousCR = false
		} else {
			column++
			previousCR = false
		}
		for index < len(unique) && int64(byteOffset) >= unique[index] {
			result[unique[index]] = Position{Line: line, ScalarColumn: column}
			index++
		}
	}
	for index < len(unique) {
		result[unique[index]] = Position{Line: line, ScalarColumn: column}
		index++
	}
	return result
}

func diagnosticError(source []byte, code string, path string, span ByteSpan, validUTF8 bool) error {
	diagnostic := Diagnostic{Code: code, Path: path, Span: span, CoordinateState: "byte_only"}
	if validUTF8 {
		positions := positionsAt(source, []int64{span.Start, span.End})
		start := positions[span.Start]
		end := positions[span.End]
		diagnostic.CoordinateState = "scalar"
		diagnostic.Start = &start
		diagnostic.End = &end
	}
	return &Error{diagnostic: diagnostic}
}

func syntaxError(source []byte, offset int64) error {
	if offset < 0 {
		offset = 0
	}
	if offset > int64(len(source)) {
		offset = int64(len(source))
	}
	return diagnosticError(source, "invalid_syntax", "", ByteSpan{Start: offset, End: offset}, true)
}

func joinPointer(parent string, token string) string {
	escaped := strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
	return parent + "/" + escaped
}

func sortStrings(values []string) {
	sort.Strings(values)
}
