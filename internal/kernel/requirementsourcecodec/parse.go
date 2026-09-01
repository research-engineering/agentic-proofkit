package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func Parse(source []byte) (Result, error) {
	return ParseWithLimits(source, DefaultLimits(), requirementsourcemodel.DefaultLimits())
}

func ParseWithLimits(source []byte, codecLimits Limits, modelLimits requirementsourcemodel.Limits) (Result, error) {
	if err := validateLimits(codecLimits, modelLimits); err != nil {
		return Result{}, err
	}
	if int64(len(source)) > codecLimits.MaxRawBytes {
		start := codecLimits.MaxRawBytes
		return Result{}, diagnosticError(source, "raw_byte_limit_exceeded", "", ByteSpan{Start: start, End: start + 1}, false)
	}
	if invalidOffset, ok := firstInvalidUTF8(source); ok {
		return Result{}, diagnosticError(source, "invalid_utf8", "", ByteSpan{Start: invalidOffset, End: invalidOffset + 1}, false)
	}

	indexed, err := indexJSON(source, codecLimits)
	if err != nil {
		return Result{}, err
	}
	if err := validateShape(indexed.value, documentShape(modelLimits), "", indexed.locations, source); err != nil {
		return Result{}, err
	}

	canonicalValue, err := json.Marshal(indexed.value)
	if err != nil {
		return Result{}, diagnosticError(source, "invalid_projection", "", indexed.locations[""].value, true)
	}
	var wire document
	decoder := json.NewDecoder(bytes.NewReader(canonicalValue))
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		return Result{}, diagnosticError(source, "invalid_projection", "", indexed.locations[""].value, true)
	}
	draft, err := draftFromDocument(wire)
	if err != nil {
		return Result{}, diagnosticError(source, "invalid_projection", "", indexed.locations[""].value, true)
	}
	model, err := requirementsourcemodel.NormalizeWithLimits(draft, modelLimits)
	if err != nil {
		return Result{}, modelDiagnostic(source, indexed.locations, err)
	}
	return Result{Model: model, SourceMap: sourceMap(source, indexed.locations)}, nil
}

func firstInvalidUTF8(source []byte) (int64, bool) {
	for offset := 0; offset < len(source); {
		value, width := utf8.DecodeRune(source[offset:])
		if value == utf8.RuneError && width == 1 {
			return int64(offset), true
		}
		offset += width
	}
	return 0, false
}

func modelDiagnostic(source []byte, locations map[string]rawLocation, err error) error {
	code := requirementsourcemodel.ErrorCode(err)
	validation, ok := err.(*requirementsourcemodel.ValidationError)
	if !ok || code == "" {
		return diagnosticError(source, "model_admission_failed", "", locations[""].value, true)
	}
	lookupPath, reportedPath := modelPathPointers(validation.Path)
	location := closestLocation(locations, lookupPath)
	return diagnosticError(source, code, reportedPath, location.value, true)
}

func closestLocation(locations map[string]rawLocation, path string) rawLocation {
	for current := path; ; {
		if location, exists := locations[current]; exists {
			return location
		}
		index := strings.LastIndex(current, "/")
		if index < 0 {
			break
		}
		current = current[:index]
	}
	return locations[""]
}

func modelPathPointers(path string) (string, string) {
	segments := modelPathSegments(path)
	lookup := ""
	reported := ""
	dynamicEntry := false
	for _, segment := range segments {
		lookup = joinPointer(lookup, segment)
		reportedSegment := segment
		if dynamicEntry {
			reportedSegment = "<entry>"
			dynamicEntry = false
		}
		reported = joinPointer(reported, reportedSegment)
		if segment == "values" {
			dynamicEntry = true
		}
	}
	return lookup, reported
}

func modelPathSegments(path string) []string {
	segments := make([]string, 0, 8)
	for offset := 0; offset < len(path); {
		switch path[offset] {
		case '.':
			offset++
		case '[':
			end := strings.IndexByte(path[offset:], ']')
			if end < 0 {
				return segments
			}
			end += offset
			if _, err := strconv.Atoi(path[offset+1 : end]); err == nil {
				segments = append(segments, path[offset+1:end])
			}
			offset = end + 1
		default:
			end := offset
			for end < len(path) && path[end] != '.' && path[end] != '[' {
				end++
			}
			if end > offset {
				segments = append(segments, path[offset:end])
			}
			offset = end
		}
	}
	return segments
}
