package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
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
	if err := preflightTokenLimit(source, codecLimits.MaxTokens); err != nil {
		return Result{}, err
	}

	wireShape := documentShape(modelLimits)
	indexed, err := indexJSON(source, codecLimits, wireShape)
	if err != nil {
		return Result{}, err
	}
	if err := validateShape(indexed.value, wireShape, "", indexed.locations, source); err != nil {
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
		return Result{}, modelDiagnostic(source, indexed.locations, wire, err)
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

func modelDiagnostic(source []byte, locations map[string]rawLocation, wire document, err error) error {
	code := requirementsourcemodel.ErrorCode(err)
	validation, ok := err.(*requirementsourcemodel.ValidationError)
	if !ok || code == "" {
		return diagnosticError(source, "model_admission_failed", "", locations[""].value, true)
	}
	resolved := resolveModelPath(wire, validation.Path)
	location := closestLocation(locations, resolved.lookup)
	return diagnosticError(source, code, resolved.reported, location.value, true)
}
