package requirementsourcecodec

import (
	"errors"
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

const (
	SchemaVersion = 2
	DocumentKind  = "proofkit.requirement-source"
)

type Limits struct {
	MaxRawBytes    int64
	MaxTokens      int
	MaxNesting     int
	MaxOutputBytes int64
}

type ByteSpan struct {
	Start int64
	End   int64
}

type Position struct {
	Line         int
	ScalarColumn int
}

type Location struct {
	KeySpan   *ByteSpan
	ValueSpan ByteSpan
	Start     Position
	End       Position
}

type SourceMap struct {
	entries map[string]Location
}

// Location resolves a lexical JSON pointer in the admitted wire source. Array
// indexes describe the caller's source order, not normalized model order.
func (sourceMap SourceMap) Location(pointer string) (Location, bool) {
	location, exists := sourceMap.entries[pointer]
	return cloneLocation(location), exists
}

func (sourceMap SourceMap) Pointers() []string {
	result := make([]string, 0, len(sourceMap.entries))
	for pointer := range sourceMap.entries {
		result = append(result, pointer)
	}
	sortStrings(result)
	return result
}

type Result struct {
	Model     requirementsourcemodel.Model
	SourceMap SourceMap
}

type Diagnostic struct {
	Code            string
	Path            string
	Span            ByteSpan
	CoordinateState string
	Start           *Position
	End             *Position
}

// Error describes the first rejected fault; additional holds later
// independent faults of the same rejected source, bounded like the model.
type Error struct {
	diagnostic Diagnostic
	additional []Diagnostic
	omitted    int
}

func (err *Error) Error() string {
	parts := make([]string, 0, len(err.additional)+2)
	for _, diagnostic := range append([]Diagnostic{err.diagnostic}, err.additional...) {
		if diagnostic.Path == "" {
			parts = append(parts, diagnostic.Code)
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s", diagnostic.Code, diagnostic.Path))
		}
	}
	if err.omitted > 0 {
		parts = append(parts, fmt.Sprintf("%d more", err.omitted))
	}
	return strings.Join(parts, "; ")
}

func (err *Error) Diagnostic() Diagnostic {
	return cloneDiagnostic(err.diagnostic)
}

// Diagnostics returns every described fault in report order.
func (err *Error) Diagnostics() []Diagnostic {
	result := make([]Diagnostic, 0, len(err.additional)+1)
	for _, diagnostic := range append([]Diagnostic{err.diagnostic}, err.additional...) {
		result = append(result, cloneDiagnostic(diagnostic))
	}
	return result
}

// OmittedCount reports faults beyond the described bound.
func (err *Error) OmittedCount() int {
	return err.omitted
}

// diagnosticCollector joins independent codec faults with the model bound.
// A located fault is kept as a span with CoordinateState scalar and no
// position until locatedErr computes the positions of all kept faults at once.
type diagnosticCollector struct {
	diagnostics []Diagnostic
	omitted     int
	fatal       error
}

// addLocated keeps a fault's span while the bound has room and otherwise only
// counts it, so an omitted fault never costs a coordinate sweep.
func (collector *diagnosticCollector) addLocated(code string, path string, span ByteSpan) {
	if collector.fatal != nil {
		return
	}
	if len(collector.diagnostics) >= requirementsourcemodel.MaxReportedValidationErrors {
		collector.omitted++
		return
	}
	collector.diagnostics = append(collector.diagnostics, Diagnostic{Code: code, Path: path, Span: span, CoordinateState: "scalar"})
}

// locatedErr computes scalar coordinates for every kept located fault in one
// source sweep, then returns the collected error.
func (collector *diagnosticCollector) locatedErr(source []byte) error {
	pending := func(diagnostic Diagnostic) bool {
		return diagnostic.CoordinateState == "scalar" && diagnostic.Start == nil
	}
	offsets := []int64{}
	for _, diagnostic := range collector.diagnostics {
		if pending(diagnostic) {
			offsets = append(offsets, diagnostic.Span.Start, diagnostic.Span.End)
		}
	}
	if len(offsets) != 0 {
		positions := positionsAt(source, offsets)
		for index, diagnostic := range collector.diagnostics {
			if pending(diagnostic) {
				start, end := positions[diagnostic.Span.Start], positions[diagnostic.Span.End]
				collector.diagnostics[index].Start, collector.diagnostics[index].End = &start, &end
			}
		}
	}
	return collector.err()
}

func (collector *diagnosticCollector) add(err error) {
	if err == nil || collector.fatal != nil {
		return
	}
	var typed *Error
	if !errors.As(err, &typed) || typed == nil {
		collector.fatal = err
		return
	}
	for _, diagnostic := range append([]Diagnostic{typed.diagnostic}, typed.additional...) {
		if len(collector.diagnostics) < requirementsourcemodel.MaxReportedValidationErrors {
			collector.diagnostics = append(collector.diagnostics, cloneDiagnostic(diagnostic))
		} else {
			collector.omitted++
		}
	}
	collector.omitted += typed.omitted
}

func (collector *diagnosticCollector) failed() bool {
	return collector.fatal != nil || len(collector.diagnostics) != 0 || collector.omitted != 0
}

func (collector *diagnosticCollector) err() error {
	if collector.fatal != nil {
		return collector.fatal
	}
	if len(collector.diagnostics) == 0 {
		return nil
	}
	return &Error{diagnostic: collector.diagnostics[0], additional: append([]Diagnostic{}, collector.diagnostics[1:]...), omitted: collector.omitted}
}

func ErrorCode(err error) string {
	var typed *Error
	if errors.As(err, &typed) && typed != nil {
		return typed.diagnostic.Code
	}
	return ""
}

func cloneLocation(value Location) Location {
	result := value
	if value.KeySpan != nil {
		span := *value.KeySpan
		result.KeySpan = &span
	}
	return result
}

func cloneDiagnostic(value Diagnostic) Diagnostic {
	result := value
	if value.Start != nil {
		position := *value.Start
		result.Start = &position
	}
	if value.End != nil {
		position := *value.End
		result.End = &position
	}
	return result
}
