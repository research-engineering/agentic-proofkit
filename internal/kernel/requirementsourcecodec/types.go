package requirementsourcecodec

import (
	"fmt"

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

type Error struct {
	diagnostic Diagnostic
}

func (err *Error) Error() string {
	if err.diagnostic.Path == "" {
		return err.diagnostic.Code
	}
	return fmt.Sprintf("%s: %s", err.diagnostic.Code, err.diagnostic.Path)
}

func (err *Error) Diagnostic() Diagnostic {
	return cloneDiagnostic(err.diagnostic)
}

func ErrorCode(err error) string {
	if typed, ok := err.(*Error); ok {
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
