package requirementsourceconversion

import (
	"errors"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

const (
	documentInput    = "input"
	documentBaseline = "baseline"
)

// Error is one bounded conversion refusal. Code comes from the closed
// converter, grouped codec or source model vocabulary. Pointer is a JSON
// pointer into the named caller document built only from declared names and
// array indexes; Detail is a structural admission message with the same
// property. No refusal echoes a caller-authored key or value.
type Error struct {
	Document string
	Code     string
	Pointer  string
	Detail   string
}

func (err *Error) Error() string {
	var message strings.Builder
	message.WriteString("requirement source conversion refused ")
	message.WriteString(err.Document)
	message.WriteString(": ")
	message.WriteString(err.Code)
	if err.Pointer != "" {
		message.WriteString(" at ")
		message.WriteString(err.Pointer)
	}
	if err.Detail != "" {
		message.WriteString(" (")
		message.WriteString(err.Detail)
		message.WriteString(")")
	}
	return message.String()
}

func refusal(document, code, pointer string) *Error {
	return &Error{Document: document, Code: code, Pointer: pointer}
}

// admitGroupedValue is the only route into the model. translate maps a grouped
// codec pointer to the caller's coordinates; locate maps a requirement ID that
// failed source policy to its caller coordinates.
func admitGroupedValue(value any, document string, translate func(string) string, locate func(string) string) (requirementsourcemodel.Model, error) {
	assessment, err := requirementsourcecodec.AssessValue(value)
	if err != nil {
		var typed *requirementsourcecodec.Error
		if errors.As(err, &typed) {
			diagnostic := typed.Diagnostic()
			return requirementsourcemodel.Model{}, refusal(document, diagnostic.Code, translate(diagnostic.Path))
		}
		return requirementsourcemodel.Model{}, refusal(document, "source_admission_failed", "")
	}
	if model, ok := assessment.Model(); ok {
		return model, nil
	}
	violations := assessment.Violations()
	if len(violations) == 0 {
		return requirementsourcemodel.Model{}, refusal(document, "source_admission_failed", "")
	}
	failure := refusal(document, violations[0].Code, locate(violations[0].RequirementID))
	failure.Detail = strconv.Itoa(len(violations)) + " source policy violation(s)"
	return requirementsourcemodel.Model{}, failure
}

func pointer(values ...any) string {
	var builder strings.Builder
	for _, value := range values {
		builder.WriteByte('/')
		switch typed := value.(type) {
		case string:
			builder.WriteString(strings.ReplaceAll(strings.ReplaceAll(typed, "~", "~0"), "/", "~1"))
		case int:
			builder.WriteString(strconv.Itoa(typed))
		default:
			panic("unsupported JSON pointer component")
		}
	}
	return builder.String()
}
