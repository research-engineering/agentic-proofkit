package requirementsourcemodel

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorCodePreservesWrappedClassification(t *testing.T) {
	original := invalid("invalid_id", "sourceId")
	for _, err := range []error{original, fmt.Errorf("context: %w", original), errors.Join(errors.New("cleanup"), original)} {
		if got := ErrorCode(err); got != "invalid_id" {
			t.Errorf("ErrorCode(%v)=%q, want invalid_id", err, got)
		}
	}
	for _, err := range []error{nil, errors.New("unclassified"), (*ValidationError)(nil)} {
		if got := ErrorCode(err); got != "" {
			t.Errorf("ErrorCode()=%q, want empty", got)
		}
	}
}
