package requirementsourcecodec

import (
	"bytes"
	"strings"
	"testing"
)

func TestInvalidUTF8UsesByteOnlyCoordinates(t *testing.T) {
	payload := []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	_, err := Parse(payload)
	assertDiagnostic(t, err, "invalid_utf8", "")
	diagnostic := err.(*Error).Diagnostic()
	if diagnostic.CoordinateState != "byte_only" || diagnostic.Start != nil || diagnostic.End != nil {
		t.Fatalf("invalid UTF-8 coordinates = %#v", diagnostic)
	}
	if diagnostic.Span != (ByteSpan{Start: 6, End: 7}) {
		t.Fatalf("invalid UTF-8 span = %#v", diagnostic.Span)
	}
}

func TestBareCRAndCRLFAdvanceScalarLinesOnce(t *testing.T) {
	for _, item := range []struct {
		name      string
		separator string
	}{
		{name: "bare CR", separator: "\r"},
		{name: "CRLF", separator: "\r\n"},
	} {
		t.Run(item.name, func(t *testing.T) {
			payload := []byte(strings.Join([]string{
				"{", `  "kind":"proofkit.requirement-source",`, `  "schemaVersion":2,`, `  "sourceId":"safe",`, `  "extra":true`, "}",
			}, item.separator))
			_, err := Parse(payload)
			assertDiagnostic(t, err, "unknown_field", "/<unknown>")
			start := err.(*Error).Diagnostic().Start
			if start == nil || start.Line != 5 || start.ScalarColumn != 3 {
				t.Fatalf("diagnostic start = %#v", start)
			}
		})
	}
}

func TestMultipleValueDiagnosticSpansSecondToken(t *testing.T) {
	payload := append(append([]byte(nil), mustPayload(t)...), []byte(" true")...)
	_, err := Parse(payload)
	assertDiagnostic(t, err, "multiple_values", "")
	span := err.(*Error).Diagnostic().Span
	if !bytes.Equal(payload[span.Start:span.End], []byte("true")) {
		t.Fatalf("multiple-value span = %q", payload[span.Start:span.End])
	}
}

func TestValidUnicodeDiagnosticsUseScalarColumns(t *testing.T) {
	payload := []byte("{\n  \"kind\": \"proofkit.requirement-source\",\n  \"schemaVersion\": 2,\n  \"sourceId\": \"\u03bb\",\n  \"extra\": true\n}")
	_, err := Parse(payload)
	assertDiagnostic(t, err, "unknown_field", "/<unknown>")
	diagnostic := err.(*Error).Diagnostic()
	if diagnostic.CoordinateState != "scalar" || diagnostic.Start == nil || diagnostic.End == nil {
		t.Fatalf("valid UTF-8 coordinates = %#v", diagnostic)
	}
	if diagnostic.Start.Line != 5 || diagnostic.Start.ScalarColumn != 3 {
		t.Fatalf("unknown-field start = %#v", diagnostic.Start)
	}
}

func TestShapeDiagnosticSelectionFollowsSourceOrder(t *testing.T) {
	firstUnknown := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		root["zUnknown"] = true
		root["aUnknown"] = true
	})
	firstUnknown = moveFieldFirst(t, firstUnknown, "zUnknown")
	for run := 0; run < 20; run++ {
		_, err := Parse(firstUnknown)
		assertDiagnostic(t, err, "unknown_field", "/<unknown>")
		span := err.(*Error).Diagnostic().Span
		if !bytes.Equal(firstUnknown[span.Start:span.End], []byte(`"zUnknown"`)) {
			t.Fatalf("run %d selected %q", run, firstUnknown[span.Start:span.End])
		}
	}
}

func moveFieldFirst(t *testing.T, payload []byte, field string) []byte {
	t.Helper()
	needle := []byte(`"` + field + `":true`)
	index := bytes.Index(payload, needle)
	if index < 0 {
		t.Fatalf("field %q not found", field)
	}
	end := index + len(needle)
	if end < len(payload) && payload[end] == ',' {
		end++
	} else if index > 0 && payload[index-1] == ',' {
		index--
	}
	fieldBytes := append([]byte(nil), payload[index:end]...)
	fieldBytes = bytes.Trim(fieldBytes, ",")
	remainder := append([]byte(nil), payload[:index]...)
	remainder = append(remainder, payload[end:]...)
	return append(append(append([]byte{'{'}, fieldBytes...), ','), remainder[1:]...)
}
