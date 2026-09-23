package requirementbrowser

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const maxWorkspaceLookupResponseBytes = 16 << 20

// Private lookup routes share the encoded-page budget, not row semantics.
type workspacePage struct {
	Count      int
	Offset     int
	Limit      int
	RowsKey    string
	Row        func(int) map[string]any
	Projection func([]any) (workspaceProjection, error)
}

type workspaceProjection struct {
	Value map[string]any
	State string
	// Canonical subtree lengths without the final newline, for shared arrays.
	EncodedArrayBytes map[string]int
}

func (page workspacePage) encode(requestID, snapshotID string, byteLimit int) ([]byte, error) {
	rows := []any{}
	rowBytes := 0
	start := min(page.Offset, page.Count)
	end := start + min(page.Limit, page.Count-start)
	envelope := func(projection workspaceProjection) map[string]any {
		return map[string]any{"projection": projection.Value, "requestId": requestID, "schemaVersion": json.Number(fmt.Sprint(workspaceProjectionSchemaVersion)), "snapshotId": snapshotID, "state": projection.State}
	}
	projection, err := page.Projection(rows)
	if err != nil {
		return nil, err
	}
	estimated, err := page.encodedSize(projection, envelope, 0, 0)
	if err != nil {
		return nil, err
	}
	if _, err := encodeWorkspaceProjection(envelope(projection), estimated); err != nil {
		return nil, err
	}
	if estimated > byteLimit {
		return nil, fmt.Errorf("browser lookup metadata exceeds response capacity")
	}
	for position := start; position < end; position++ {
		row := page.Row(position)
		encodedRow, err := stablejson.MarshalLayout(row, stablejson.LayoutCompact)
		if err != nil {
			return nil, err
		}
		candidate := append(rows, row)
		next, err := page.Projection(candidate)
		if err != nil {
			return nil, err
		}
		nextRowBytes := rowBytes + len(encodedRow) - 1
		nextSize, err := page.encodedSize(next, envelope, len(candidate), nextRowBytes)
		if err != nil {
			return nil, err
		}
		if nextSize > byteLimit {
			// An overestimated cache must not silently omit a row that would fit.
			if _, err := encodeWorkspaceProjection(envelope(next), nextSize); err != nil {
				return nil, err
			}
			if len(rows) == 0 {
				return nil, fmt.Errorf("browser lookup record exceeds response capacity")
			}
			break
		}
		rows, rowBytes = candidate, nextRowBytes
		projection, estimated = next, nextSize
	}
	body, err := encodeWorkspaceProjection(envelope(projection), estimated)
	if err != nil {
		return nil, err
	}
	if len(body) > byteLimit {
		return nil, fmt.Errorf("browser lookup metadata exceeds response capacity")
	}
	return body, nil
}

func (page workspacePage) encodedSize(projection workspaceProjection, envelope func(workspaceProjection) map[string]any, rowCount, rowBytes int) (int, error) {
	metadata := maps.Clone(projection.Value)
	if rows, ok := metadata[page.RowsKey].([]any); !ok || len(rows) != rowCount {
		return 0, fmt.Errorf("browser lookup projection does not retain its rows")
	}
	metadata[page.RowsKey] = []any{}
	additional := rowBytes + max(0, rowCount-1)
	for key, size := range projection.EncodedArrayBytes {
		if _, ok := metadata[key].([]any); !ok || key == page.RowsKey || size < 2 || size-2 > math.MaxInt-additional {
			return 0, fmt.Errorf("browser lookup shared array size is invalid")
		}
		metadata[key] = []any{}
		additional += size - 2
	}
	projection.Value = metadata
	header, err := stablejson.MarshalLayout(envelope(projection), stablejson.LayoutCompact)
	if err != nil {
		return 0, err
	}
	if additional > math.MaxInt-len(header) {
		return 0, fmt.Errorf("browser lookup encoded size overflows")
	}
	return len(header) + additional, nil
}

func encodeWorkspaceProjection(value map[string]any, expected int) ([]byte, error) {
	body, err := stablejson.MarshalLayout(value, stablejson.LayoutCompact)
	if err != nil {
		return nil, err
	}
	if len(body) != expected {
		return nil, fmt.Errorf("browser lookup encoded size disagrees with canonical bytes")
	}
	return body, nil
}
