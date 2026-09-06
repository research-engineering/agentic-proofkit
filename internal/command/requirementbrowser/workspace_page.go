package requirementbrowser

import (
	"encoding/json"
	"fmt"

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
	Projection func([]any) (map[string]any, string)
}

func (page workspacePage) encode(requestID, snapshotID string, byteLimit int) ([]byte, error) {
	rows := []any{}
	rowBytes := 0
	start := min(page.Offset, page.Count)
	end := start + min(page.Limit, page.Count-start)
	envelope := func(selected []any) map[string]any {
		projection, state := page.Projection(selected)
		return map[string]any{"projection": projection, "requestId": requestID, "schemaVersion": json.Number("2"), "snapshotId": snapshotID, "state": state}
	}
	empty, err := stablejson.MarshalLayout(envelope(rows), stablejson.LayoutCompact)
	if err != nil {
		return nil, err
	}
	if len(empty) > byteLimit {
		return nil, fmt.Errorf("browser lookup metadata exceeds response capacity")
	}
	for position := start; position < end; position++ {
		row := page.Row(position)
		encodedRow, err := stablejson.MarshalLayout(row, stablejson.LayoutCompact)
		if err != nil {
			return nil, err
		}
		candidate := append(rows, row)
		// Count fields change, but previously encoded row bytes are not revisited.
		metadata := envelope(candidate)
		metadata["projection"].(map[string]any)[page.RowsKey] = []any{}
		header, err := stablejson.MarshalLayout(metadata, stablejson.LayoutCompact)
		if err != nil {
			return nil, err
		}
		nextRowBytes := rowBytes + len(encodedRow) - 1
		if len(header)+len(candidate)-1+nextRowBytes > byteLimit {
			if len(rows) == 0 {
				return nil, fmt.Errorf("browser lookup record exceeds response capacity")
			}
			break
		}
		rows, rowBytes = candidate, nextRowBytes
	}
	body, err := stablejson.MarshalLayout(envelope(rows), stablejson.LayoutCompact)
	if err != nil {
		return nil, err
	}
	if len(body) > byteLimit {
		return nil, fmt.Errorf("browser lookup metadata exceeds response capacity")
	}
	return body, nil
}
