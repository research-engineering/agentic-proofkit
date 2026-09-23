package requirementdiff

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestDiffOutputRejectsRehashedValuesOutsideProducerStructure(t *testing.T) {
	for _, mutation := range []string{"missing-before", "missing-source-digest", "unknown-map", "boolean-array"} {
		t.Run(mutation, func(t *testing.T) {
			input := diffStructureInput(t)
			output, err := Build(input)
			if err != nil {
				t.Fatal(err)
			}
			change := output["changes"].([]any)[0].(map[string]any)
			switch mutation {
			case "missing-before":
				delete(change, "before")
			case "missing-source-digest":
				delete(change, "baseSourceDigest")
			case "unknown-map":
				change["after"] = map[string]any{"notAnOwnerField": "value"}
			case "boolean-array":
				change["after"] = []any{true}
			}
			identity := map[string]any{"baseSnapshotId": output["baseSnapshotId"], "currentSnapshotId": output["currentSnapshotId"]}
			for _, key := range []string{"after", "baseSourceDigest", "before", "changeClass", "currentSourceDigest", "entityId", "entityKind", "jsonPointer"} {
				identity[key] = change[key]
			}
			encoded, err := stablejson.Marshal(identity)
			if err != nil {
				t.Fatal(err)
			}
			change["changeId"] = digest.SHA256BytesRef(encoded)
			if err := diffOutputShape.CheckGenerated(output, "diff"); err == nil {
				t.Fatal("malformed producer value admitted by structure")
			}
			if _, err := AdmitOutput(output, output["currentSnapshotId"].(string)); err == nil {
				t.Fatal("rehashing bypassed producer structure")
			}
		})
	}
}
