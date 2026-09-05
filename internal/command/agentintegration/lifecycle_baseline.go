package agentintegration

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const maximumBaselineBytes = 1024

func baselinePath(document Document) string {
	return "proofkit/integrations/" + document.tool + ".v1.json"
}

func baselineValue(document Document, snapshot repositorytransaction.Snapshot) map[string]any {
	return map[string]any{
		"kind": "proofkit.integration-baseline", "schemaVersion": json.Number("1"),
		"tool": document.tool, "targetPath": document.path,
		"byteCount":     json.Number(fmt.Sprint(snapshot.ByteCount)),
		"contentDigest": snapshot.SHA256, "mode": "0644",
	}
}

func currentBaseline(document Document) ([]byte, error) {
	return stablejson.MarshalLayout(baselineValue(document, repositorytransaction.Snapshot{
		ByteCount: int64(len(document.content)), Exists: true, Mode: 0o644, SHA256: document.contentDigest,
	}), stablejson.LayoutCompact)
}

func admitBaseline(content []byte, document Document) (repositorytransaction.Snapshot, error) {
	raw, err := admission.DecodeJSON(bytes.NewReader(content), maximumBaselineBytes)
	if err != nil {
		return repositorytransaction.Snapshot{}, fmt.Errorf("integration baseline is invalid")
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return repositorytransaction.Snapshot{}, fmt.Errorf("integration baseline must be an object")
	}
	if err := admit.KnownKeys(record, []string{"kind", "schemaVersion", "tool", "targetPath", "byteCount", "contentDigest", "mode"}, "integration baseline"); err != nil {
		return repositorytransaction.Snapshot{}, err
	}
	if record["kind"] != "proofkit.integration-baseline" || !admit.JSONNumberEquals(record["schemaVersion"], 1) || record["tool"] != document.tool || record["targetPath"] != document.path || record["mode"] != "0644" {
		return repositorytransaction.Snapshot{}, fmt.Errorf("integration baseline identity is invalid")
	}
	count, err := admit.CanonicalInteger(record["byteCount"], "integration baseline byteCount")
	if err != nil || count <= 0 || count > maximumCheckBytes {
		return repositorytransaction.Snapshot{}, fmt.Errorf("integration baseline byteCount is invalid")
	}
	sha, err := admit.SHA256Ref(record["contentDigest"], "integration baseline contentDigest")
	if err != nil {
		return repositorytransaction.Snapshot{}, err
	}
	snapshot := repositorytransaction.Snapshot{Exists: true, ByteCount: count, SHA256: sha, Mode: 0o644}
	canonical, err := stablejson.MarshalLayout(baselineValue(document, snapshot), stablejson.LayoutCompact)
	if err != nil || !bytes.Equal(content, canonical) {
		return repositorytransaction.Snapshot{}, fmt.Errorf("integration baseline encoding is not canonical")
	}
	return snapshot, nil
}

func recognizeLifecyclePair(document Document, operation string, transaction repositorytransaction.Plan) string {
	var bootstrap, baseline repositorytransaction.Operation
	var baselineBytes []byte
	for index, target := range transaction.Operations {
		if target.Path == document.path {
			bootstrap = target
		} else if target.Path == baselinePath(document) {
			baseline = target
			baselineBytes, _ = transaction.BeforeContent(index)
		}
	}
	if !baseline.Before.Exists {
		if !bootstrap.Before.Exists {
			if operation == OperationUpdate {
				return "not_installed"
			}
			return ""
		}
		current := bootstrap.Before.Mode == 0o644 && bootstrap.Before.SHA256 == document.contentDigest && bootstrap.Before.ByteCount == int64(len(document.content))
		if !current {
			return "unrecognized_bootstrap"
		}
		if operation != OperationInstall {
			return "missing_baseline"
		}
		return ""
	}
	prior, err := admitBaseline(baselineBytes, document)
	if err != nil || baseline.Before.Mode != 0o644 {
		return "invalid_baseline"
	}
	if !bootstrap.Before.Exists {
		if operation == OperationRemove {
			return ""
		}
		return "orphan_baseline"
	}
	if bootstrap.Before != prior {
		return "baseline_mismatch"
	}
	if operation == OperationInstall && lifecycleHasChanges(transaction) {
		return "update_required"
	}
	return ""
}
