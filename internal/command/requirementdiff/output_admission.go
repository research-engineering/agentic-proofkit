package requirementdiff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/secretjson"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var changeClasses = map[string]struct{}{
	"entity_added": {}, "entity_removed": {}, "lifecycle_transition": {},
	"opaque_value_changed": {}, "reference_changed": {}, "scalar_changed": {},
	"sequence_changed": {}, "set_membership_changed": {}, "tree_parent_changed": {},
}

func AdmitOutput(raw any, currentSnapshotID string) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("requirement semantic diff output must be an object")
	}
	if err := admit.KnownKeys(record, []string{"baseBaselineVerification", "baseSnapshotId", "changeCount", "changes", "currentBaselineVerification", "currentSnapshotId", "diffId", "diffKind", "nonClaims", "schemaVersion"}, "requirement semantic diff output"); err != nil {
		return nil, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) && record["schemaVersion"] != 1 {
		return nil, fmt.Errorf("requirement semantic diff output schemaVersion must be 1")
	}
	if record["diffKind"] != "proofkit.requirement-semantic-diff" || record["currentSnapshotId"] != currentSnapshotID {
		return nil, fmt.Errorf("requirement semantic diff output identity is invalid")
	}
	for _, key := range []string{"baseSnapshotId", "currentSnapshotId"} {
		if _, err := digestRef(record[key], "requirement semantic diff output "+key); err != nil {
			return nil, err
		}
	}
	for _, key := range []string{"baseBaselineVerification", "currentBaselineVerification"} {
		if _, err := admit.Enum(record[key], map[string]struct{}{"partially_verified": {}, "unverified": {}, "verified": {}}, "requirement semantic diff output "+key); err != nil {
			return nil, err
		}
	}
	changes, ok := record["changes"].([]any)
	if !ok || !countEquals(record["changeCount"], len(changes)) {
		return nil, fmt.Errorf("requirement semantic diff changeCount must match changes")
	}
	seen := map[string]struct{}{}
	var previousOrder *changeOrderKey
	for index, rawChange := range changes {
		change, ok := rawChange.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement semantic diff changes[%d] must be an object", index)
		}
		if err := admit.KnownKeys(change, []string{"after", "baseSourceDigest", "before", "changeClass", "changeId", "currentSourceDigest", "entityId", "entityKind", "jsonPointer"}, "requirement semantic diff change"); err != nil {
			return nil, err
		}
		changeID, err := digestRef(change["changeId"], "requirement semantic diff changeId")
		if err != nil {
			return nil, err
		}
		if _, exists := seen[changeID]; exists {
			return nil, fmt.Errorf("requirement semantic diff change ids must be unique")
		}
		seen[changeID] = struct{}{}
		changeClass, err := admit.Enum(change["changeClass"], changeClasses, "requirement semantic diff changeClass")
		if err != nil {
			return nil, err
		}
		if change["entityKind"] != "requirement" {
			return nil, fmt.Errorf("requirement semantic diff entityKind must be requirement")
		}
		entityID, err := admit.RuleID(change["entityId"], "requirement semantic diff entityId")
		if err != nil {
			return nil, err
		}
		pointer, err := admit.NonEmptyText(change["jsonPointer"], "requirement semantic diff jsonPointer")
		expectedPrefix := "/requirements/" + escapePointer(entityID)
		if err != nil || (pointer != expectedPrefix && !strings.HasPrefix(pointer, expectedPrefix+"/")) {
			return nil, fmt.Errorf("requirement semantic diff jsonPointer must target requirements")
		}
		order := changeOrderKey{EntityID: entityID, JSONPointer: pointer, ChangeClass: changeClass, ChangeID: changeID}
		if previousOrder != nil && !changeOrderLess(*previousOrder, order) {
			return nil, fmt.Errorf("requirement semantic diff changes must use canonical semantic order")
		}
		previousOrder = &order
		identity := map[string]any{"after": change["after"], "baseSnapshotId": record["baseSnapshotId"], "baseSourceDigest": change["baseSourceDigest"], "before": change["before"], "changeClass": changeClass, "currentSnapshotId": record["currentSnapshotId"], "currentSourceDigest": change["currentSourceDigest"], "entityId": entityID, "entityKind": "requirement", "jsonPointer": pointer}
		encodedIdentity, err := stablejson.Marshal(identity)
		if err != nil || digest.SHA256TextRef(string(encodedIdentity)) != changeID {
			return nil, fmt.Errorf("requirement semantic diff changeId does not match change identity")
		}
		if err := admitOptionalDigest(change["baseSourceDigest"], "requirement semantic diff baseSourceDigest"); err != nil {
			return nil, err
		}
		if err := admitOptionalDigest(change["currentSourceDigest"], "requirement semantic diff currentSourceDigest"); err != nil {
			return nil, err
		}
		if changeClass == "entity_added" && change["before"] != nil {
			return nil, fmt.Errorf("added requirement semantic diff change must not have a before value")
		}
		if changeClass == "entity_removed" && change["after"] != nil {
			return nil, fmt.Errorf("removed requirement semantic diff change must not have an after value")
		}
	}
	findings, err := secretjson.Scan(record, "semantic_diff")
	if err != nil {
		return nil, err
	}
	if len(findings) > 0 {
		return nil, fmt.Errorf("requirement semantic diff output contains secret-shaped data")
	}
	if err := exactNonClaims(record["nonClaims"]); err != nil {
		return nil, err
	}
	return canonicalCopy(record)
}

func exactNonClaims(raw any) error {
	values, ok := raw.([]any)
	if !ok || len(values) != len(nonClaims) {
		return fmt.Errorf("requirement semantic diff nonClaims must equal the command-owned boundary")
	}
	for index, expected := range nonClaims {
		if values[index] != expected {
			return fmt.Errorf("requirement semantic diff nonClaims must equal the command-owned boundary")
		}
	}
	return nil
}

func canonicalCopy(record map[string]any) (map[string]any, error) {
	encoded, err := stablejson.Marshal(record)
	if err != nil {
		return nil, err
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		return nil, err
	}
	return decoded.(map[string]any), nil
}

func admitOptionalDigest(raw any, context string) error {
	if raw == nil || raw == "" {
		return nil
	}
	_, err := digestRef(raw, context)
	return err
}

func digestRef(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil || !strings.HasPrefix(value, "sha256:") {
		return "", fmt.Errorf("%s must be a sha256 digest reference", context)
	}
	if _, err := admit.LowercaseSHA256(strings.TrimPrefix(value, "sha256:"), context); err != nil {
		return "", err
	}
	return value, nil
}

func countEquals(raw any, expected int) bool {
	if value, ok := raw.(int); ok {
		return value == expected
	}
	number, ok := raw.(json.Number)
	if !ok {
		return false
	}
	if expected == 0 {
		return admit.JSONNumberEquals(number, 0)
	}
	value, err := admit.PositiveInteger(number, "semantic diff count")
	return err == nil && value == expected
}
