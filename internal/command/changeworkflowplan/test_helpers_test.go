package changeworkflowplan

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const testDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

func initialInput() map[string]any {
	return map[string]any{
		"checkpoint":              map[string]any{"state": "not_started"},
		"completedStageIds":       []any{},
		"contextRefs":             []any{},
		"governingAuthorityRefId": nil,
		"requiredContextRefIds":   []any{},
		"schemaVersion":           json.Number("1"),
	}
}

func contextValue(id string, kind string, digest string, dependencies []string) map[string]any {
	return map[string]any{
		"artifactPath":     "evidence/" + id + ".json",
		"dependencyRefIds": stringsValue(dependencies),
		"refId":            id,
		"refKind":          kind,
		"subjectDigest":    digest,
	}
}

func reviewInput(state string) map[string]any {
	input := initialInput()
	input["contextRefs"] = []any{
		contextValue("ctx.artifact", "artifact", testDigest, nil),
		contextValue("ctx.authority", "authority", "sha256:1111111111111111111111111111111111111111111111111111111111111111", nil),
		contextValue("ctx.finding", "finding", "sha256:3333333333333333333333333333333333333333333333333333333333333333", nil),
	}
	input["governingAuthorityRefId"] = "ctx.authority"
	checkpointValue := map[string]any{"state": state, "subjectDigest": testDigest, "subjectRefId": "ctx.artifact"}
	if state == "review_findings" || state == "review_passed" {
		checkpointValue["assessmentSubjectDigest"] = testDigest
	}
	if state == "review_findings" {
		checkpointValue["findingRefs"] = []any{"ctx.finding"}
	}
	input["checkpoint"] = checkpointValue
	return input
}

func inputForStage(stageIndex int, checkpointState string) map[string]any {
	input := initialInput()
	completed := make([]any, stageIndex)
	for index := 0; index < stageIndex; index++ {
		completed[index] = stageTable[index].ID
	}
	input["completedStageIds"] = completed
	if checkpointState != "not_started" {
		input = reviewInput(checkpointState)
		input["completedStageIds"] = completed
	}
	return input
}

func terminalInput() map[string]any {
	input := initialInput()
	input["completedStageIds"] = stringsValue(stageIDs())
	input["checkpoint"] = nil
	return input
}

func stageIDs() []string {
	result := make([]string, len(stageTable))
	for index, stage := range stageTable {
		result[index] = stage.ID
	}
	return result
}

func requireBuild(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	result, err := Build(input)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	return result
}

func requireReject(t *testing.T, input map[string]any) error {
	t.Helper()
	_, err := Build(input)
	if err == nil {
		t.Fatal("Build unexpectedly admitted invalid input")
	}
	return err
}

func canonical(t *testing.T, value any) string {
	t.Helper()
	encoded, err := stablejson.MarshalLayout(value, stablejson.LayoutCompact)
	if err != nil {
		t.Fatalf("stable JSON: %v", err)
	}
	return string(encoded)
}

func cloneMap(value map[string]any) map[string]any {
	return cloneValue(value).(map[string]any)
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			result[key] = cloneValue(child)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = cloneValue(child)
		}
		return result
	default:
		return typed
	}
}

func requireEqual(t *testing.T, got any, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mismatch\ngot:  %s\nwant: %s", canonical(t, got), canonical(t, want))
	}
}

func containsANSI(value string) bool { return strings.Contains(value, "\x1b[") }
