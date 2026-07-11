package proofobligationalgebra

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestAnalyzeGraphHandlesDeepChainWithinBudget(t *testing.T) {
	const count = 256
	obligations := make([]obligationInput, 0, count)
	byID := make(map[string]obligationInput, count)
	for index := 0; index < count; index++ {
		id := fmt.Sprintf("proofkit.obligation.%04d", index)
		item := obligationInput{ObligationID: id}
		if index+1 < count {
			item.ChildObligationIDs = []string{fmt.Sprintf("proofkit.obligation.%04d", index+1)}
		}
		obligations = append(obligations, item)
		byID[id] = item
	}
	analysis, err := analyzeGraph(obligations, byID)
	if err != nil {
		t.Fatalf("analyzeGraph() error = %v", err)
	}
	rootID := "proofkit.obligation.0000"
	if analysis.depthByID[rootID] != count-1 || len(analysis.transitiveByID[rootID]) != count-1 {
		t.Fatalf("root analysis depth=%d closure=%d, want %d", analysis.depthByID[rootID], len(analysis.transitiveByID[rootID]), count-1)
	}
}

func TestAnalyzeGraphRejectsTransitiveProjectionBeyondBudget(t *testing.T) {
	const count = 400
	obligations := make([]obligationInput, 0, count)
	byID := make(map[string]obligationInput, count)
	for index := 0; index < count; index++ {
		id := fmt.Sprintf("proofkit.obligation.%04d", index)
		item := obligationInput{ObligationID: id}
		if index+1 < count {
			item.ChildObligationIDs = []string{fmt.Sprintf("proofkit.obligation.%04d", index+1)}
		}
		obligations = append(obligations, item)
		byID[id] = item
	}
	if _, err := analyzeGraph(obligations, byID); err == nil || !strings.Contains(err.Error(), "transitive output exceeds") {
		t.Fatalf("analyzeGraph() error = %v, want bounded-output rejection", err)
	}
}

func TestAnalyzeGraphPreservesUndeclaredChildProjection(t *testing.T) {
	root := obligationInput{ObligationID: "proofkit.obligation.root", ChildObligationIDs: []string{"proofkit.obligation.missing"}}
	analysis, err := analyzeGraph([]obligationInput{root}, map[string]obligationInput{root.ObligationID: root})
	if err != nil {
		t.Fatalf("analyzeGraph() error = %v", err)
	}
	if analysis.depthByID[root.ObligationID] != 1 || !equalStrings(analysis.transitiveByID[root.ObligationID], []string{"proofkit.obligation.missing"}) {
		t.Fatalf("analysis=%#v, want missing child depth and projection", analysis)
	}
}

func TestAnalyzeGraphMarksOnlyCycleMembers(t *testing.T) {
	items := []obligationInput{
		{ObligationID: "proofkit.obligation.ancestor", ChildObligationIDs: []string{"proofkit.obligation.left"}},
		{ObligationID: "proofkit.obligation.left", ChildObligationIDs: []string{"proofkit.obligation.right"}},
		{ObligationID: "proofkit.obligation.right", ChildObligationIDs: []string{"proofkit.obligation.left"}},
	}
	byID := map[string]obligationInput{}
	for _, item := range items {
		byID[item.ObligationID] = item
	}
	analysis, err := analyzeGraph(items, byID)
	if err != nil {
		t.Fatalf("analyzeGraph() error = %v", err)
	}
	if analysis.blockedByCycle["proofkit.obligation.ancestor"] {
		t.Fatal("acyclic ancestor was classified as a cycle member")
	}
	if !analysis.blockedByCycle["proofkit.obligation.left"] || !analysis.blockedByCycle["proofkit.obligation.right"] {
		t.Fatalf("cycle members not classified: %#v", analysis.blockedByCycle)
	}
}

func TestAnalyzeGraphMatchesReferenceForDeterministicAcyclicCorpus(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	for sample := 0; sample < 64; sample++ {
		count := 2 + random.Intn(18)
		items := make([]obligationInput, 0, count)
		byID := map[string]obligationInput{}
		for index := 0; index < count; index++ {
			item := obligationInput{ObligationID: fmt.Sprintf("proofkit.obligation.%02d", index)}
			for child := index + 1; child < count; child++ {
				if random.Intn(4) == 0 {
					item.ChildObligationIDs = append(item.ChildObligationIDs, fmt.Sprintf("proofkit.obligation.%02d", child))
				}
			}
			if random.Intn(8) == 0 {
				item.ChildObligationIDs = append(item.ChildObligationIDs, fmt.Sprintf("proofkit.missing.%02d", index))
			}
			sort.Strings(item.ChildObligationIDs)
			items = append(items, item)
			byID[item.ObligationID] = item
		}
		analysis, err := analyzeGraph(items, byID)
		if err != nil {
			t.Fatalf("sample %d analyzeGraph() error = %v", sample, err)
		}
		for _, item := range items {
			wantDepth := referenceGraphDepth(item.ObligationID, byID, map[string]struct{}{})
			wantClosure := referenceTransitiveIDs(item.ObligationID, byID)
			if analysis.depthByID[item.ObligationID] != wantDepth || !equalStrings(analysis.transitiveByID[item.ObligationID], wantClosure) {
				t.Fatalf("sample %d id=%s depth=%d/%d closure=%v/%v", sample, item.ObligationID, analysis.depthByID[item.ObligationID], wantDepth, analysis.transitiveByID[item.ObligationID], wantClosure)
			}
		}
	}
}

func referenceGraphDepth(id string, byID map[string]obligationInput, visited map[string]struct{}) int {
	item, ok := byID[id]
	if !ok || len(item.ChildObligationIDs) == 0 {
		return 0
	}
	if _, seen := visited[id]; seen {
		return 0
	}
	visited[id] = struct{}{}
	maxDepth := 0
	for _, childID := range item.ChildObligationIDs {
		childVisited := map[string]struct{}{}
		for key := range visited {
			childVisited[key] = struct{}{}
		}
		if depth := referenceGraphDepth(childID, byID, childVisited); depth > maxDepth {
			maxDepth = depth
		}
	}
	return 1 + maxDepth
}

func referenceTransitiveIDs(id string, byID map[string]obligationInput) []string {
	seen := map[string]struct{}{}
	queue := append([]string(nil), byID[id].ChildObligationIDs...)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, exists := seen[current]; exists {
			continue
		}
		seen[current] = struct{}{}
		if child, ok := byID[current]; ok {
			queue = append(queue, child.ChildObligationIDs...)
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestBuildAdmitsAtomicObligationAndRejectsMissingRoute(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.102661548092694621144975813646090608936469525015523708393935225916992472621290")
	input := validProofObligationAlgebraInput()
	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}
	encoded, _ := json.Marshal(record.JSONValue())
	if !strings.Contains(string(encoded), `"routeBearing":true`) {
		t.Fatalf("Build() output=%s, want routeBearing diagnostic", encoded)
	}
	if strings.Contains(string(encoded), "proofBearing") {
		t.Fatalf("Build() output=%s, must not claim proofBearing diagnostic", encoded)
	}

	input = validProofObligationAlgebraInput()
	input["obligations"].([]any)[0].(map[string]any)["proofRouteRefs"] = []any{}
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build(mutated) error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build(mutated) exit=%d state=%s, want failed", exitCode, record.State)
	}
}

func validProofObligationAlgebraInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"algebraId":     "proofkit.test.algebra",
		"obligations": []any{
			map[string]any{
				"obligationId":       "proofkit.test.obligation",
				"obligationKind":     "atomic",
				"requirementId":      "REQ-PROOFKIT-TEST-001",
				"owner":              "proofkit.test.owner",
				"proofRouteRefs":     []any{"proofkit.test.route"},
				"childObligationIds": []any{},
				"conditionRefs":      []any{},
				"delegationRefs":     []any{},
				"evidenceRefs":       []any{"artifacts/proofkit/test.json"},
				"expiryRef":          nil,
				"reviewConditionRef": nil,
				"rationale":          "test route is required",
				"nonClaims":          []any{"Proof obligation test input does not execute witnesses."},
			},
		},
		"nonClaims": []any{"Proof obligation algebra test input is not merge proof."},
	}
}
