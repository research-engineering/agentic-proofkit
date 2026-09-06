package requirementbrowser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/browserfixture"
)

func coverageWorkspaceFixture(t *testing.T, mode string, empty bool) map[string]any {
	t.Helper()
	value, err := browserfixture.CoverageWorkspace(mode, empty)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestWorkspaceCoveragePairedModesPreserveWholeOwnerRows(t *testing.T) {
	for _, mode := range []string{"compact", "structured"} {
		t.Run(mode, func(t *testing.T) {
			input := coverageWorkspaceFixture(t, mode, false)
			session, _, err := buildWorkspace(input)
			if err != nil {
				t.Fatal(err)
			}
			handle, capability := startWorkspaceTestServer(t, input, false)
			response := postWorkspaceJSON(t, handle.URL+"api/v1/coverage", capability, map[string]any{
				"requestId": "coverage.paired", "snapshotId": handle.SnapshotID, "query": map[string]any{"maxRecords": json.Number("1")},
			})
			projection := response["projection"].(map[string]any)
			if projection["proofMode"] != mode || projection["coverageAuthority"] != "lookup_fragment_only" || session.Manifest["coverageAvailable"] != true {
				t.Fatal("browser mode or coverage boundary changed")
			}
			assertWorkspaceRowIDs(t, projection["requirements"], "requirementId", []string{"REQ-BROWSER-COVERAGE-001"})
			got := projection["requirements"].([]any)[0].(map[string]any)["coverage"]
			want := session.Snapshot.Coverage["requirementCoverage"].([]any)[0]
			if !reflect.DeepEqual(got, want) {
				t.Fatal("bounded browser projection lost a nested owner field")
			}
			for key, want := range map[string]int{
				"availableRequirementCount": 2, "matchingRequirementCount": 2, "selectedRequirementCount": 1,
				"matchingReportedRequirementCount": 1, "matchingNotReportedRequirementCount": 1,
				"filteredOutRequirementCount": 0, "pageOmittedRequirementCount": 1, "omittedRequirementCount": 1,
			} {
				if projection[key] != json.Number(fmt.Sprint(want)) {
					t.Fatalf("%s = %v, want %d", key, projection[key], want)
				}
			}
			anchor := projection["requirements"].([]any)[0].(map[string]any)["anchor"].(map[string]any)
			if anchor["jsonPointer"] != "/projections/requirementSources/1/requirements/0/invariant" {
				t.Fatal("coverage page rebased its source anchor")
			}
			selected := map[string]struct{}{"REQ-BROWSER-COVERAGE-001": {}}
			fragment := requirementcoverageview.SelectRequirements(session.Snapshot.Coverage, selected)
			assertOriginalCoverageFragmentKeys(t, fragment)
			slice, err := requirementcontext.SliceSnapshot(session.Snapshot, map[string]any{"profile": "review", "requirementIds": []any{"REQ-BROWSER-COVERAGE-001"}}, "test.coverage.review")
			if err != nil {
				t.Fatal(err)
			}
			assertOriginalCoverageFragmentKeys(t, slice["projections"].(map[string]any)["coverage"].(map[string]any))
			packet := postWorkspaceJSON(t, handle.URL+"api/v1/handoff", capability, map[string]any{
				"annotations": []any{map[string]any{"anchorId": "requirement:REQ-BROWSER-COVERAGE-001:invariant", "startCodePoint": 0, "endCodePoint": 8, "exactQuote": "Coverage", "question": "Which evidence is declared?"}},
			})
			assertOriginalCoverageFragmentKeys(t, packet["context"].(map[string]any)["projections"].(map[string]any)["coverage"].(map[string]any))
			fragment["requirementCoverage"].([]any)[0].(map[string]any)["tests"].([]any)[0].(map[string]any)["nonClaims"] = []any{"Changed local clone."}
			if reflect.DeepEqual(fragment["requirementCoverage"].([]any)[0], want) {
				t.Fatal("detachment falsifier did not change its local row")
			}
			if !reflect.DeepEqual(session.Snapshot.Coverage["requirementCoverage"].([]any)[0], got) {
				t.Fatal("selected fragment aliases the owner snapshot")
			}
		})
	}
}

func assertOriginalCoverageFragmentKeys(t *testing.T, fragment map[string]any) {
	t.Helper()
	keys := make([]string, 0, len(fragment))
	for key := range fragment {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	want := []string{"authority", "nonClaims", "requirementCoverage", "requirementCoverageCount", "schemaVersion", "sourceViewInputId", "viewKind"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("shared fragment contract changed: %v", keys)
	}
}

func TestWorkspaceCoverageFiltersBeforeCountingAndBytePaging(t *testing.T) {
	session, _, err := buildWorkspace(coverageWorkspaceFixture(t, "compact", false))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		query             map[string]any
		id                string
		reported, missing int
	}{
		{map[string]any{"offset": json.Number("1")}, "REQ-CONSUMER-001", 1, 1},
		{map[string]any{"ownerId": "browser.fixture.owner"}, "REQ-CONSUMER-001", 0, 1},
		{map[string]any{"searchText": "Coverage browser"}, "REQ-BROWSER-COVERAGE-001", 1, 0},
	} {
		query, err := admitWorkspaceLookupQuery(row.query, session.Lookup)
		if err != nil {
			t.Fatal(err)
		}
		page := workspaceCoveragePage(&session, query)
		encoded, err := page.encode("coverage.page", session.SnapshotID, maxWorkspaceLookupResponseBytes)
		if err != nil {
			t.Fatal(err)
		}
		response, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
		if err != nil {
			t.Fatal(err)
		}
		projection := response.(map[string]any)["projection"].(map[string]any)
		assertWorkspaceRowIDs(t, projection["requirements"], "requirementId", []string{row.id})
		if projection["matchingReportedRequirementCount"] != json.Number(fmt.Sprint(row.reported)) || projection["matchingNotReportedRequirementCount"] != json.Number(fmt.Sprint(row.missing)) {
			t.Fatal("coverage counted the retained page instead of the filtered cohort")
		}
		if row.id == "REQ-CONSUMER-001" && projection["requirements"].([]any)[0].(map[string]any)["coverage"] != nil {
			t.Fatal("missing row was converted into a coverage verdict")
		}
	}
	page := workspaceCoveragePage(&session, workspaceLookupQuery{Page: projectionQuery{MaxRecords: 2}})
	full, err := page.encode("coverage.bytes", session.SnapshotID, maxWorkspaceLookupResponseBytes)
	if err != nil {
		t.Fatal(err)
	}
	bounded, err := page.encode("coverage.bytes", session.SnapshotID, len(full)-1)
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(bounded), int64(len(bounded)))
	if err != nil {
		t.Fatal(err)
	}
	projection := value.(map[string]any)["projection"].(map[string]any)
	if len(bounded) >= len(full) || projection["selectedRequirementCount"] != json.Number("1") {
		t.Fatal("encoded budget failed to retain exactly one whole row")
	}
	got := projection["requirements"].([]any)[0].(map[string]any)["coverage"]
	if !reflect.DeepEqual(got, session.Snapshot.Coverage["requirementCoverage"].([]any)[0]) {
		t.Fatal("byte cut truncated a row")
	}
	if _, err := page.encode("coverage.bytes", session.SnapshotID, 1); err == nil {
		t.Fatal("oversized metadata admitted")
	}
}

func TestWorkspaceCoverageAbsentAndAdmittedZeroRemainDistinct(t *testing.T) {
	for _, mode := range []string{"compact", "structured"} {
		session, _, err := buildWorkspace(coverageWorkspaceFixture(t, mode, true))
		if err != nil {
			t.Fatal(err)
		}
		page := workspaceCoveragePage(&session, workspaceLookupQuery{Page: projectionQuery{MaxRecords: 2}})
		projection, _ := page.Projection([]any{page.Row(0)})
		if session.Manifest["coverageAvailable"] != true || projection["proofMode"] != mode || projection["matchingReportedRequirementCount"] != 0 || projection["matchingNotReportedRequirementCount"] != 1 {
			t.Fatal("zero-row projection was treated as unavailable")
		}
	}
	session, _, err := buildWorkspace(workspaceFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if session.Manifest["coverageAvailable"] != false {
		t.Fatal("absent coverage became available")
	}
	handle, capability := startWorkspaceTestServer(t, workspaceFixture(t), false)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/coverage", strings.NewReader(fmt.Sprintf(`{"query":{},"requestId":"coverage.absent","snapshotId":%q}`, handle.SnapshotID)))
	request.Header.Set("Origin", "http://workspace.local")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Proofkit-Browser-Capability", capability)
	response := httptest.NewRecorder()
	serveWorkspaceRequirements(response, request, "http://workspace.local", capability, &session)
	if response.Code != http.StatusNotFound {
		t.Fatalf("absent coverage status %d", response.Code)
	}
	slice, err := requirementcontext.SliceSnapshot(session.Snapshot, map[string]any{"profile": "review", "requirementIds": []any{"REQ-CONSUMER-001"}}, "test.absent.review")
	if err != nil {
		t.Fatal(err)
	}
	if _, present := slice["projections"].(map[string]any)["coverage"]; present {
		t.Fatal("review invented absent coverage")
	}
	packet := postWorkspaceJSON(t, handle.URL+"api/v1/handoff", capability, map[string]any{"annotations": []any{map[string]any{"anchorId": "requirement:REQ-CONSUMER-001:invariant", "startCodePoint": 0, "endCodePoint": 3, "exactQuote": "The", "question": "What is declared?"}}})
	if _, present := packet["context"].(map[string]any)["projections"].(map[string]any)["coverage"]; present {
		t.Fatal("handoff invented absent coverage")
	}
}
