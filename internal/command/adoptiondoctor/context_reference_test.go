package adoptiondoctor

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
)

func TestDoctorEnvelopePreservesWireContextPaths(t *testing.T) {
	for _, path := range []struct{ name, prefix string }{
		{"task_names", "docs/task-"},
		{"risk_names", "docs/risk-"},
		{"long_paths", strings.Repeat("segment/", 70) + "task-"},
	} {
		t.Run(path.name, func(t *testing.T) {
			input := completeInput()
			input["childReports"] = []any{}
			route := input["ownerRoutes"].([]any)[0].(map[string]any)
			want := map[string]string{}
			for index, field := range []string{"specPaths", "proofBindingPaths", "nativeWitnessRefs"} {
				value := path.prefix + field + ".json"
				route[field] = []any{value}
				want[fmt.Sprintf("owner_route.%s.context.%03d", route["routeId"], index+1)] = value
			}
			candidate := baseInput()["modernization"].(map[string]any)["candidateBoundaries"].([]any)[0].(map[string]any)
			candidate["admissionState"] = "owner_admitted"
			candidate["proofBindingRefs"] = route["proofBindingPaths"]
			candidate["nativeWitnessRefs"] = route["nativeWitnessRefs"]
			candidatePath := path.prefix + "candidate.ts"
			candidate["affectedPaths"] = []any{candidatePath}
			input["modernization"] = map[string]any{"candidateBoundaries": []any{candidate}}
			want["candidate_boundary."+candidate["boundaryId"].(string)+".context.001"] = candidatePath
			want["candidate_boundary."+candidate["boundaryId"].(string)+".context.002"] = route["nativeWitnessRefs"].([]any)[0].(string)
			want["candidate_boundary."+candidate["boundaryId"].(string)+".context.003"] = route["proofBindingPaths"].([]any)[0].(string)
			authorityPath := path.prefix + "authority.md"
			input["staleAuthority"] = staleAuthorityInput("current", authorityPath, "")
			surface := input["staleAuthority"].(map[string]any)["authoritySurfaces"].([]any)[0].(map[string]any)
			surface["matchedVocabularyIds"] = []any{}
			want["stale_authority_surface."+surface["surfaceId"].(string)+".context.001"] = authorityPath
			if path.name == "long_paths" {
				for _, value := range want {
					if len(value) <= 512 {
						t.Fatal("context path does not cross the scalar truncation boundary")
					}
				}
			}
			wire, code := wireDoctorEnvelope(t, input)
			if code != 0 {
				t.Fatalf("complete doctor envelope: exit=%d", code)
			}
			if wire["sourceReport"].(map[string]any)["state"] != "passed" {
				t.Fatal("complete fixture did not reach a passed doctor envelope")
			}
			contexts := wire["contextRefs"].([]any)
			if len(contexts) != len(want) || len(wire["omitted"].([]any)) != 0 || len(wire["commands"].([]any)) != 1 {
				t.Fatalf("complete doctor context/command inventory changed: refs=%d want=%d omitted=%v", len(contexts), len(want), wire["omitted"])
			}
			seenKinds := map[string]bool{}
			for _, raw := range contexts {
				ref := raw.(map[string]any)
				id, ok := ref["refId"].(string)
				value, exists := want[id]
				if !ok || !exists || ref["path"] != value {
					t.Fatalf("context path was altered, duplicated, or invented: %#v", ref)
				}
				delete(want, id)
				seenKinds[ref["kind"].(string)] = true
			}
			if len(want) != 0 || !seenKinds["owner_route"] || !seenKinds["candidate_boundary"] || !seenKinds["stale_authority_surface"] {
				t.Fatal("doctor did not preserve every context-producing family")
			}
			assertDoctorReferenceClosure(t, wire, input["doctorId"].(string))
		})
	}
}

func TestDoctorGapActionsLinkExactContextCatalog(t *testing.T) {
	for _, prefix := range []string{"docs/task-", strings.Repeat("segment/", 70) + "task-"} {
		t.Run(fmt.Sprintf("prefix_bytes_%d", len(prefix)), func(t *testing.T) {
			input := completeInput()
			route := input["ownerRoutes"].([]any)[0].(map[string]any)
			route["commands"] = []any{} // Exercise a real route GAP with all structural families present.
			candidate := baseInput()["modernization"].(map[string]any)["candidateBoundaries"].([]any)[0].(map[string]any)
			candidate["blockedPreconditions"] = []any{"Caller approval pending."}
			candidate["observedFacts"] = []any{"Caller\u202e descriptive fact."}
			candidate["ownerQuestions"] = []any{"Caller\u202e descriptive question?"}
			candidate["uncertainties"] = []any{strings.Repeat("descriptive ", 60)}
			input["modernization"] = map[string]any{"candidateBoundaries": []any{candidate}}
			child := input["childReports"].([]any)[0].(map[string]any)
			child["state"] = "failed"
			blocked := map[string]any{"preconditionId": "consumer.external", "owner": "consumer.external-owner",
				"reason": "Caller precondition pending.", "nonClaim": "Caller-owned evidence only."}
			input["blockedPreconditions"] = []any{blocked}
			input["staleAuthority"] = staleAuthorityInput("current", prefix+"authority.md", "")
			surface := input["staleAuthority"].(map[string]any)["authoritySurfaces"].([]any)[0].(map[string]any)

			type reference struct{ kind, source, role, path string }
			want := map[reference]bool{}
			add := func(record map[string]any, field, idField, kind, role string) {
				paths := []any{prefix + kind + "-" + field + "-a.json", prefix + kind + "-" + field + "-b.json"}
				record[field] = paths
				for _, path := range paths {
					want[reference{kind, record[idField].(string), role, path.(string)}] = true
				}
				if len(prefix) > 512 && (len(paths[0].(string)) <= 512 || paths[0].(string)[:512] != paths[1].(string)[:512]) {
					t.Fatal("long references do not share a prefix beyond the scalar truncation boundary")
				}
			}
			for field, role := range map[string]string{"specPaths": "spec_path", "proofBindingPaths": "proof_binding", "nativeWitnessRefs": "native_witness"} {
				add(route, field, "routeId", "owner_route", role)
			}
			for field, role := range map[string]string{"affectedPaths": "affected_path", "contractWitnessRefs": "contract_witness", "nativeWitnessRefs": "native_witness", "proofBindingRefs": "proof_binding"} {
				add(candidate, field, "boundaryId", "candidate_boundary", role)
			}
			add(child, "evidenceRefs", "reportId", "child_report", "evidence")
			add(blocked, "evidenceRefs", "preconditionId", "blocked_precondition", "evidence")
			add(surface, "evidenceRefs", "surfaceId", "stale_authority_surface", "evidence")
			want[reference{"stale_authority_surface", surface["surfaceId"].(string), "authority_path", surface["path"].(string)}] = true

			envelope, code := wireDoctorEnvelope(t, input)
			if code != 1 || envelope["sourceReport"].(map[string]any)["state"] != "blocked" || len(envelope["actionPlan"].([]any)) != 6 {
				t.Fatal("fixture did not exercise the six intended GAP actions")
			}
			if len(envelope["omitted"].([]any)) != 0 || envelope["bounds"].(map[string]any)["fanout"] != "bounded" {
				t.Fatalf("admitted structural references were degraded: %v", envelope["bounds"])
			}
			for _, raw := range envelope["contextRefs"].([]any) {
				ref := raw.(map[string]any)
				key := reference{ref["kind"].(string), ref["sourceId"].(string), ref["role"].(string), ref["path"].(string)}
				if !want[key] {
					t.Fatalf("context lost exact path, provenance or role, or was duplicated: %#v", ref)
				}
				delete(want, key)
			}
			if len(want) != 0 {
				t.Fatalf("missing structural contexts: %#v", want)
			}
			assertDoctorReferenceClosure(t, envelope, input["doctorId"].(string))
			for _, row := range []struct{ step, source, kind string }{
				{"consumer.example-route.missing_command_route", route["routeId"].(string), "owner_route"},
				{"consumer.example-boundary.candidate-boundary-not-admitted", candidate["boundaryId"].(string), "candidate_boundary"},
				{"consumer.example-boundary.blocked-precondition", candidate["boundaryId"].(string), "candidate_boundary"},
				{"consumer.source-admission.failed", child["reportId"].(string), "child_report"},
				{"consumer.external", blocked["preconditionId"].(string), "blocked_precondition"},
				{"consumer.proofkit-delivery-adr.stale-authority-current-vocabulary", surface["surfaceId"].(string), "stale_authority_surface"},
			} {
				action := findAction(t, envelope["actionPlan"].([]any), row.step)
				wantIDs := []any{}
				for _, raw := range envelope["contextRefs"].([]any) {
					ref := raw.(map[string]any)
					if ref["sourceId"] == row.source && ref["kind"] == row.kind {
						wantIDs = append(wantIDs, ref["refId"])
					}
				}
				if len(wantIDs) == 0 || !reflect.DeepEqual(action["evidenceRefs"], wantIDs) {
					t.Fatalf("gap %s lost its exact source contexts: got=%v want=%v", row.step, action["evidenceRefs"], wantIDs)
				}
			}
			candidateAction := findAction(t, envelope["actionPlan"].([]any), "consumer.example-boundary.candidate-boundary-not-admitted")
			if candidateAction["observedFact"] != admit.DiagnosticRedactionMarker || candidateAction["ownerQuestions"].([]any)[0] != admit.DiagnosticRedactionMarker {
				t.Fatal("structural context preservation bypassed descriptive-text scalar redaction")
			}
			if candidateAction["uncertainty"] == candidate["uncertainties"].([]any)[0] || !strings.Contains(candidateAction["uncertainty"].(string), "<truncated-diagnostic>") {
				t.Fatal("long descriptive text bypassed scalar truncation")
			}
			second, _ := wireDoctorEnvelope(t, input)
			if !reflect.DeepEqual(envelope, second) {
				t.Fatal("context/action linkage is not deterministic")
			}
		})
	}
}

func TestDoctorContextCatalogDoesNotMutateCallerSliceCapacity(t *testing.T) {
	result, err := BuildResult(decodeInput(t, completeInput()))
	if err != nil {
		t.Fatal(err)
	}
	backing := []string{"proofkit/binding.json", "caller-owned-spare-a", "caller-owned-spare-b"}
	before := slices.Clone(backing)
	result.Input.OwnerRoutes[0].ProofBindingPaths = backing[:1]
	result.Input.OwnerRoutes[0].NativeWitnessRefs = []string{"tests/native-a.go", "tests/native-b.go"}
	envelope := AgentEnvelope(result)
	if !slices.Equal(backing, before) {
		t.Fatalf("context projection mutated caller spare capacity: got=%v want=%v", backing, before)
	}
	paths := []string{}
	for _, raw := range envelope["contextRefs"].([]any) {
		ref := raw.(map[string]any)
		if ref["kind"] == "owner_route" {
			paths = append(paths, ref["path"].(string))
		}
	}
	if !slices.Equal(paths, []string{"docs/specs/example/requirements.v1.json", "proofkit/binding.json", "tests/native-a.go", "tests/native-b.go"}) {
		t.Fatalf("alias-safe projection lost structural references: %v", paths)
	}
}

func TestDoctorContextCatalogReservesSourceReportIdentity(t *testing.T) {
	for _, item := range []struct {
		name, doctorID string
		gaps           bool
	}{
		{"source_and_route_gaps", "owner_route.r.context.001", true},
		{"no_gaps", "owner_route.r.context.001", false},
		{"second_local_identity", "owner_route.r.context.002", true},
		{"ordinary_gaps", "consumer.adoption-doctor", true},
		{"ordinary_no_gaps", "consumer.adoption-doctor", false},
		{"source_ends_in_local", "owner_route.r.context.001.local", true},
	} {
		t.Run(item.name, func(t *testing.T) {
			input := doctorSourceCollisionInput("r", item.doctorID, item.gaps)
			envelope, code := wireDoctorEnvelope(t, input)
			if code != 0 || len(envelope["omitted"].([]any)) != 0 || envelope["bounds"].(map[string]any)["fanout"] != "bounded" {
				t.Fatalf("source/local collision was refused or silently degraded: code=%d bounds=%v omitted=%v", code, envelope["bounds"], envelope["omitted"])
			}
			assertDoctorReferenceClosure(t, envelope, item.doctorID)
			if envelope["sourceReport"].(map[string]any)["reportId"] != item.doctorID {
				t.Fatal("source report identity was renamed instead of reserving it")
			}
			wantPaths := []string{"docs/a", "proofkit/requirement-bindings.json"}
			wantRoles := []string{contextRoleSpecPath, contextRoleProofBinding}
			if !item.gaps {
				wantPaths = append(wantPaths, "internal/command/adoptiondoctor/adoptiondoctor_test.go")
				wantRoles = append(wantRoles, contextRoleNativeWitness)
			}
			wantIDs := []any{}
			for index := range wantPaths {
				id := fmt.Sprintf("owner_route.r.context.%03d", index+1)
				if id == item.doctorID {
					id += ".local"
				}
				wantIDs = append(wantIDs, id)
			}
			contexts := envelope["contextRefs"].([]any)
			if len(contexts) != len(wantPaths) {
				t.Fatalf("context count=%d want %d", len(contexts), len(wantPaths))
			}
			for index, raw := range contexts {
				ref := raw.(map[string]any)
				if ref["refId"] != wantIDs[index] || ref["kind"] != recordKindOwnerRoute || ref["sourceId"] != "r" || ref["role"] != wantRoles[index] || ref["path"] != wantPaths[index] || ref["owner"] != "consumer.repository" {
					t.Fatalf("local context identity, origin, role or path changed: %#v", ref)
				}
			}
			if item.gaps {
				if len(envelope["actionPlan"].([]any)) != 2 {
					t.Fatal("fixture must exercise exactly the source and native-witness gaps")
				}
				sourceAction := findAction(t, envelope["actionPlan"].([]any), "proofkit.adoption-doctor."+item.doctorID+".missing-touched-owner-route")
				routeAction := findAction(t, envelope["actionPlan"].([]any), "proofkit.adoption-doctor.r.missing_native_witness")
				if !reflect.DeepEqual(sourceAction["evidenceRefs"], []any{item.doctorID}) || !reflect.DeepEqual(routeAction["evidenceRefs"], wantIDs) {
					t.Fatalf("source and local gap meanings were aliased: source=%v route=%v", sourceAction["evidenceRefs"], routeAction["evidenceRefs"])
				}
			} else {
				if len(envelope["actionPlan"].([]any)) != 1 {
					t.Fatal("no-gap fixture must retain its single source-report action")
				}
				action := findAction(t, envelope["actionPlan"].([]any), noGapsRuleID)
				if !reflect.DeepEqual(action["evidenceRefs"], []any{item.doctorID}) {
					t.Fatal("no-gap action lost its original source-report reference")
				}
			}
			for _, raw := range envelope["routeQuestions"].([]any) {
				if !reflect.DeepEqual(raw.(map[string]any)["evidenceRefs"], []any{item.doctorID}) {
					t.Fatal("source-report question was rebound to a local context")
				}
			}
		})
	}
}

func TestDoctorSourceReportCollisionDegradesBeyondLocalIdentityLimit(t *testing.T) {
	for _, item := range []struct {
		name      string
		length    int
		collision bool
		degraded  bool
	}{
		{"suffix_at_limit", admit.MaxRuleIDBytes - len(".local"), true, false},
		{"suffix_exceeds_by_one", admit.MaxRuleIDBytes - len(".local") + 1, true, true},
		{"normal_id_at_limit", admit.MaxRuleIDBytes, true, true},
		{"ordinary_id_at_limit", admit.MaxRuleIDBytes, false, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			routeID := strings.Repeat("r", item.length-len("owner_route..context.001"))
			ordinaryID := "owner_route." + routeID + ".context.001"
			doctorID := "consumer.adoption-doctor"
			if item.collision {
				doctorID = ordinaryID
			}
			envelope, code := wireDoctorEnvelope(t, doctorSourceCollisionInput(routeID, doctorID, true))
			if code != 0 || envelope["sourceReport"].(map[string]any)["reportId"] != doctorID {
				t.Fatal("length-bound projection changed the source report or advisory outcome")
			}
			assertDoctorReferenceClosure(t, envelope, doctorID)
			sourceAction := findAction(t, envelope["actionPlan"].([]any), "proofkit.adoption-doctor."+doctorID+".missing-touched-owner-route")
			routeAction := findAction(t, envelope["actionPlan"].([]any), "proofkit.adoption-doctor."+routeID+".missing_native_witness")
			if !reflect.DeepEqual(sourceAction["evidenceRefs"], []any{doctorID}) {
				t.Fatal("source-report reference was pruned with the overlong local identity")
			}
			wantIDs := []any{"owner_route." + routeID + ".context.002"}
			if !item.degraded {
				id := ordinaryID
				if item.collision {
					id += ".local"
				}
				wantIDs = append([]any{id}, wantIDs...)
			}
			if !reflect.DeepEqual(routeAction["evidenceRefs"], wantIDs) {
				t.Fatalf("route evidence aliased the source, used a fallback, or retained an invalid identity: got=%v want=%v", routeAction["evidenceRefs"], wantIDs)
			}
			contexts := envelope["contextRefs"].([]any)
			if len(contexts) != len(wantIDs) {
				t.Fatalf("retained contexts=%d want %d", len(contexts), len(wantIDs))
			}
			for index, raw := range contexts {
				if raw.(map[string]any)["refId"] != wantIDs[index] {
					t.Fatalf("unexpected retained context: %#v", raw)
				}
			}
			bounds := envelope["bounds"].(map[string]any)
			cost := envelope["costContract"].(map[string]any)
			omitted := envelope["omitted"].([]any)
			if item.degraded {
				pruned, ok := cost["prunedLocalReferenceCount"].(json.Number)
				count, err := pruned.Int64()
				if !ok || err != nil || count <= 0 || len(omitted) == 0 || bounds["fanout"] != "wide_or_full_gate_required" || cost["referenceClosurePreserved"] != false {
					t.Fatalf("overlong collision did not explicitly degrade and prune: bounds=%v cost=%v omitted=%v", bounds, cost, omitted)
				}
				found := false
				for _, raw := range omitted {
					found = found || raw.(map[string]any)["omittedKind"] == "unsafeLocalIdentity"
				}
				if !found {
					t.Fatal("identity-bound failure has no explicit unsafe-local-identity omission")
				}
			} else if len(omitted) != 0 || bounds["fanout"] != "bounded" || cost["referenceClosurePreserved"] != true {
				t.Fatalf("legal local identity was degraded: bounds=%v cost=%v omitted=%v", bounds, cost, omitted)
			}
		})
	}
}

func TestDoctorContextCatalogPreservesInputAndNativeReport(t *testing.T) {
	result, err := BuildResult(decodeInput(t, doctorSourceCollisionInput("r", "owner_route.r.context.001", true)))
	if err != nil {
		t.Fatal(err)
	}
	nativeJSON := func() string {
		encoded, err := json.Marshal(map[string]any{"input": result.Input, "report": result.Record.JSONValue()})
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	before, gaps := nativeJSON(), slices.Clone(result.Gaps)
	AgentEnvelope(result)
	if after := nativeJSON(); after != before || !reflect.DeepEqual(result.Gaps, gaps) {
		t.Fatal("local identity reservation mutated input, gap origins, or native report JSON")
	}
	if strings.Contains(before, "owner_route.r.context.001.local") {
		t.Fatal("local envelope identity leaked into native report or input")
	}
}

func doctorSourceCollisionInput(routeID, doctorID string, gaps bool) map[string]any {
	input := completeInput()
	input["doctorId"], input["childReports"] = doctorID, []any{}
	route := input["ownerRoutes"].([]any)[0].(map[string]any)
	route["routeId"], route["specPaths"] = routeID, []any{"docs/a"}
	if gaps {
		route["touchedRuleIds"], route["nativeWitnessRefs"] = []any{}, []any{}
	}
	return input
}

func TestDoctorGapReferenceClosureAfterBoundsAndIdentityOmission(t *testing.T) {
	for _, name := range []string{"context_bounds", "evidence_bounds", "action_bounds", "unsafe_context_identity"} {
		t.Run(name, func(t *testing.T) {
			input := baseInput()
			route := input["ownerRoutes"].([]any)[0].(map[string]any)
			switch name {
			case "context_bounds", "evidence_bounds":
				count := 40
				if name == "context_bounds" {
					count = agentenvelope.MaxContextRefs + 7
				}
				paths := []any{}
				for index := range count {
					paths = append(paths, fmt.Sprintf("docs/task-spec-%03d.md", index))
				}
				route["specPaths"] = paths
			case "action_bounds":
				routes := []any{}
				for index := range agentenvelope.MaxActionItems + 3 {
					routes = append(routes, map[string]any{"routeId": fmt.Sprintf("consumer.route-%03d", index), "owner": "consumer.owner",
						"specPaths": []any{fmt.Sprintf("docs/task-route-%03d.md", index)}})
				}
				input["ownerRoutes"] = routes
			case "unsafe_context_identity":
				// The caller ID is legal; its derived context ID exceeds the local
				// identity bound and must be omitted without a raw-path fallback.
				route["routeId"] = "consumer." + strings.Repeat("r", 240)
			}
			envelope, code := wireDoctorEnvelope(t, input)
			if code != 0 || len(envelope["omitted"].([]any)) != 1 || envelope["bounds"].(map[string]any)["fanout"] != "wide_or_full_gate_required" {
				t.Fatalf("fixture did not report bounded advisory degradation: code=%d bounds=%v omitted=%v", code, envelope["bounds"], envelope["omitted"])
			}
			assertDoctorReferenceClosure(t, envelope, input["doctorId"].(string))
			if len(envelope["contextRefs"].([]any)) > agentenvelope.MaxContextRefs || len(envelope["actionPlan"].([]any)) > agentenvelope.MaxActionItems {
				t.Fatal("hard context/action bound exceeded")
			}
			evidenceCount := 0
			for _, raw := range envelope["actionPlan"].([]any) {
				evidenceCount += len(raw.(map[string]any)["evidenceRefs"].([]any))
			}
			if evidenceCount > agentenvelope.MaxActionEvidenceRefs {
				t.Fatal("hard action evidence bound exceeded")
			}
			if name == "context_bounds" && len(envelope["contextRefs"].([]any)) != agentenvelope.MaxContextRefs {
				t.Fatal("context bound falsifier did not fill the retained catalog")
			}
			if name == "evidence_bounds" && evidenceCount != agentenvelope.MaxActionEvidenceRefs {
				t.Fatal("evidence bound falsifier did not fill the retained reference budget")
			}
			if name == "action_bounds" && len(envelope["actionPlan"].([]any)) != agentenvelope.MaxActionItems {
				t.Fatal("action bound falsifier did not fill the retained action budget")
			}
		})
	}
}

func wireDoctorEnvelope(t *testing.T, input map[string]any) (map[string]any, int) {
	t.Helper()
	envelope, code, err := BuildEnvelope(decodeInput(t, input))
	if err != nil || envelope["envelopeId"] == "proofkit.agent-envelope.invalid-input" {
		t.Fatalf("doctor input unexpectedly refused: err=%v envelope=%v", err, envelope)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	return wire, code
}

func assertDoctorReferenceClosure(t *testing.T, envelope map[string]any, doctorID string) {
	t.Helper()
	contexts := map[string]bool{}
	for _, raw := range envelope["contextRefs"].([]any) {
		id := raw.(map[string]any)["refId"].(string)
		if id == doctorID {
			t.Fatalf("local context aliases the source report identity: %s", id)
		}
		if contexts[id] {
			t.Fatalf("duplicate retained context identity: %s", id)
		}
		contexts[id] = true
	}
	for _, field := range []string{"actionPlan", "blockedPreconditions", "clarificationQuestions", "routeQuestions"} {
		for _, raw := range envelope[field].([]any) {
			record := raw.(map[string]any)
			for _, ref := range record["evidenceRefs"].([]any) {
				if ref != doctorID && !contexts[ref.(string)] {
					t.Fatalf("%s has dangling or raw external evidence: %v", field, ref)
				}
			}
			if field == "actionPlan" {
				selectors := record["selectors"].(map[string]any)
				for key := range selectors {
					if !slices.Contains([]string{"ruleRefs", "ownerRouteId", "candidateBoundaryId"}, key) {
						t.Fatalf("selector duplicated context linkage or serialized a path: %s", key)
					}
				}
			}
		}
	}
	if err := EnvelopeShape(envelope["envelopeId"].(string)).CheckGenerated(envelope, "doctor envelope"); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorOriginsSeparateEqualIDsAcrossInputCollections(t *testing.T) {
	const sharedID = "consumer.shared"
	input := completeInput()
	route := input["ownerRoutes"].([]any)[0].(map[string]any)
	route["routeId"], route["owner"], route["commands"] = sharedID, "consumer.route-owner", []any{}
	candidate := baseInput()["modernization"].(map[string]any)["candidateBoundaries"].([]any)[0].(map[string]any)
	candidate["boundaryId"], candidate["candidateOwner"] = sharedID, "consumer.candidate-owner"
	candidate["contractWitnessRefs"] = []any{"tests/task-contract.go"}
	candidate["nativeWitnessRefs"] = []any{"tests/task-native.go"}
	candidate["proofBindingRefs"] = []any{"proofkit/task-bindings.json"}
	input["modernization"] = map[string]any{"candidateBoundaries": []any{candidate}}
	child := input["childReports"].([]any)[0].(map[string]any)
	child["reportId"], child["state"] = sharedID, "failed"
	input["blockedPreconditions"] = []any{map[string]any{"preconditionId": sharedID, "owner": "consumer.precondition-owner",
		"evidenceRefs": []any{"docs/task-precondition.md"}, "reason": "Caller approval pending.", "nonClaim": "Caller-owned evidence."}}
	input["staleAuthority"] = staleAuthorityInput("current", "docs/task-authority.md", "")
	surface := input["staleAuthority"].(map[string]any)["authoritySurfaces"].([]any)[0].(map[string]any)
	surface["surfaceId"], surface["evidenceRefs"] = sharedID, []any{"docs/task-authority-evidence.md"}

	envelope, code := wireDoctorEnvelope(t, input)
	if code != 1 || envelope["sourceReport"].(map[string]any)["state"] != "blocked" || len(envelope["omitted"].([]any)) != 0 || envelope["bounds"].(map[string]any)["fanout"] != "bounded" {
		t.Fatalf("equal IDs in different collections were aliased or degraded: code=%d bounds=%v omitted=%v", code, envelope["bounds"], envelope["omitted"])
	}
	assertDoctorReferenceClosure(t, envelope, input["doctorId"].(string))
	wantCounts := map[string]int{"owner_route": 3, "candidate_boundary": 4, "child_report": 1, "blocked_precondition": 1, "stale_authority_surface": 2}
	idsByKind := map[string][]any{}
	for _, raw := range envelope["contextRefs"].([]any) {
		ref := raw.(map[string]any)
		kind := ref["kind"].(string)
		if ref["sourceId"] != sharedID || !strings.HasPrefix(ref["refId"].(string), kind+"."+sharedID+".context.") {
			t.Fatalf("context identity omitted input-record kind or changed caller ID: %#v", ref)
		}
		idsByKind[kind] = append(idsByKind[kind], ref["refId"])
	}
	if len(idsByKind) != len(wantCounts) || len(envelope["actionPlan"].([]any)) != len(wantCounts) {
		t.Fatal("fixture did not exercise all five equal-ID input collections")
	}
	for _, row := range []struct{ kind, suffix, owner, selector string }{
		{"owner_route", ".missing_command_route", "consumer.route-owner", "ownerRouteId"},
		{"candidate_boundary", ".candidate-boundary-not-admitted", "consumer.candidate-owner", "candidateBoundaryId"},
		{"child_report", ".failed", "consumer_repository", ""},
		{"blocked_precondition", "", "consumer.precondition-owner", ""},
		{"stale_authority_surface", ".stale-authority-current-vocabulary", "consumer.docs", ""},
	} {
		action := findAction(t, envelope["actionPlan"].([]any), "proofkit.adoption-doctor."+sharedID+row.suffix)
		if len(idsByKind[row.kind]) != wantCounts[row.kind] || !reflect.DeepEqual(action["evidenceRefs"], idsByKind[row.kind]) || action["owner"] != row.owner {
			t.Fatalf("action %s crossed input-record origin: %#v", row.kind, action)
		}
		selectors := action["selectors"].(map[string]any)
		if row.selector != "" {
			if len(selectors) != 2 || selectors[row.selector] != sharedID {
				t.Fatalf("action %s projected another origin's selector: %v", row.kind, selectors)
			}
		} else if len(selectors) != 1 {
			t.Fatalf("non-route/candidate origin acquired another collection's selector: %v", selectors)
		}
	}
	second, _ := wireDoctorEnvelope(t, input)
	if !reflect.DeepEqual(envelope, second) {
		t.Fatal("equal-ID origin/context projection is not deterministic")
	}
}

func TestGapReportKeepsCallerEvidenceWithoutSerializingOrigin(t *testing.T) {
	item := gap{
		origin:       inputRecordOrigin{recordKindCandidateBoundary, "consumer.boundary"},
		EvidenceRefs: []string{"docs/task-evidence.md"}, GapID: "consumer.boundary.candidate-boundary-not-admitted",
		Kind: "candidate_boundary_not_admitted", Message: "Caller boundary is advisory.", Owner: "consumer.owner",
		Phase: "modernize-boundary", RuleRefs: []string{"REQ-CONSUMER-001"}, Touched: true,
	}
	want := map[string]any{
		"evidenceRefs": []any{"docs/task-evidence.md"}, "gapId": "consumer.boundary.candidate-boundary-not-admitted",
		"kind": "candidate_boundary_not_admitted", "message": "Caller boundary is advisory.", "owner": "consumer.owner",
		"phase": "modernize-boundary", "ruleRefs": []any{"REQ-CONSUMER-001"}, "touched": true,
	}
	if got := gapJSON(item); !reflect.DeepEqual(got, want) {
		t.Fatalf("native report fields changed or serialized origin: got=%v want=%v", got, want)
	}
	item.origin = inputRecordOrigin{recordKindOwnerRoute, "consumer.another-record"}
	if !reflect.DeepEqual(gapJSON(item), want) {
		t.Fatal("report serialization depends on private input-record origin")
	}
}

func TestDoctorEnvelopeShapeRejectsSelectorEvidenceRefs(t *testing.T) {
	for name, input := range map[string]map[string]any{"gap": baseInput(), "no_gap": completeInput()} {
		t.Run(name, func(t *testing.T) {
			envelope, _ := wireDoctorEnvelope(t, input)
			assertDoctorReferenceClosure(t, envelope, input["doctorId"].(string))
			action := envelope["actionPlan"].([]any)[0].(map[string]any)
			action["selectors"].(map[string]any)["evidenceRefs"] = action["evidenceRefs"]
			if err := EnvelopeShape(envelope["envelopeId"].(string)).CheckGenerated(envelope, "doctor envelope"); err == nil {
				t.Fatal("envelope shape admitted duplicate selector evidence linkage")
			}
		})
	}
}

func actionContextRefs(t *testing.T, envelope, action map[string]any) []map[string]any {
	t.Helper()
	refs := []map[string]any{}
	for _, raw := range envelope["contextRefs"].([]any) {
		ref := raw.(map[string]any)
		if slices.Contains(action["evidenceRefs"].([]any), ref["refId"]) {
			refs = append(refs, ref)
		}
	}
	return refs
}

func assertActionContext(t *testing.T, envelope, action map[string]any, role, path string) {
	t.Helper()
	for _, ref := range actionContextRefs(t, envelope, action) {
		if ref["role"] == role && ref["path"] == path {
			return
		}
	}
	t.Fatalf("action %v has no %s context for %s", action["stepId"], role, path)
}

func assertActionContextCount(t *testing.T, envelope, action map[string]any, role string, want int) {
	t.Helper()
	count := 0
	for _, ref := range actionContextRefs(t, envelope, action) {
		if ref["role"] == role {
			count++
		}
	}
	if count != want {
		t.Fatalf("action %v has %d %s contexts, want %d", action["stepId"], count, role, want)
	}
}
