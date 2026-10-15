package adoptiondoctor

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
)

func TestReportAndEnvelopeStructuresDescribeReachableStates(t *testing.T) {
	seen := map[string]bool{}
	for name, input := range doctorStateFixtures() {
		t.Run(name, func(t *testing.T) {
			decoded := decodeInput(t, input)
			value, exit, err := Build(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if err := ReportShape().CheckGenerated(value, "doctor report"); err != nil {
				t.Fatal(err)
			}
			if (exit == 0) != (value["state"] == "passed") {
				t.Fatalf("state/exit drift: %v %d", value["state"], exit)
			}
			envelope, envelopeExit, err := BuildEnvelope(decoded)
			if err != nil || envelopeExit != exit {
				t.Fatalf("envelope phase drift: %v %d", err, envelopeExit)
			}
			envelopeID := input["doctorId"].(string) + ".agent-envelope"
			if envelope["envelopeId"] != envelopeID {
				envelopeID = admit.DiagnosticRedactionMarker
			}
			if err := EnvelopeShape(envelopeID).CheckGenerated(envelope, "doctor envelope"); err != nil {
				t.Fatal(err)
			}
			record(seen, value, envelope)
		})
	}
	for _, want := range []string{
		"state/passed", "state/failed", "state/blocked", "status/passed", "status/skipped", "status/warning", "status/failed", "status/blocked",
		"readiness/retire-stale-authority", "readiness/route/blocked_missing_owner_route", "readiness/promote/ready_for_owner_review",
		"readiness/modernize-boundary/blocked", "readiness/bind/blocked", "readiness/verify/blocked",
		"package/empty", "package/text", "replacement/empty", "replacement/text", "scope/empty", "scope/id",
		"action/no-gaps", "action/gap", "selectors/route+candidate", "witness/", "witness/candidate_witness_not_admitted",
		"witness/missing_native_witness", "witness/missing_owner_route", "witness/missing_proof_binding",
		"context/owner_route", "context/candidate_boundary", "context/stale_authority_surface", "clarification/1", "omitted/1",
		"bounds/boundsViolations", "envelopeId/redacted",
	} {
		if !seen[want] {
			t.Fatalf("reachable output domain was not exercised: %s", want)
		}
	}
	for kind := range gapKinds() {
		if !seen["kind/"+kind] {
			t.Fatalf("gap kind was not exercised: %s", kind)
		}
	}
}

func TestEnvelopeStructureAdmitsRedactedIdentityOnly(t *testing.T) {
	schema := EnvelopeStructure()
	alternatives := schema["properties"].(map[string]any)["envelopeId"].(map[string]any)["anyOf"].([]any)
	if len(alternatives) != 2 || alternatives[1].(map[string]any)["const"] != admit.DiagnosticRedactionMarker {
		t.Fatal("envelope identity lost its redaction alternative")
	}
	input := baseInput()
	input["doctorId"] = "eyJfixture.owner"
	envelope, _, err := BuildEnvelope(decodeInput(t, input))
	if err != nil || envelope["envelopeId"] != admit.DiagnosticRedactionMarker {
		t.Fatalf("redacted identity fixture changed: %v %v", err, envelope["envelopeId"])
	}
	invalid, exit, err := BuildEnvelope(map[string]any{})
	if err != nil || exit != 1 || invalid["envelopeId"] != "proofkit.agent-envelope.invalid-input" {
		t.Fatal("refused input did not select the invalid-input envelope")
	}
}

func TestInputStructureAgreesWithNativeAdmission(t *testing.T) {
	set := func(path string, value any) func(map[string]any) {
		return func(input map[string]any) { setPath(input, path, value) }
	}
	drop := func(path string) func(map[string]any) {
		return func(input map[string]any) { deletePath(input, path) }
	}
	full := func(input map[string]any) {
		input["staleAuthority"] = staleAuthorityInput("retired", "docs/archive/adr.md", "consumer.historical-proofkit")
		input["blockedPreconditions"] = []any{map[string]any{"evidenceRefs": []any{"docs/a.md"}, "nonClaim": "Caller fact.", "owner": "owner", "preconditionId": "consumer.blocked", "reason": "External input.", "touchedRuleIds": []any{"REQ-CONSUMER-001"}}}
	}
	long := strings.Repeat("A", 256)
	cases := []struct {
		name   string
		mutate func(map[string]any)
		class  string
	}{
		{"positive", func(map[string]any) {}, "accepted"},
		{"full", full, "accepted"},
		{"absent optional roots", func(input map[string]any) {
			delete(input, "modernization")
			delete(input, "staleAuthority")
			delete(input, "touchedRuleIds")
			input["checkedScope"] = "none"
		}, "accepted"},
		{"null optional roots", func(input map[string]any) {
			input["modernization"], input["staleAuthority"], input["touchedRuleIds"] = nil, nil, nil
			input["checkedScope"] = "none"
		}, "accepted"},
		{"null record lists", func(input map[string]any) {
			for _, key := range []string{"commands", "nativeWitnessRefs", "nonClaims", "proofBindingPaths", "specPaths", "touchedRuleIds"} {
				input["ownerRoutes"].([]any)[0].(map[string]any)[key] = nil
			}
		}, "accepted"},
		{"absent candidate lists", func(input map[string]any) {
			input["modernization"] = map[string]any{"candidateBoundaries": []any{map[string]any{"admissionState": "owner_admitted", "boundaryId": "consumer.boundary", "candidateOwner": "owner"}}}
		}, "accepted"},
		{"empty stale authority", set("staleAuthority", map[string]any{}), "accepted"},
		{"null stale members", set("staleAuthority", map[string]any{"authoritySurfaces": nil, "currentPackage": nil, "forbiddenVocabulary": nil, "retiredScopes": nil}), "accepted"},
		{"null replacement", func(input map[string]any) {
			full(input)
			input["staleAuthority"].(map[string]any)["forbiddenVocabulary"].([]any)[0].(map[string]any)["replacementText"] = nil
		}, "accepted"},
		{"whitespace path", set("ownerRoutes.0.specPaths", []any{" "}), "accepted"},
		{"maximum identifier", set("doctorId", long), "accepted"},
		{"padded command", set("ownerRoutes.0.commands", []any{" go test ./... "}), "accepted"},
		{"unknown root", set("foreign", true), "structural"},
		{"unknown route", set("ownerRoutes.0.foreign", true), "structural"},
		{"unknown modernization", set("modernization.foreign", true), "structural"},
		{"unknown candidate", set("modernization.candidateBoundaries.0.foreign", true), "structural"},
		{"unknown child", set("childReports.0.foreign", true), "structural"},
		{"unknown stale", set("staleAuthority", map[string]any{"foreign": true}), "structural"},
		{"unknown package", set("staleAuthority", map[string]any{"currentPackage": map[string]any{"name": "n", "version": "v", "foreign": true}}), "structural"},
		{"missing schemaVersion", drop("schemaVersion"), "structural"},
		{"schemaVersion two", set("schemaVersion", json.Number("2")), "structural"},
		{"missing doctorId", drop("doctorId"), "structural"},
		{"long identifier", set("doctorId", long+"A"), "structural"},
		{"unknown mode", set("mode", "audit"), "structural"},
		{"unknown scope", set("checkedScope", "partial"), "structural"},
		{"enforce all without all", func(input map[string]any) { input["mode"] = "enforce-all" }, "structural"},
		{"enforce touched with none", func(input map[string]any) { input["mode"], input["checkedScope"] = "enforce-touched", "none" }, "structural"},
		{"missing routes", drop("ownerRoutes"), "structural"},
		{"null routes", set("ownerRoutes", nil), "structural"},
		{"missing children", drop("childReports"), "structural"},
		{"missing blocked", drop("blockedPreconditions"), "structural"},
		{"missing nonClaims", drop("nonClaims"), "structural"},
		{"empty nonClaims", set("nonClaims", []any{}), "structural"},
		{"blank nonClaim", set("nonClaims", []any{"\u3000"}), "structural"},
		{"modernization array", set("modernization", []any{}), "structural"},
		{"missing candidate list", set("modernization", map[string]any{}), "structural"},
		{"candidate state", set("modernization.candidateBoundaries.0.admissionState", "approved"), "structural"},
		{"candidate blank owner", set("modernization.candidateBoundaries.0.candidateOwner", " "), "structural"},
		{"child state", set("childReports.0.state", "unknown"), "structural"},
		{"child kind identifier", set("childReports.0.reportKind", "bad kind"), "structural"},
		{"child missing summary", drop("childReports.0.summary"), "structural"},
		{"route missing owner", drop("ownerRoutes.0.owner"), "structural"},
		{"route path kind", set("ownerRoutes.0.specPaths", []any{false}), "structural"},
		{"route empty path", set("ownerRoutes.0.specPaths", []any{""}), "structural"},
		{"route identifier list", set("ownerRoutes.0.touchedRuleIds", []any{"1bad"}), "structural"},
		{"stale array", set("staleAuthority", []any{}), "structural"},
		{"package missing version", set("staleAuthority", map[string]any{"currentPackage": map[string]any{"name": "n"}}), "structural"},
		{"surface state", func(input map[string]any) {
			full(input)
			input["staleAuthority"].(map[string]any)["authoritySurfaces"].([]any)[0].(map[string]any)["authorityState"] = "stale"
		}, "structural"},
		{"scope without prefixes", func(input map[string]any) {
			full(input)
			input["staleAuthority"].(map[string]any)["retiredScopes"].([]any)[0].(map[string]any)["pathPrefixes"] = []any{}
		}, "structural"},
		{"scope null allowed ids", func(input map[string]any) {
			full(input)
			input["staleAuthority"].(map[string]any)["retiredScopes"].([]any)[0].(map[string]any)["allowedVocabularyIds"] = nil
		}, "structural"},
		{"blank replacement", func(input map[string]any) {
			full(input)
			input["staleAuthority"].(map[string]any)["forbiddenVocabulary"].([]any)[0].(map[string]any)["replacementText"] = " "
		}, "structural"},
		{"secret text", set("nonClaims", []any{"api_" + "key=synthetic-doctor-fixture"}), "native"},
		{"timestamp identifier", set("doctorId", "consumer.20260101"), "native"},
		{"shell command", set("ownerRoutes.0.commands", []any{"go test ./... && rm -rf"}), "native"},
		{"unsorted paths", set("ownerRoutes.0.specPaths", []any{"b.md", "a.md"}), "native"},
		{"absolute path", set("ownerRoutes.0.specPaths", []any{"/a.md"}), "native"},
		{"duplicate routes", func(input map[string]any) {
			input["ownerRoutes"] = append(input["ownerRoutes"].([]any), input["ownerRoutes"].([]any)[0])
		}, "native"},
		{"unknown vocabulary", func(input map[string]any) {
			full(input)
			input["staleAuthority"].(map[string]any)["authoritySurfaces"].([]any)[0].(map[string]any)["matchedVocabularyIds"] = []any{"foreign.vocabulary"}
		}, "native"},
		{"unknown retired scope", func(input map[string]any) {
			full(input)
			input["staleAuthority"].(map[string]any)["authoritySurfaces"].([]any)[0].(map[string]any)["retiredScopeId"] = "foreign.scope"
		}, "native"},
		{"duplicate normalized nonClaims", set("nonClaims", []any{"a", " a"}), "native"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := baseInput()
			item.mutate(input)
			decoded := decodeInput(t, input)
			_, nativeErr := BuildResult(decoded)
			_, shapeErr := InputShape().Admit(decoded, "input")
			record := decoded.(map[string]any)
			mode, _ := record["mode"].(string)
			scope, _ := record["checkedScope"].(string)
			structural := shapeErr == nil && modeScopeAdmitted(InputStructure(), mode, scope)
			switch item.class {
			case "accepted":
				if nativeErr != nil || !structural {
					t.Fatalf("accepted input diverged: native=%v shape=%v", nativeErr, shapeErr)
				}
			case "structural":
				if nativeErr == nil || structural {
					t.Fatalf("structural refusal diverged: native=%v shape=%v", nativeErr, shapeErr)
				}
			case "native":
				if nativeErr == nil || !structural {
					t.Fatalf("native-only predicate diverged: native=%v shape=%v", nativeErr, shapeErr)
				}
			}
		})
	}
}

func TestModeScopeProjectionMatchesNativeAdmission(t *testing.T) {
	schema := InputStructure()
	for mode := range adoptionmode.ValuesMap() {
		for scope := range scopeValues() {
			input := baseInput()
			input["mode"], input["checkedScope"] = mode, scope
			_, err := BuildResult(decodeInput(t, input))
			if (err == nil) != modeScopeAdmitted(schema, mode, scope) {
				t.Fatalf("%s/%s: native=%v", mode, scope, err)
			}
		}
	}
}

func TestDoctorStructuresAreDetachedProjections(t *testing.T) {
	for _, build := range []func() map[string]any{InputStructure, OutputStructure, EnvelopeStructure} {
		first := build()
		first["properties"].(map[string]any)["schemaVersion"].(map[string]any)["const"] = json.Number("2")
		if reflect.DeepEqual(first, build()) {
			t.Fatal("structure projection aliases a prior caller")
		}
	}
	if !slices.Equal(slices.Sorted(maps.Keys(InputStructure()["properties"].(map[string]any))), inputKeys) {
		t.Fatal("input structure differs from the native member inventory")
	}
}

func doctorStateFixtures() map[string]map[string]any {
	fixtures := map[string]map[string]any{"observe": baseInput(), "complete": completeInput()}
	for _, mode := range []string{"warn", "enforce-touched", "enforce-all"} {
		input := baseInput()
		input["mode"] = mode
		if mode == "enforce-all" {
			input["checkedScope"] = "all"
		}
		fixtures[mode] = input
	}
	enforceAllComplete := completeInput()
	enforceAllComplete["mode"], enforceAllComplete["checkedScope"] = "enforce-all", "all"
	fixtures["enforce-all-complete"] = enforceAllComplete
	for state := range childReportStates {
		input := baseInput()
		input["mode"], input["checkedScope"] = "enforce-all", "all"
		input["childReports"].([]any)[0].(map[string]any)["state"] = state
		fixtures["child-"+state] = input
	}
	noRoutes := baseInput()
	noRoutes["ownerRoutes"], noRoutes["mode"] = []any{}, "enforce-touched"
	fixtures["no-routes"] = noRoutes
	uncovered := completeInput()
	uncovered["mode"], uncovered["touchedRuleIds"] = "enforce-touched", []any{"REQ-CONSUMER-001", "REQ-CONSUMER-002"}
	fixtures["uncovered"] = uncovered
	blocked := completeInput()
	blocked["blockedPreconditions"] = []any{map[string]any{"evidenceRefs": []any{"docs/blocked.md"}, "nonClaim": "Caller fact.", "owner": "owner", "preconditionId": "consumer.blocked", "reason": "External input."}}
	blocked["modernization"] = map[string]any{"candidateBoundaries": []any{map[string]any{"admissionState": "owner_admitted", "blockedPreconditions": []any{"Owner approval."}, "boundaryId": "consumer.example-route.boundary", "candidateOwner": "owner", "nativeWitnessRefs": []any{"tests/a.go"}}}}
	fixtures["blocked"] = blocked
	for _, row := range []struct{ name, state, path, scope string }{
		{"stale-current", "current", "docs/adr.md", ""}, {"stale-retired-outside", "retired", "docs/adr.md", "consumer.historical-proofkit"},
		{"stale-retired-inside", "retired", "docs/archive/adr.md", "consumer.historical-proofkit"},
	} {
		input := completeInput()
		input["mode"], input["checkedScope"] = "enforce-all", "all"
		input["staleAuthority"] = staleAuthorityInput(row.state, row.path, row.scope)
		fixtures[row.name] = input
	}
	sparse := completeInput()
	sparse["staleAuthority"] = map[string]any{"forbiddenVocabulary": []any{map[string]any{"text": "legacy", "vocabularyId": "legacy.term"}},
		"authoritySurfaces": []any{map[string]any{"authorityState": "retired", "owner": "docs", "path": "docs/old.md", "surfaceId": "consumer.surface", "matchedVocabularyIds": []any{"legacy.term"}}}}
	fixtures["stale-sparse"] = sparse
	overlap := baseInput()
	overlap["modernization"].(map[string]any)["candidateBoundaries"].([]any)[0].(map[string]any)["boundaryId"] = "consumer.example-route.boundary"
	fixtures["route-candidate-overlap"] = overlap
	degraded := baseInput()
	route := degraded["ownerRoutes"].([]any)[0].(map[string]any)
	route["routeId"] = "consumer." + strings.Repeat("r", 240)
	route["commands"], route["specPaths"] = []any{"go test ./..."}, []any{"docs/spec\u202e.md"}
	fixtures["degraded"] = degraded
	many := baseInput()
	routes := []any{}
	for index := range 30 {
		routes = append(routes, map[string]any{"owner": "owner", "routeId": fmt.Sprintf("consumer.route-%02d", index), "specPaths": []any{fmt.Sprintf("docs/spec-%02d.md", index)}})
	}
	many["ownerRoutes"], many["checkedScope"] = routes, "all"
	fixtures["many"] = many
	redacted := baseInput()
	redacted["doctorId"] = "eyJfixture.owner"
	fixtures["redacted"] = redacted
	return fixtures
}

func record(seen map[string]bool, value map[string]any, envelope map[string]any) {
	seen["state/"+value["state"].(string)] = true
	for _, raw := range value["ruleResults"].([]any) {
		seen["status/"+raw.(map[string]any)["status"].(string)] = true
	}
	for _, raw := range value["diagnostics"].([]any) {
		diagnostic := raw.(map[string]any)
		switch diagnostic["key"] {
		case "gaps":
			for _, gap := range diagnostic["value"].([]any) {
				seen["kind/"+gap.(map[string]any)["kind"].(string)] = true
			}
		case "promotionReadiness":
			for key, status := range diagnostic["value"].(map[string]any) {
				seen["readiness/"+key] = true
				seen["readiness/"+key+"/"+status.(string)] = true
			}
		case "staleAuthority":
			stale := diagnostic["value"].(map[string]any)
			seen[map[bool]string{true: "package/empty", false: "package/text"}[stale["currentPackage"].(map[string]any)["name"] == ""]] = true
			for _, vocabulary := range stale["forbiddenVocabulary"].([]any) {
				seen[map[bool]string{true: "replacement/empty", false: "replacement/text"}[vocabulary.(map[string]any)["replacementText"] == ""]] = true
			}
			for _, surface := range stale["authoritySurfaces"].([]any) {
				seen[map[bool]string{true: "scope/empty", false: "scope/id"}[surface.(map[string]any)["retiredScopeId"] == ""]] = true
			}
		}
	}
	for _, raw := range envelope["actionPlan"].([]any) {
		action := raw.(map[string]any)
		if action["stepId"] == reportKind+".no-gaps" {
			seen["action/no-gaps"] = true
			continue
		}
		seen["action/gap"] = true
		seen["witness/"+action["missingWitness"].(string)] = true
		selectors := action["selectors"].(map[string]any)
		if selectors["ownerRouteId"] != nil && selectors["candidateBoundaryId"] != nil {
			seen["selectors/route+candidate"] = true
		}
	}
	for _, raw := range envelope["contextRefs"].([]any) {
		seen["context/"+raw.(map[string]any)["kind"].(string)] = true
	}
	seen[fmt.Sprintf("clarification/%d", len(envelope["clarificationQuestions"].([]any)))] = true
	seen[fmt.Sprintf("omitted/%d", len(envelope["omitted"].([]any)))] = true
	if _, ok := envelope["bounds"].(map[string]any)["boundsViolations"]; ok {
		seen["bounds/boundsViolations"] = true
	}
	if envelope["envelopeId"] == admit.DiagnosticRedactionMarker {
		seen["envelopeId/redacted"] = true
	}
}

func modeScopeAdmitted(schema map[string]any, mode string, scope string) bool {
	matches := 0
	for _, raw := range schema["oneOf"].([]any) {
		properties := raw.(map[string]any)["properties"].(map[string]any)
		if properties["mode"].(map[string]any)["const"] == mode && slices.Contains(properties["checkedScope"].(map[string]any)["enum"].([]any), any(scope)) {
			matches++
		}
	}
	return matches == 1
}

func setPath(record map[string]any, path string, value any) {
	parent, key := walk(record, path)
	switch typed := parent.(type) {
	case map[string]any:
		typed[key] = value
	case []any:
		typed[int(key[0]-'0')] = value
	}
}

func deletePath(record map[string]any, path string) {
	parent, key := walk(record, path)
	delete(parent.(map[string]any), key)
}

func walk(record map[string]any, path string) (any, string) {
	parts := strings.Split(path, ".")
	var current any = record
	for _, part := range parts[:len(parts)-1] {
		switch typed := current.(type) {
		case map[string]any:
			current = typed[part]
		case []any:
			current = typed[int(part[0]-'0')]
		}
	}
	return current, parts[len(parts)-1]
}
