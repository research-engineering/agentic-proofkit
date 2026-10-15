package requirementbrowser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementdiff"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementgraph"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/browserfixture"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/projectfixture"
)

// Independently stated root inventories; they are not read from the schemas.
var (
	planKeys      = []string{"authority", "host", "htmlByteLength", "nonClaims", "planKind", "port", "portSelection", "renderedAuthority", "renderedViewKind", "schemaVersion", "url", "view"}
	terminalKeys  = []string{"handoffKind", "nonClaims", "schemaVersion", "snapshotRefs", "state"}
	submittedKeys = []string{"annotations", "context", "handoffKind", "instructionAuthority", "nonClaims", "schemaVersion", "snapshotRefs", "sourceTextAuthority", "state"}
	annotationKey = []string{"anchor", "endCodePoint", "exactQuote", "prefix", "question", "startCodePoint", "suffix", "targetId"}
)

type planCase struct {
	view, kind, authority string
	input                 any
	options               Options
}

func planCases(t *testing.T) []planCase {
	t.Helper()
	structured, err := browserfixture.CoverageInput("structured")
	if err != nil {
		t.Fatal(err)
	}
	compact, err := browserfixture.CoverageInput("compact")
	if err != nil {
		t.Fatal(err)
	}
	return []planCase{
		{"coverage", "proofkit.requirement-coverage-view", "lookup_only", structured, Options{}},
		{"coverage", "proofkit.requirement-coverage-view", "lookup_only", compact, Options{}},
		{"proof", "proofkit.requirement-proof-view", "lookup_only", proofInput(t), Options{ProofViewScope: "graph"}},
		{"proof", "proofkit.compact-requirement-proof-view", "lookup_only", compact["compactProofContract"], Options{LocalEnvironmentClasses: []string{"local-go"}}},
		{"proof", "proofkit.compact-requirement-proof-view", "lookup_only", compact["compactProofContract"], Options{EmptyLocalEnvironmentPolicy: true}},
		{"source", "proofkit.requirement-source-view", "presentation_only", sourceInput(t), Options{}},
		{"spec-tree", "proofkit.requirement-spec-tree-view", "presentation_only", specTreeInput(t), Options{}},
		{"workspace", "proofkit.requirement-workspace", "presentation_adapter", workspaceFixture(t), Options{}},
	}
}

func TestPlanStructuresAdmitEveryViewHostAndPortSelection(t *testing.T) {
	urlPattern := regexp.MustCompile(`\A` + plannedURLGrammar() + `\z`)
	for _, row := range planCases(t) {
		shape, err := PlanOutputShape(row.view)
		if err != nil {
			t.Fatal(err)
		}
		for _, host := range HostChoices() {
			for _, port := range []int{0, 1, 80, 8080, maximumPort} {
				options := row.options
				options.View, options.Host, options.Port, options.PortSet = row.view, host, port, true
				plan, code, err := BuildPlan(row.input, options)
				if err != nil || code != 0 {
					t.Fatalf("%s plan failed: %v", row.view, err)
				}
				if !slices.Equal(slices.Sorted(maps.Keys(plan)), planKeys) || plan["renderedViewKind"] != row.kind || plan["renderedAuthority"] != row.authority {
					t.Fatalf("%s plan inventory or rendering drifted: %v", row.view, plan)
				}
				if err := shape.CheckGenerated(plan, "plan"); err != nil {
					t.Fatalf("%s/%s/%d: %v", row.view, host, port, err)
				}
				// The schema-only oneOf branch must agree with the native partition.
				url, fixed := plan["url"].(string)
				if (port == ephemeralPort) != (plan["portSelection"] == portSelectionEphemeral) || fixed == (port == ephemeralPort) || (fixed && !urlPattern.MatchString(url)) {
					t.Fatalf("port partition drifted: %v", plan)
				}
				for _, other := range ViewChoices() {
					if other == row.view {
						continue
					}
					otherShape, err := PlanOutputShape(other)
					if err != nil {
						t.Fatal(err)
					}
					if otherShape.CheckGenerated(plan, "plan") == nil {
						t.Fatalf("%s plan was admitted by the %s variant", row.view, other)
					}
				}
			}
		}
	}
	fixture := projectfixture.New(t)
	plan, code, err := BuildProjectPlan(t.Context(), fixture.Root, Options{})
	shape, shapeErr := PlanOutputShape("workspace")
	if err != nil || shapeErr != nil || code != 0 || shape.CheckGenerated(plan, "project plan") != nil {
		t.Fatalf("project plan is outside the workspace plan structure: %v %v", err, shapeErr)
	}
}

func TestPlanStructureRejectsIsolatedClauseViolations(t *testing.T) {
	shape, err := PlanOutputShape("workspace")
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err := BuildPlan(workspaceFixture(t), Options{View: "workspace"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range planKeys {
		missing := maps.Clone(plan)
		delete(missing, key)
		if shape.CheckGenerated(missing, "plan") == nil {
			t.Fatalf("missing %s was admitted", key)
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown":       func(v map[string]any) { v["foreign"] = true },
		"host":          func(v map[string]any) { v["host"] = "localhost" },
		"port-high":     func(v map[string]any) { v["port"] = maximumPort + 1 },
		"port-negative": func(v map[string]any) { v["port"] = -1 },
		"html-empty":    func(v map[string]any) { v["htmlByteLength"] = 0 },
		"selection":     func(v map[string]any) { v["portSelection"] = "dynamic" },
		"url-host":      func(v map[string]any) { v["url"] = "http://localhost:8080/" },
		"url-path":      func(v map[string]any) { v["url"] = "http://127.0.0.1:8080/x" },
		"url-zero-port": func(v map[string]any) { v["url"] = "http://127.0.0.1:0/" },
		"kind":          func(v map[string]any) { v["renderedViewKind"] = "proofkit.requirement-source-view" },
		"authority":     func(v map[string]any) { v["renderedAuthority"] = "lookup_only" },
		"plan-kind":     func(v map[string]any) { v["planKind"] = "proofkit.other" },
		"version":       func(v map[string]any) { v["schemaVersion"] = 2 },
		"claims-short":  func(v map[string]any) { v["nonClaims"] = v["nonClaims"].([]any)[1:] },
		"claims-order": func(v map[string]any) {
			claims := slices.Clone(v["nonClaims"].([]any))
			slices.Reverse(claims)
			v["nonClaims"] = claims
		},
	} {
		value := maps.Clone(plan)
		mutate(value)
		if shape.CheckGenerated(value, "plan") == nil {
			t.Fatalf("%s violation was admitted", name)
		}
	}
	if _, err := PlanOutputShape("foreign"); err == nil {
		t.Fatal("an unowned view acquired a plan structure")
	}
	schema, err := PlanOutputStructure("workspace")
	if err != nil {
		t.Fatal(err)
	}
	partition := schema["oneOf"].([]any)
	ephemeral := partition[0].(map[string]any)["properties"].(map[string]any)
	fixed := partition[1].(map[string]any)["properties"].(map[string]any)
	if len(partition) != 2 || ephemeral["portSelection"].(map[string]any)["const"] != portSelectionEphemeral || ephemeral["url"].(map[string]any)["type"] != "null" ||
		ephemeral["port"].(map[string]any)["const"] != json.Number("0") || fixed["portSelection"].(map[string]any)["const"] != portSelectionFixed ||
		fixed["url"].(map[string]any)["type"] != "string" || fixed["port"].(map[string]any)["minimum"] != json.Number("1") {
		t.Fatalf("plan port partition differs from renderedPlan: %v", partition)
	}
}

func TestQuestionPacketStructuresAdmitEveryTerminalProducer(t *testing.T) {
	terminal := TerminalOutputShape()
	submitted, err := SubmittedOutputShape()
	if err != nil {
		t.Fatal(err)
	}
	check := func(label string, shape jsonshape.Shape, keys []string, raw []byte, state string) map[string]any {
		t.Helper()
		value, err := admission.DecodeJSON(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		record := value.(map[string]any)
		if !slices.Equal(slices.Sorted(maps.Keys(record)), keys) || record["state"] != state {
			t.Fatalf("%s inventory or state drifted: %v", label, record)
		}
		if err := shape.CheckGenerated(record, label); err != nil {
			t.Fatal(err)
		}
		other := submitted
		if state == questionStateSubmitted {
			other = terminal
		}
		if other.CheckGenerated(record, label) == nil {
			t.Fatalf("%s matched both packet variants", label)
		}
		return record
	}

	var expired bytes.Buffer
	err = Serve(t.Context(), workspaceFixture(t), Options{Host: "127.0.0.1", PortSet: true, SessionMode: "one-shot-question", SessionTimeout: 10 * time.Millisecond, View: "workspace"}, &expired)
	if !errors.Is(err, ErrOneShotTerminal) {
		t.Fatalf("expiry did not end as a terminal state: %v", err)
	}
	check("expired", terminal, terminalKeys, expired.Bytes(), questionStateExpired)

	handle, _ := startWorkspaceTestServer(t, workspaceFixture(t), true)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	var interrupted bytes.Buffer
	if err := serveHandle(cancelled, handle, Options{SessionMode: "one-shot-question"}, &interrupted); !errors.Is(err, ErrOneShotTerminal) {
		t.Fatalf("cancellation did not end as a terminal state: %v", err)
	}
	check("context-cancelled", terminal, terminalKeys, interrupted.Bytes(), questionStateCancelled)

	handle, capability := startWorkspaceTestServer(t, workspaceFixture(t), true)
	result := make(chan error, 1)
	var browserCancelled bytes.Buffer
	go func() {
		result <- serveHandle(t.Context(), handle, Options{SessionMode: "one-shot-question"}, &browserCancelled)
	}()
	body := postPacketRequest(t, handle, capability, "cancel", map[string]any{"requestId": "browser.cancel", "snapshotId": handle.SnapshotID})
	if err := <-result; !errors.Is(err, ErrOneShotTerminal) {
		t.Fatalf("browser cancellation did not end as a terminal state: %v", err)
	}
	check("browser-cancel-response", terminal, terminalKeys, body, questionStateCancelled)
	check("browser-cancelled", terminal, terminalKeys, browserCancelled.Bytes(), questionStateCancelled)

	for _, annotations := range [][]any{
		{handoffAnnotation(11, 20, "preserves", "  Does this remain true?\u0085")},
		{handoffAnnotation(0, 3, "The", "Why?"), handoffAnnotation(11, 20, "preserves", "\ufeffAnd this?\ufeff")},
	} {
		handle, capability := startWorkspaceTestServer(t, workspaceFixture(t), true)
		result := make(chan error, 1)
		var stdout bytes.Buffer
		go func() { result <- serveHandle(t.Context(), handle, Options{SessionMode: "one-shot-question"}, &stdout) }()
		body := postPacketRequest(t, handle, capability, "handoff", map[string]any{"annotations": annotations})
		if err := <-result; err != nil {
			t.Fatalf("submitted session failed: %v", err)
		}
		packet := check("submitted", submitted, submittedKeys, stdout.Bytes(), questionStateSubmitted)
		check("submitted-response", submitted, submittedKeys, body, questionStateSubmitted)
		for _, raw := range packet["annotations"].([]any) {
			if !slices.Equal(slices.Sorted(maps.Keys(raw.(map[string]any))), annotationKey) {
				t.Fatalf("annotation inventory drifted: %v", raw)
			}
		}
	}
}

func TestSubmittedStructureCoversProjectOriginAndExactBounds(t *testing.T) {
	submitted, err := SubmittedOutputShape()
	if err != nil {
		t.Fatal(err)
	}
	fixture := projectfixture.New(t)
	rendered, _, err := prepareProject(t.Context(), fixture.Root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	anchor := rendered.workspace.Anchors["requirement:REQ-WIRE-001:invariant"]
	runes := []rune(anchor.Text)
	packet, err := buildHandoffPacket(handoffRequest(t, []any{handoffAnnotationRecord(anchor.AnchorID, 11, 12, string(runes[11:12]), "Project origin?")}), *rendered.workspace)
	if err != nil {
		t.Fatal(err)
	}
	if err := submitted.CheckGenerated(packet, "project packet"); err != nil {
		t.Fatal(err)
	}
	if _, origin := packet["context"].(map[string]any)["projections"]; !origin {
		t.Fatal("project packet lost its review projections")
	}

	invariant := strings.Repeat("q", maxHandoffQuoteBytes+2*handoffQuoteContextCodePoints+8)
	session := workspaceSessionForInvariant(t, invariant)
	start := handoffQuoteContextCodePoints + 4
	exact, err := buildHandoffPacket(handoffRequest(t, []any{handoffAnnotation(start, start+maxHandoffQuoteBytes, invariant[start:start+maxHandoffQuoteBytes], strings.Repeat("a", maxHandoffQuestionBytes))}), session)
	if err != nil {
		t.Fatal(err)
	}
	if err := submitted.CheckGenerated(exact, "bound packet"); err != nil {
		t.Fatal(err)
	}
	annotation := exact["annotations"].([]any)[0].(map[string]any)
	if len([]rune(annotation["prefix"].(string))) != handoffQuoteContextCodePoints || len([]rune(annotation["suffix"].(string))) != handoffQuoteContextCodePoints {
		t.Fatal("bounded prefix and suffix were not exercised at their exact limit")
	}
	schema, err := SubmittedOutputStructure()
	if err != nil {
		t.Fatal(err)
	}
	fields := schema["properties"].(map[string]any)["annotations"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	if fields["exactQuote"].(map[string]any)["maxLength"] != json.Number(fmt.Sprint(maxHandoffQuoteBytes)) || fields["question"].(map[string]any)["maxLength"] != json.Number(fmt.Sprint(maxHandoffQuestionBytes)) ||
		fields["prefix"].(map[string]any)["maxLength"] != json.Number(fmt.Sprint(handoffQuoteContextCodePoints)) {
		t.Fatal("implied code-point bounds drifted from native byte limits")
	}
	for name, mutate := range map[string]func(map[string]any){
		"prefix-long":    func(a map[string]any) { a["prefix"] = strings.Repeat("p", handoffQuoteContextCodePoints+1) },
		"suffix-long":    func(a map[string]any) { a["suffix"] = strings.Repeat("s", handoffQuoteContextCodePoints+1) },
		"quote-blank":    func(a map[string]any) { a["exactQuote"] = " \u0085 " },
		"question-outer": func(a map[string]any) { a["question"] = " Why? " },
		"question-empty": func(a map[string]any) { a["question"] = "" },
		"end-zero":       func(a map[string]any) { a["endCodePoint"] = 0 },
		"start-negative": func(a map[string]any) { a["startCodePoint"] = -1 },
		"target":         func(a map[string]any) { a["targetId"] = "sha256:short" },
		"unknown":        func(a map[string]any) { a["foreign"] = true },
		"anchor-space": func(a map[string]any) {
			a["anchor"] = map[string]any{"anchorId": "a", "coordinateSpace": "source_wire", "jsonPointer": "/", "requirementId": "R", "sourceDigest": "d", "sourceId": "s"}
		},
	} {
		value := cloneWorkspaceRecord(t, exact)
		mutate(value["annotations"].([]any)[0].(map[string]any))
		if submitted.CheckGenerated(value, "packet") == nil {
			t.Fatalf("%s violation was admitted", name)
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"no-annotations": func(p map[string]any) { p["annotations"] = []any{} },
		"many": func(p map[string]any) {
			p["annotations"] = slices.Repeat(p["annotations"].([]any), maxHandoffAnnotations+1)
		},
		"context-profile": func(p map[string]any) { p["context"].(map[string]any)["profile"] = "routing" },
		"snapshot-refs":   func(p map[string]any) { p["snapshotRefs"] = []any{} },
		"snapshot-role":   func(p map[string]any) { p["snapshotRefs"].([]any)[0].(map[string]any)["role"] = "base" },
		"instruction":     func(p map[string]any) { p["instructionAuthority"] = "operator" },
		"source-text":     func(p map[string]any) { p["sourceTextAuthority"] = "trusted" },
	} {
		value := cloneWorkspaceRecord(t, exact)
		mutate(value)
		if submitted.CheckGenerated(value, "packet") == nil {
			t.Fatalf("%s violation was admitted", name)
		}
	}
	at := cloneWorkspaceRecord(t, exact)
	at["annotations"] = slices.Repeat(at["annotations"].([]any), maxHandoffAnnotations)
	if err := submitted.CheckGenerated(at, "packet"); err != nil {
		t.Fatalf("exact annotation count was refused: %v", err)
	}
}

func TestInputStructuresDelegateWholeOwnersAndSpecializeOnlyThePartition(t *testing.T) {
	source, err := SourceInputStructure()
	owner, ownerErr := requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
	if err != nil || ownerErr != nil || !reflect.DeepEqual(source, owner) {
		t.Fatal("source view input differs from the source owner")
	}
	if !reflect.DeepEqual(CompactProofInputStructure(), compactproofcontract.InputStructure()) || !reflect.DeepEqual(SpecTreeInputStructure(), requirementspectree.InputStructure()) {
		t.Fatal("compact proof or spec-tree input differs from its owner")
	}
	structured := StructuredProofInputStructure()
	ownerStructured := requirementproofview.StructuredInputStructure()
	delete(structured, "description")
	delete(ownerStructured, "description")
	if !reflect.DeepEqual(structured, ownerStructured) || !reflect.DeepEqual(ownerStructured["properties"], requirementbinding.InputStructure()["properties"]) {
		t.Fatal("structured proof input changed more than its browser flag description")
	}

	coverage, err := requirementcoverageview.InputStructure()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, row := range []struct {
		compact           bool
		required, nonNull []string
		null              string
	}{
		{true, []string{"compactProofContract", "coverageUniverse", "localEnvironmentPolicy", "requirementSource", "schemaVersion", "viewInputId"}, []string{"compactProofContract", "localEnvironmentPolicy"}, "requirementProofBinding"},
		{false, []string{"coverageUniverse", "requirementProofBinding", "requirementSource", "schemaVersion", "viewInputId"}, []string{"requirementProofBinding"}, "compactProofContract"},
	} {
		schema, err := CoverageInputStructure(row.compact)
		if err != nil {
			t.Fatal(err)
		}
		properties := schema["properties"].(map[string]any)
		ownerProperties := coverage["properties"].(map[string]any)
		if !slices.Equal(slices.Sorted(maps.Keys(properties)), []string{"compactProofContract", "coverageUniverse", "localEnvironmentPolicy", "normalizedTestEvidenceInventory", "options", "ownerInvariantRegistry", "requirementProofBinding", "requirementSource", "schemaVersion", "testEvidenceInventory", "viewInputId"}) {
			t.Fatal("coverage member inventory drifted from native admission")
		}
		if got := schema["required"].([]any); !reflect.DeepEqual(got, stringsAny(row.required)) {
			t.Fatalf("coverage required members=%v", got)
		}
		if _, sum := schema["oneOf"]; sum || ids[schema["$id"].(string)] || schema["additionalProperties"] != false {
			t.Fatal("coverage variant retained the sum, reused a resource id or opened its root")
		}
		ids[schema["$id"].(string)] = true
		for _, name := range row.nonNull {
			if !reflect.DeepEqual(nullableMember(properties[name].(map[string]any)), ownerProperties[name]) {
				t.Fatalf("%s is not exactly the owner's non-null member", name)
			}
		}
		if !reflect.DeepEqual(properties[row.null], map[string]any{"type": "null"}) {
			t.Fatalf("%s may carry a value in this mode", row.null)
		}
		for name, member := range properties {
			if !slices.Contains(row.nonNull, name) && name != row.null && !reflect.DeepEqual(member, ownerProperties[name]) {
				t.Fatalf("%s changed outside the proof-mode partition", name)
			}
		}
		_, compactResource := schema["$defs"].(map[string]any)[compactCoverageMember]
		if compactResource != row.compact || containsLocalReference(schema, "#/$defs/"+compactCoverageMember) != row.compact {
			t.Fatal("compact resource reachability differs from the proof mode")
		}
	}

	workspace, err := WorkspaceInputStructure()
	if err != nil {
		t.Fatal(err)
	}
	properties := workspace["properties"].(map[string]any)
	if !slices.Equal(slices.Sorted(maps.Keys(properties)), workspaceInputKeys) || !reflect.DeepEqual(workspace["required"], []any{"context", "schemaVersion", "workspaceId"}) || ids[workspace["$id"].(string)] {
		t.Fatal("workspace members differ from native admission")
	}
	snapshot := requirementcontext.SnapshotShape().JSONSchema()
	delete(snapshot, "$schema")
	if !reflect.DeepEqual(workspace["$defs"].(map[string]any)[workspaceContextResource], snapshot) || !reflect.DeepEqual(properties["context"], contextReference()) {
		t.Fatal("workspace context is not the shared requirement-context owner")
	}
	for name, owner := range map[string]map[string]any{"diffInput": requirementdiff.InputStructure(), "graphInput": requirementgraph.InputStructure()} {
		expanded := expandContextReferences(properties[name], snapshot)
		delete(owner, "$schema")
		if !reflect.DeepEqual(expanded, nullableMember(owner)) {
			t.Fatalf("%s differs from its owner after resource expansion", name)
		}
	}
	first, _ := WorkspaceInputStructure()
	first["$defs"].(map[string]any)[workspaceContextResource].(map[string]any)["foreign"] = true
	if second, _ := WorkspaceInputStructure(); reflect.DeepEqual(first, second) {
		t.Fatal("workspace structures share mutable owner maps")
	}
}

func TestWorkspaceAdmissionAgreesWithStructuralMembers(t *testing.T) {
	accepts := func(label string, input map[string]any) {
		t.Helper()
		if _, _, err := buildWorkspace(wireValue(t, input)); err != nil {
			t.Fatalf("%s was refused: %v", label, err)
		}
	}
	refuses := func(label string, input map[string]any) {
		t.Helper()
		if _, _, err := buildWorkspace(wireValue(t, input)); err == nil {
			t.Fatalf("%s was admitted", label)
		}
	}
	full, err := browserfixture.Workspace()
	if err != nil {
		t.Fatal(err)
	}
	accepts("full", full)
	for _, name := range []string{"diffInput", "graphInput"} {
		absent := maps.Clone(full)
		delete(absent, name)
		accepts(name+" absent", absent)
		null := maps.Clone(full)
		null[name] = nil
		accepts(name+" null", null)
		wrong := maps.Clone(full)
		wrong[name] = []any{}
		refuses(name+" array", wrong)
	}
	for _, name := range []string{"context", "schemaVersion", "workspaceId"} {
		missing := maps.Clone(full)
		delete(missing, name)
		refuses(name+" missing", missing)
	}
	for label, mutate := range map[string]func(map[string]any){
		"unknown":       func(v map[string]any) { v["foreign"] = true },
		"version-2":     func(v map[string]any) { v["schemaVersion"] = json.Number("2") },
		"version-text":  func(v map[string]any) { v["schemaVersion"] = "3" },
		"id-pattern":    func(v map[string]any) { v["workspaceId"] = "bad id" },
		"id-long":       func(v map[string]any) { v["workspaceId"] = strings.Repeat("ab.", 85) + "cd" },
		"context-type":  func(v map[string]any) { v["context"] = []any{} },
		"context-older": func(v map[string]any) { v["context"].(map[string]any)["schemaVersion"] = json.Number("3") },
	} {
		value := wireValue(t, full)
		mutate(value)
		refuses(label, value)
	}
	exact := wireValue(t, full)
	exact["workspaceId"] = strings.Repeat("ab.", 85) + "c"
	accepts("id at bound", exact)

	// A project-origin context is natively admissible, so the structure keeps
	// the requirement-context owner's two-origin sum rather than catalog only.
	fixture := projectfixture.New(t)
	rendered, _, err := prepareProject(t.Context(), fixture.Root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	project := wireValue(t, map[string]any{"schemaVersion": json.Number("3"), "workspaceId": "project.workspace", "context": requirementcontext.SnapshotValue(rendered.workspace.Snapshot)})
	accepts("project origin", project)
	if _, err := requirementcontext.SnapshotShape().Admit(project["context"], "context"); err != nil {
		t.Fatal(err)
	}
	if _, origin := project["context"].(map[string]any)["projectOrigin"]; !origin {
		t.Fatal("project fixture did not exercise the project origin")
	}
}

func TestCoverageProofModesAgreeWithNativeAdmission(t *testing.T) {
	for _, row := range []struct {
		mode   string
		mutate func(map[string]any)
		admit  bool
	}{
		{"structured", func(map[string]any) {}, true},
		{"structured", func(v map[string]any) { v["compactProofContract"] = nil }, true},
		{"structured", func(v map[string]any) {
			v["localEnvironmentPolicy"] = map[string]any{"authority": "caller_provided", "localEnvironmentClasses": []any{"local-go"}}
		}, true},
		{"structured", func(v map[string]any) { delete(v, "requirementProofBinding") }, false},
		{"structured", func(v map[string]any) { v["requirementProofBinding"] = nil }, false},
		{"compact", func(map[string]any) {}, true},
		{"compact", func(v map[string]any) { v["requirementProofBinding"] = nil }, true},
		{"compact", func(v map[string]any) { v["localEnvironmentPolicy"] = nil }, false},
		{"compact", func(v map[string]any) { delete(v, "localEnvironmentPolicy") }, false},
		{"compact", func(v map[string]any) { v["compactProofContract"] = nil }, false},
	} {
		input, err := browserfixture.CoverageInput(row.mode)
		if err != nil {
			t.Fatal(err)
		}
		if row.mode == "compact" && input["localEnvironmentPolicy"] == nil {
			t.Fatal("compact fixture lacks local environment policy")
		}
		value := wireValue(t, input)
		row.mutate(value)
		_, _, err = BuildPlan(value, Options{View: "coverage"})
		if (err == nil) != row.admit {
			t.Fatalf("%s coverage admission=%v, want %v", row.mode, err, row.admit)
		}
	}
	structured, _ := browserfixture.CoverageInput("structured")
	compact, _ := browserfixture.CoverageInput("compact")
	both := wireValue(t, structured)
	both["compactProofContract"] = compact["compactProofContract"]
	both["localEnvironmentPolicy"] = compact["localEnvironmentPolicy"]
	if _, _, err := BuildPlan(both, Options{View: "coverage"}); err == nil {
		t.Fatal("coverage admitted both proof modes")
	}
}

func postPacketRequest(t *testing.T, handle ServerHandle, capability, endpoint string, value any) []byte {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, handle.URL+"api/v1/"+endpoint, bytes.NewReader(stableWorkspaceBytes(t, value)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", strings.TrimSuffix(handle.URL, "/"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Proofkit-Browser-Capability", capability)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("%s status=%d body=%s", endpoint, response.StatusCode, body)
	}
	return body
}

func wireValue(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return decoded.(map[string]any)
}

func expandContextReferences(raw any, snapshot map[string]any) any {
	switch value := raw.(type) {
	case map[string]any:
		if reflect.DeepEqual(value, contextReference()) {
			return snapshot
		}
		result := make(map[string]any, len(value))
		for key, child := range value {
			result[key] = expandContextReferences(child, snapshot)
		}
		return result
	case []any:
		result := make([]any, len(value))
		for i, child := range value {
			result[i] = expandContextReferences(child, snapshot)
		}
		return result
	}
	return raw
}

func stringsAny(values []string) []any {
	result := make([]any, len(values))
	for i, value := range values {
		result[i] = value
	}
	return result
}
