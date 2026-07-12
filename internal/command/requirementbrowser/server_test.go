package requirementbrowser

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestStartServerServesExplicitSourceViews(t *testing.T) {
	handle, err := StartServer(sourceInput(t), Options{
		Host:    "127.0.0.1",
		Port:    0,
		PortSet: true,
		View:    "source",
	})
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer closeTestServer(t, handle)
	if !strings.HasPrefix(handle.URL, "http://127.0.0.1:") {
		t.Fatalf("unexpected URL: %s", handle.URL)
	}
	client := http.Client{Timeout: 5 * time.Second}

	root, err := client.Get(handle.URL)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer root.Body.Close()
	if root.StatusCode != http.StatusOK {
		t.Fatalf("unexpected root status: %d", root.StatusCode)
	}
	if !strings.Contains(root.Header.Get("content-type"), "text/html") {
		t.Fatalf("unexpected root content-type: %s", root.Header.Get("content-type"))
	}
	rootBody, err := io.ReadAll(root.Body)
	if err != nil {
		t.Fatalf("read root body: %v", err)
	}
	rootOutput := string(rootBody)
	for _, want := range []string{
		"Requirement Source View",
		"REQ-BROWSER-001",
		"The browser server serves admitted requirement views from explicit input only.",
		"docs/contracts/proof-bindings/browser.json",
		"Browser samples do not claim repository rollout readiness.",
	} {
		if !strings.Contains(rootOutput, want) {
			t.Fatalf("source server output missing %q:\n%s", want, rootOutput)
		}
	}

	health, err := client.Get(handle.URL + "healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("unexpected health status: %d", health.StatusCode)
	}
	var status map[string]any
	if err := json.NewDecoder(health.Body).Decode(&status); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if status["authority"] != "presentation_adapter_status" || status["state"] != "ok" || status["view"] != "source" {
		t.Fatalf("unexpected health status: %#v", status)
	}

	rejected, err := client.Post(handle.URL, "text/plain", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST /: %v", err)
	}
	defer rejected.Body.Close()
	if rejected.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected rejected method status: %d", rejected.StatusCode)
	}
	if rejected.Header.Get("allow") != "GET, HEAD" {
		t.Fatalf("unexpected allow header: %s", rejected.Header.Get("allow"))
	}

	missing, err := client.Get(handle.URL + "missing")
	if err != nil {
		t.Fatalf("GET /missing: %v", err)
	}
	defer missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("unexpected missing status: %d", missing.StatusCode)
	}

	for _, item := range []struct {
		name   string
		host   string
		origin string
	}{
		{name: "foreign host", host: "attacker.invalid"},
		{name: "foreign origin", origin: "https://attacker.invalid"},
	} {
		t.Run(item.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, handle.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			if item.host != "" {
				request.Host = item.host
			}
			if item.origin != "" {
				request.Header.Set("origin", item.origin)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("status=%d, want forbidden", response.StatusCode)
			}
		})
	}
}

func TestStartServerServesExplicitProofViews(t *testing.T) {
	handle, err := StartServer(proofInput(t), Options{
		Host:           "127.0.0.1",
		Port:           0,
		PortSet:        true,
		View:           "proof",
		ProofViewScope: "graph",
	})
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer closeTestServer(t, handle)
	client := http.Client{Timeout: 5 * time.Second}

	response, err := client.Get(handle.URL)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected root status: %d", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read root body: %v", err)
	}
	output := string(body)
	for _, want := range []string{
		"Requirement Proof View",
		"Scenarios and test witnesses",
		"proofkit.browser.scenario",
		"proofkit.browser.witness",
		"internal/browser_test.go",
		"proofkit.browser.command",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("proof server output missing %q:\n%s", want, output)
		}
	}
}

func TestStartServerServesExplicitCoverageViews(t *testing.T) {
	handle, err := StartServer(coverageInput(t), Options{
		Host:    "127.0.0.1",
		Port:    0,
		PortSet: true,
		View:    "coverage",
	})
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer closeTestServer(t, handle)
	client := http.Client{Timeout: 5 * time.Second}

	response, err := client.Get(handle.URL)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected root status: %d", response.StatusCode)
	}
	if !strings.Contains(response.Header.Get("content-type"), "text/html") {
		t.Fatalf("unexpected root content-type: %s", response.Header.Get("content-type"))
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read root body: %v", err)
	}
	output := string(body)
	for _, want := range []string{
		"Requirement Coverage View",
		"REQ-BROWSER-COVERAGE-001",
		"covered_by_semantic_falsifier",
		"Test evidence",
		"Route-only evidence remains insufficient.",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("coverage server output missing %q:\n%s", want, output)
		}
	}
	health, err := client.Get(handle.URL + "healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("unexpected health status: %d", health.StatusCode)
	}
	var status map[string]any
	if err := json.NewDecoder(health.Body).Decode(&status); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if status["authority"] != "presentation_adapter_status" || status["state"] != "ok" || status["view"] != "coverage" {
		t.Fatalf("unexpected health status: %#v", status)
	}
}

func TestStartServerServesExplicitSpecTreeViews(t *testing.T) {
	handle, err := StartServer(specTreeInput(t), Options{
		Host:    "127.0.0.1",
		Port:    0,
		PortSet: true,
		View:    "spec-tree",
	})
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer closeTestServer(t, handle)
	client := http.Client{Timeout: 5 * time.Second}

	response, err := client.Get(handle.URL)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected root status: %d", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read root body: %v", err)
	}
	output := string(body)
	for _, want := range []string{
		"Requirement Spec Tree View",
		"Specification tree",
		"Download Markdown",
		"data-proofkit-download",
		"Module spec",
		"docs/specs/module/requirements.v1.json",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("spec-tree server output missing %q:\n%s", want, output)
		}
	}
	health, err := client.Get(handle.URL + "healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer health.Body.Close()
	var status map[string]any
	if err := json.NewDecoder(health.Body).Decode(&status); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if status["view"] != "spec-tree" || status["viewKind"] != "proofkit.requirement-spec-tree-view" {
		t.Fatalf("unexpected health status: %#v", status)
	}
}

func TestServeReportsBrowserOpenFailure(t *testing.T) {
	t.Setenv("PATH", filepath.Join(t.TempDir(), "missing-bin"))
	err := Serve(t.Context(), sourceInput(t), Options{
		Host:    "127.0.0.1",
		Open:    true,
		Port:    0,
		PortSet: true,
		View:    "source",
	}, readyWriter{ready: make(chan string, 1)})
	if err == nil || !strings.Contains(err.Error(), "open browser") {
		t.Fatalf("unexpected open failure: %v", err)
	}
}

func TestServeStopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	ready := make(chan string, 1)
	go func() {
		done <- Serve(ctx, sourceInput(t), Options{
			Host:    "127.0.0.1",
			Port:    0,
			PortSet: true,
			View:    "source",
		}, readyWriter{ready: ready})
	}()
	select {
	case output := <-ready:
		if !strings.Contains(output, "Proofkit requirement browser: http://127.0.0.1:") {
			cancel()
			t.Fatalf("unexpected server output: %q", output)
		}
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("server did not publish URL")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not stop after context cancellation")
	}
}

func TestServerCloseForcesTerminationAfterGracefulDeadline(t *testing.T) {
	handle, err := StartServer(sourceInput(t), Options{Host: "127.0.0.1", Port: 0, PortSet: true, View: "source"})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("tcp", net.JoinHostPort(handle.Host, strconv.Itoa(handle.Port)))
	if err != nil {
		closeTestServer(t, handle)
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, "GET / HTTP/1.1\r\nHost: "+net.JoinHostPort(handle.Host, strconv.Itoa(handle.Port))+"\r\n"); err != nil {
		t.Fatal(err)
	}
	shutdownCtx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_ = handle.Close(shutdownCtx)
	select {
	case <-handle.Done():
	case <-time.After(time.Second):
		t.Fatal("server did not reach terminal state after forced close")
	}
}

type readyWriter struct {
	ready chan<- string
}

func (writer readyWriter) Write(bytes []byte) (int, error) {
	select {
	case writer.ready <- string(bytes):
	default:
	}
	return len(bytes), nil
}

func TestStartServerFailsClosedForNonLoopbackHosts(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.094034782477634282784990120509101846539349621662349085355544682336212659794052")
	for _, host := range []string{"0.0.0.0", "localhost"} {
		t.Run(host, func(t *testing.T) {
			_, err := StartServer(sourceInput(t), Options{
				Host:    host,
				Port:    0,
				PortSet: true,
				View:    "source",
			})
			if err == nil || !strings.Contains(err.Error(), "host must be loopback") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func sourceInput(t *testing.T) any {
	t.Helper()
	input, err := admission.DecodeJSON(strings.NewReader(`{
  "schemaVersion": 1,
  "sourceId": "proofkit.requirement-browser.source",
  "specPackagePath": "docs/specs/browser",
  "overviewPath": "docs/specs/browser/overview.md",
  "requirementsPath": "docs/specs/browser/requirements.v1.json",
  "requirements": [
    {
      "requirementId": "REQ-BROWSER-001",
      "ownerId": "browser.owner",
      "invariant": "The browser server serves admitted requirement views from explicit input only.",
      "claimLevel": "blocking",
      "riskClass": "high",
      "proofBindingRefs": ["docs/contracts/proof-bindings/browser.json"],
      "nonClaimRefs": ["NC-BROWSER-001"],
      "nonClaims": ["Browser samples do not claim repository rollout readiness."],
      "lifecycle": {"state": "active", "replacementRequirementIds": [], "evidenceRefs": []},
      "deferral": null,
      "updatePolicy": {
        "reviewOwnerId": "browser.owner",
        "requiresImpactDeclaration": true,
        "requiresProofBindingReview": true
      }
    }
  ],
  "nonClaims": ["Consumer repositories own requirement meaning."]
}`), 1<<20)
	if err != nil {
		t.Fatalf("decode source fixture: %v", err)
	}
	return input
}

func proofInput(t *testing.T) any {
	t.Helper()
	input, err := admission.DecodeJSON(strings.NewReader(`{
  "schemaVersion": 1,
  "bindingId": "proofkit.browser.bindings",
  "requirements": [
    {
      "requirementId": "REQ-BROWSER-001",
      "ownerId": "browser.owner",
      "specPath": "docs/specs/browser/requirements.v1.json",
      "claimLevel": "blocking",
      "proofState": "witness_backed",
      "nonClaims": ["Browser proof samples do not execute native commands."]
    }
  ],
  "bindings": [
    {
      "requirementId": "REQ-BROWSER-001",
      "scenarioId": "proofkit.browser.scenario",
      "witnessId": "proofkit.browser.witness",
      "witnessKind": "contract",
      "witnessPath": "internal/browser_test.go",
      "commandIds": ["proofkit.browser.command"],
      "environmentClasses": ["local-go"]
    }
  ],
  "witnessCommands": [
    {
      "commandId": "proofkit.browser.command",
      "command": "go test ./internal/command/requirementbrowser",
      "environmentClass": "local-go"
    }
  ],
  "selection": {
    "changedPaths": [],
    "ownerIds": [],
    "requirementIds": []
  },
  "nonClaims": ["Browser proof fixture does not claim command execution."]
}`), 1<<20)
	if err != nil {
		t.Fatalf("decode proof fixture: %v", err)
	}
	return input
}

func coverageInput(t *testing.T) any {
	t.Helper()
	input, err := admission.DecodeJSON(strings.NewReader(`{
  "schemaVersion": 1,
  "viewInputId": "proofkit.browser.coverage.view",
  "requirementSource": {
    "schemaVersion": 1,
    "sourceId": "proofkit.browser.coverage.source",
    "specPackagePath": "docs/specs/browser-coverage",
    "overviewPath": "docs/specs/browser-coverage/overview.md",
    "requirementsPath": "docs/specs/browser-coverage/requirements.v1.json",
    "requirements": [
      {
        "requirementId": "REQ-BROWSER-COVERAGE-001",
        "ownerId": "browser.coverage",
        "invariant": "Coverage browser views render test evidence for each requirement.",
        "claimLevel": "blocking",
        "riskClass": "high",
        "proofBindingRefs": ["proofkit/browser-coverage-bindings.json"],
        "nonClaimRefs": [],
        "nonClaims": ["Coverage browser fixture does not execute tests."],
        "lifecycle": {"state": "active", "replacementRequirementIds": [], "evidenceRefs": []},
        "deferral": null,
        "updatePolicy": {
          "reviewOwnerId": "browser.coverage",
          "requiresImpactDeclaration": true,
          "requiresProofBindingReview": true
        }
      }
    ],
    "nonClaims": ["Coverage browser source fixture does not own native tests."]
  },
  "requirementProofBinding": {
    "schemaVersion": 1,
    "bindingId": "proofkit.browser.coverage.binding",
    "requirements": [
      {
        "requirementId": "REQ-BROWSER-COVERAGE-001",
        "ownerId": "browser.coverage",
        "specPath": "docs/specs/browser-coverage/requirements.v1.json",
        "claimLevel": "blocking",
        "proofState": "witness_backed",
        "nonClaims": ["Coverage browser binding fixture does not execute witnesses."]
      }
    ],
    "bindings": [
      {
        "requirementId": "REQ-BROWSER-COVERAGE-001",
        "scenarioId": "proofkit.browser.coverage.scenario",
        "witnessId": "proofkit.browser.coverage.witness",
        "witnessKind": "contract",
        "witnessPath": "internal/browser_coverage_test.go",
        "commandIds": ["proofkit.browser.coverage.command"],
        "environmentClasses": ["local-go"]
      }
    ],
    "witnessCommands": [
      {
        "commandId": "proofkit.browser.coverage.command",
        "command": "go test ./internal/command/requirementbrowser",
        "environmentClass": "local-go"
      }
    ],
    "selection": {"changedPaths": [], "ownerIds": [], "requirementIds": []},
    "nonClaims": ["Coverage browser binding fixture does not prove command pass evidence."]
  },
  "compactProofContract": null,
  "ownerInvariantRegistry": null,
  "coverageUniverse": {
    "schemaVersion": 1,
    "universeId": "proofkit.browser.coverage.universe",
    "authority": "caller_owned_inventory",
    "completenessDeclaration": "selected_owner_surfaces",
    "ownerIds": ["browser.coverage"],
    "codeSurfaces": [{"surfaceId": "browser.coverage.code", "ownerId": "browser.coverage", "path": "internal/command/requirementbrowser"}],
    "specSurfaces": [{"surfaceId": "browser.coverage.spec", "ownerId": "browser.coverage", "path": "docs/specs/browser-coverage/requirements.v1.json"}],
    "testSurfaces": [{"surfaceId": "browser.coverage.test", "ownerId": "browser.coverage", "path": "internal/command/requirementbrowser/server_test.go"}],
    "commandRefs": ["proofkit.browser.coverage.command"],
    "nonClaims": ["Coverage browser universe is selected-owner scope only."]
  },
  "testEvidenceInventory": {
    "schemaVersion": 1,
    "inventoryId": "proofkit.browser.coverage.inventory",
    "authority": "caller_owned_inventory",
    "entries": [
      {
        "testId": "test.browser.coverage.semantic",
        "selector": "go test ./internal/command/requirementbrowser -run TestStartServerServesExplicitCoverageViews",
        "sourcePath": "internal/command/requirementbrowser/server_test.go",
        "ownerId": "browser.coverage",
        "evidenceClass": "semantic_falsifier",
        "requirementRefs": ["REQ-BROWSER-COVERAGE-001"],
        "ownerInvariantRefs": [],
        "commandRefs": ["proofkit.browser.coverage.command"],
        "witnessRefs": ["proofkit.browser.coverage.witness"],
        "falsifier": {
          "falsifierId": "falsifier.browser.coverage",
          "negativeCaseId": "case.browser.coverage.route-only",
          "wrongImplementationClassId": "wrong.browser.coverage.no-test-detail",
          "dominanceGroup": "browser.coverage",
          "supersedes": []
        },
        "oracle": {
          "oracleId": "oracle.browser.coverage",
          "oracleKind": "html_contains_test_detail",
          "expectedPublicOutcome": "rendered report contains semantic test detail",
          "assertionSummary": "Route-only evidence remains insufficient."
        },
        "nonClaims": []
      }
    ],
    "nonClaims": ["Coverage browser inventory fixture does not execute native tests."]
  },
  "localEnvironmentPolicy": null,
  "options": {"scope": "graph"}
}`), 1<<20)
	if err != nil {
		t.Fatalf("decode coverage fixture: %v", err)
	}
	return input
}

func specTreeInput(t *testing.T) any {
	t.Helper()
	input, err := admission.DecodeJSON(strings.NewReader(`{
  "schemaVersion": 2,
  "treeId": "proofkit.browser.spec_tree",
  "rootNodeId": "meta",
  "callerAnnotations": ["Browser spec tree fixture is presentation-only."],
  "nodes": [
    {
      "nodeId": "meta",
      "nodeKind": "meta_spec",
      "label": "Meta spec",
      "displayOrder": 1,
      "sourceRefs": [
        {"sourceRefId": "source.meta", "sourceRole": "requirements", "sourceRefKind": "source_id", "sourceId": "spec.meta"}
      ],
      "callerAnnotations": []
    },
    {
      "nodeId": "module",
      "nodeKind": "module_spec",
      "label": "Module spec",
      "displayOrder": 1,
      "sourceRefs": [
        {
          "sourceRefId": "source.module",
          "sourceRole": "requirements",
          "sourceRefKind": "path_digest",
          "sourcePath": "docs/specs/module/requirements.v1.json",
          "recordedSourceDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "currentSourceDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "digestAlgorithm": "sha256"
        }
      ],
      "callerAnnotations": []
    }
  ],
  "edges": [{"parentNodeId": "meta", "childNodeId": "module"}],
  "overlays": [
    {
      "overlayId": "overlay.module.source",
      "overlayKind": "source",
      "targetNodeId": "module",
      "refKind": "source_ref",
      "refId": "source.module",
      "label": "Module source",
      "callerAnnotations": []
    }
  ]
}`), 1<<20)
	if err != nil {
		t.Fatalf("decode spec-tree fixture: %v", err)
	}
	return input
}

func closeTestServer(t *testing.T, handle ServerHandle) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := handle.Close(ctx); err != nil {
		t.Fatalf("close server: %v", err)
	}
}
