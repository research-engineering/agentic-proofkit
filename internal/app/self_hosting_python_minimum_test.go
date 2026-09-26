package app

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessschedulerplan"
)

const minimumWitnessID = "proofkit.python-minimum"
const minimumWitnessEnvironment = "local-go-python-native-docker"

const expectedMinimumWitnessCommand = `{
  "schemaVersion": 1,
  "id": "proofkit.python-minimum",
  "cwd": ".",
  "argv": [
    "go",
    "run",
    "./internal/tools/pythonpackage",
    "verify-minimum"
  ],
  "environment": {
    "inherit": "allowlist",
    "allowlist": [
      "DOCKER_CONFIG",
      "DOCKER_CONTEXT",
      "DOCKER_HOST",
      "GOCACHE",
      "GOFLAGS",
      "GOMAXPROCS",
      "GOMODCACHE",
      "GOPATH",
      "GOROOT",
      "GOTOOLCHAIN",
      "HOME",
      "PATH",
      "TMPDIR"
    ],
    "classes": [
      "local-go-python-native-docker"
    ]
  },
  "timeoutMs": 360000,
  "networkPolicy": "external",
  "credentialClass": "none",
  "cachePolicy": "disabled",
  "expectedArtifacts": [],
  "parallelGroup": "python-minimum-runtime",
  "exitCodePolicy": {
    "kind": "zero",
    "successCodes": [
      0
    ]
  }
}`

const expectedMinimumWitnessPolicy = `{
  "commandId": "proofkit.python-minimum",
  "inputSelectors": [
    ".",
    "artifacts/pypi/*.whl",
    "artifacts/pypi/python-packages.json"
  ],
  "outputSelectors": [],
  "resourceReads": [
    "resource.proofkit.docker-daemon",
    "resource.proofkit.docker-image-cache",
    "resource.proofkit.go-build-cache",
    "resource.proofkit.package-artifacts",
    "resource.proofkit.public-package-sources",
    "resource.proofkit.source"
  ],
  "resourceWrites": [
    "resource.proofkit.docker-containers",
    "resource.proofkit.docker-image-cache",
    "resource.proofkit.go-build-cache",
    "resource.proofkit.temporary-workdir"
  ],
  "exclusiveLocks": [],
  "sideEffectClass": "network",
  "deterministicOutput": false,
  "cacheAdmissionRefs": [],
  "retryPolicy": {
    "kind": "none",
    "maxAttempts": 1
  },
  "cancellationPolicy": {
    "kind": "cooperative",
    "graceMs": 30000
  },
  "timeoutPolicy": {
    "kind": "bounded",
    "timeoutMs": 360000
  },
  "nonClaims": [
    "Disabled cachePolicy prohibits witness-result reuse, not Go build-cache or Docker image-cache writes.",
    "Native prerequisites are not provisioned by this plan: repository-root execution, go and git on PATH, an accessible native Linux arm64/amd64 Docker daemon matching host architecture, and the fresh package:artifact wheel set.",
    "Network external covers host acquisition of the pinned official image, checksum-pinned pip wheel, and required Go dependencies; installed CPython 3.9.0/pip 26.0.1 execution is offline and unprivileged.",
    "Planned environment allowlisting is a caller obligation; this metadata does not attest ambient CI filtering, registry credential absence, or daemon state.",
    "Prerequisite ordering is owned by CI and native validation, not a scheduler dependency graph; this record does not execute or authenticate a minimum-runtime witness.",
    "Shared Docker and Go caches may be populated; images are retained without exclusive ownership or cleanup. Only the owned container and temporary workdir are removed before success; SIGKILL or daemon loss can prevent cleanup.",
    "The command emits its bounded observation on stdout and does not create a repository proof-receipt artifact or promote package-artifact receipts to minimum-runtime proof."
  ]
}`

const expectedMinimumEnvironmentPolicy = `{
  "environmentClass": "local-go-python-native-docker",
  "networkPolicies": [
    "external"
  ],
  "credentialClasses": [
    "none"
  ],
  "cachePolicies": [
    "disabled"
  ]
}`

func minimumNamedRecord(raw any, key, id string) (map[string]any, error) {
	records, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("missing minimum owner record collection")
	}
	var found map[string]any
	for _, item := range records {
		record, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid minimum owner record")
		}
		if record[key] == id {
			if found != nil {
				return nil, fmt.Errorf("duplicate minimum owner record")
			}
			found = record
		}
	}
	if found == nil {
		return nil, fmt.Errorf("missing minimum owner record %s", id)
	}
	return found, nil
}

func minimumHas(raw any, value string) bool {
	values, ok := raw.([]any)
	return ok && slices.Contains(values, any(value))
}

func checkSelfHostingMinimumPlan(plan, binding, producer map[string]any, commandWant, policyWant, classWant any) error {
	_, report, exit, err := witnessschedulerplan.Evaluate(plan)
	if err != nil || exit != 0 || report.State != "passed" {
		return fmt.Errorf("native scheduler rejects minimum plan: %v %v", err, report.Diagnostics)
	}
	_, exit, err = requirementbinding.BuildReport(binding)
	if err != nil || exit != 0 {
		return fmt.Errorf("native binding admission failed: %v", err)
	}
	command, err := minimumNamedRecord(plan["commands"], "id", minimumWitnessID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(command, commandWant) {
		return fmt.Errorf("minimum command differs from its exact native execution contract")
	}
	policy, err := minimumNamedRecord(plan["policies"], "commandId", minimumWitnessID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(policy, policyWant) {
		return fmt.Errorf("minimum prerequisite/effect/cleanup policy differs from its owner contract")
	}
	vocabulary := plan["vocabulary"].(map[string]any)
	if !minimumHas(vocabulary["environmentClasses"], minimumWitnessEnvironment) ||
		!minimumHas(vocabulary["parallelGroups"], "python-minimum-runtime") {
		return fmt.Errorf("minimum environment or group vocabulary is missing")
	}
	class, err := minimumNamedRecord(vocabulary["environmentClassPolicies"], "environmentClass", minimumWitnessEnvironment)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(class, classWant) {
		return fmt.Errorf("minimum environment policy must admit external acquisition and disable result caching")
	}
	boundCommand, err := minimumNamedRecord(binding["witnessCommands"], "commandId", minimumWitnessID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(boundCommand, map[string]any{
		"commandId": minimumWitnessID, "command": "go run ./internal/tools/pythonpackage verify-minimum",
		"environmentClass": minimumWitnessEnvironment,
	}) {
		return fmt.Errorf("minimum display argv/environment differs from the explicit catalog")
	}
	linked := 0
	for _, raw := range binding["bindings"].([]any) {
		row := raw.(map[string]any)
		if minimumHas(row["commandIds"], minimumWitnessID) {
			linked++
			if !minimumHas(row["environmentClasses"], minimumWitnessEnvironment) {
				return fmt.Errorf("minimum scenario lost its native Docker environment")
			}
		} else if minimumHas(row["environmentClasses"], minimumWitnessEnvironment) {
			return fmt.Errorf("minimum environment was assigned to an unrelated command")
		}
	}
	if linked != 2 {
		return fmt.Errorf("minimum command must bind exactly the installed runtime and CI split scenarios")
	}
	for _, id := range []string{"proofkit.python-package.minimum-installed", "proofkit.ci.proof-class-split"} {
		row, err := minimumNamedRecord(binding["bindings"], "witnessId", id)
		if err != nil {
			return err
		}
		if !minimumHas(row["commandIds"], minimumWitnessID) {
			return fmt.Errorf("minimum scenario omitted its command")
		}
	}
	if minimumHas(producer["environmentClasses"], minimumWitnessEnvironment) || minimumHas(producer["receiptKinds"], minimumWitnessID) {
		return fmt.Errorf("aggregate package producer was promoted to minimum-runtime authority")
	}
	for _, raw := range producer["producers"].([]any) {
		row := raw.(map[string]any)
		if minimumHas(row["environmentClasses"], minimumWitnessEnvironment) || minimumHas(row["receiptKinds"], minimumWitnessID) {
			return fmt.Errorf("existing producer was promoted to minimum-runtime authority")
		}
	}
	return nil
}

func TestSelfHostingPythonMinimumWitnessPlanClosure(t *testing.T) {
	base := readCLIJSONObject(t, "proofkit/witness-plan.json")
	bindings := readCLIJSONObject(t, "proofkit/requirement-bindings.json")
	producers := readCLIJSONObject(t, "proofkit/receipt-producer-policy.json")
	commandWant := decodeCLIJSON(t, expectedMinimumWitnessCommand)
	policyWant := decodeCLIJSON(t, expectedMinimumWitnessPolicy)
	classWant := decodeCLIJSON(t, expectedMinimumEnvironmentPolicy)
	if err := checkSelfHostingMinimumPlan(base, bindings, producers, commandWant, policyWant, classWant); err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name  string
		apply func(map[string]any, map[string]any, map[string]any)
	}{
		{"command omitted", func(p, b, r map[string]any) { p["commands"] = minimumWithout(p["commands"], "id", minimumWitnessID) }},
		{"policy omitted", func(p, b, r map[string]any) {
			p["policies"] = minimumWithout(p["policies"], "commandId", minimumWitnessID)
		}},
		{"wrong argv", func(p, b, r map[string]any) {
			c, _ := minimumNamedRecord(p["commands"], "id", minimumWitnessID)
			c["argv"] = []any{"go", "run", "./internal/tools/pythonpackage", "verify"}
		}},
		{"network omitted", func(p, b, r map[string]any) {
			c, _ := minimumNamedRecord(p["commands"], "id", minimumWitnessID)
			c["networkPolicy"] = "none"
		}},
		{"result cache enabled", func(p, b, r map[string]any) {
			c, _ := minimumNamedRecord(p["commands"], "id", minimumWitnessID)
			c["cachePolicy"] = "write-local"
		}},
		{"ambient environment assumed", func(p, b, r map[string]any) {
			c, _ := minimumNamedRecord(p["commands"], "id", minimumWitnessID)
			c["environment"].(map[string]any)["inherit"] = "none"
			c["environment"].(map[string]any)["allowlist"] = []any{}
		}},
		{"native class replaced", func(p, b, r map[string]any) {
			c, _ := minimumNamedRecord(p["commands"], "id", minimumWitnessID)
			c["environment"].(map[string]any)["classes"] = []any{"local-go-python"}
		}},
		{"environment policy omitted", func(p, b, r map[string]any) {
			v := p["vocabulary"].(map[string]any)
			v["environmentClassPolicies"] = minimumWithout(v["environmentClassPolicies"], "environmentClass", minimumWitnessEnvironment)
		}},
		{"offline auto projection allowed", func(p, b, r map[string]any) {
			v := p["vocabulary"].(map[string]any)
			c, _ := minimumNamedRecord(v["environmentClassPolicies"], "environmentClass", minimumWitnessEnvironment)
			c["networkPolicies"] = []any{"external", "none"}
		}},
		{"prerequisites omitted", func(p, b, r map[string]any) {
			c, _ := minimumNamedRecord(p["policies"], "commandId", minimumWitnessID)
			c["inputSelectors"] = []any{}
		}},
		{"shared writes hidden", func(p, b, r map[string]any) {
			c, _ := minimumNamedRecord(p["policies"], "commandId", minimumWitnessID)
			c["resourceWrites"] = []any{}
		}},
		{"fictional lock", func(p, b, r map[string]any) {
			c, _ := minimumNamedRecord(p["policies"], "commandId", minimumWitnessID)
			c["exclusiveLocks"] = []any{"lock.proofkit.docker-daemon"}
		}},
		{"cleanup boundary omitted", func(p, b, r map[string]any) {
			c, _ := minimumNamedRecord(p["policies"], "commandId", minimumWitnessID)
			c["nonClaims"] = []any{"Plan only."}
		}},
		{"wrong bound class", func(p, b, r map[string]any) {
			c, _ := minimumNamedRecord(b["witnessCommands"], "commandId", minimumWitnessID)
			c["environmentClass"] = "local-go-python"
		}},
		{"scenario operand missing", func(p, b, r map[string]any) {
			c, _ := minimumNamedRecord(b["bindings"], "witnessId", "proofkit.python-package.minimum-installed")
			c["environmentClasses"] = []any{"local-go-python"}
		}},
		{"CI command omitted", func(p, b, r map[string]any) {
			c, _ := minimumNamedRecord(b["bindings"], "witnessId", "proofkit.ci.proof-class-split")
			c["commandIds"] = []any{"proofkit.go-test"}
		}},
		{"producer promoted", func(p, b, r map[string]any) { r["environmentClasses"] = []any{minimumWitnessEnvironment} }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			p, b, r := cloneMinimumPlanOwner(t, base), cloneMinimumPlanOwner(t, bindings), cloneMinimumPlanOwner(t, producers)
			if err := checkSelfHostingMinimumPlan(p, b, r, commandWant, policyWant, classWant); err != nil {
				t.Fatalf("unchanged mutation control failed: %v", err)
			}
			mutation.apply(p, b, r)
			if err := checkSelfHostingMinimumPlan(p, b, r, commandWant, policyWant, classWant); err == nil {
				t.Fatal("minimum witness owner mutation was accepted")
			}
		})
	}
}

func cloneMinimumPlanOwner(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	return decodeCLIJSON(t, string(adoptionHelpJSON(t, value))).(map[string]any)
}

func minimumWithout(raw any, key, id string) []any {
	out := []any{}
	for _, item := range raw.([]any) {
		if item.(map[string]any)[key] != id {
			out = append(out, item)
		}
	}
	return out
}

func TestSelfHostingPythonMinimumRequiresExplicitCatalog(t *testing.T) {
	plan := readCLIJSONObject(t, "proofkit/witness-plan.json")
	bindings := readCLIJSONObject(t, "proofkit/requirement-bindings.json")
	vocabulary := cloneMinimumPlanOwner(t, plan["vocabulary"].(map[string]any))
	vocabulary["parallelGroups"] = []any{"python-minimum-runtime"}
	_, err := requirementbinding.BuildWitnessPlanInput(bindings, vocabulary)
	if err == nil || !strings.Contains(err.Error(), minimumWitnessEnvironment) || !strings.Contains(err.Error(), "must admit networkPolicy none") {
		t.Fatalf("binding-only projection must not invent offline acquisition: %v", err)
	}
	_, report, exit, err := witnessschedulerplan.Evaluate(plan)
	if err != nil || exit != 0 || report.State != "passed" {
		t.Fatalf("explicit catalog rejected: %v %v", err, report.Diagnostics)
	}
}
