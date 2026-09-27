package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessschedulerplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const legacyUnicodeStep = "Verify required legacy Unicode recovery"
const legacyUnicodeCommand = "go test ./internal/kernel/repositorytransaction -run '^TestCanonicalDialectWholeLegacyRecovery$' -count=1 -timeout=90s -v -args -proofkit-require-legacy-unicode-positive"
const legacyUnicodeWitness = "proofkit.transaction-legacy-positive"
const legacyUnicodeClass = "local-go-legacy-positive"

func validateCILegacyUnicodeStep(job githubJob) error {
	index, err := uniqueStepIndex(job.Steps, legacyUnicodeStep)
	if err != nil || index < 0 {
		return fmt.Errorf("CI must contain exactly one required Unicode recovery witness")
	}
	step := job.Steps[index]
	wantEnv := ciSourceQualityStepEnv()[legacyUnicodeStep]
	if step.Run != legacyUnicodeCommand || !step.runPresent || !reflect.DeepEqual(step.Env, wantEnv) ||
		step.If != "" || step.ifPresent || step.ContinueOnError != nil || step.continueOnErrorPresent ||
		step.Uses != "" || step.usesPresent || step.With != nil || step.withPresent || step.ID != "" || step.idPresent ||
		step.Shell != nil || step.shellPresent || step.WorkingDirectory != nil || step.workingDirectoryPresent ||
		step.TimeoutMinutes != nil || step.timeoutMinutesPresent {
		return fmt.Errorf("CI Unicode witness lost its exact required-mode invocation")
	}
	ordinary, err := uniqueStepIndex(job.Steps, "Run all Go tests")
	if err != nil || index != ordinary+1 {
		return fmt.Errorf("required Unicode witness must follow ordinary Go tests")
	}
	for _, name := range []string{"Verify self-hosting receipts", "Verify self-hosting coverage", "Verify release closeout"} {
		next, err := uniqueStepIndex(job.Steps, name)
		if err != nil || next <= index {
			return fmt.Errorf("required Unicode witness must precede %s", name)
		}
	}
	return nil
}

func TestCILegacyUnicodeRequiresPositiveMode(t *testing.T) {
	base := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err := validateCIRequiredAggregate(base); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name  string
		apply func(*githubJob, int)
	}{
		{"missing step", func(job *githubJob, i int) { job.Steps = append(job.Steps[:i], job.Steps[i+1:]...) }},
		{"duplicate step", func(job *githubJob, i int) { job.Steps = append(job.Steps, job.Steps[i]) }},
		{"missing declared-mode flag", func(job *githubJob, i int) {
			job.Steps[i].Run = "go test ./internal/kernel/repositorytransaction -run '^TestCanonicalDialectWholeLegacyRecovery$' -count=1 -timeout=90s -v"
		}},
		{"disabled declared-mode flag", func(job *githubJob, i int) { job.Steps[i].Run += "=false" }},
		{"invalid declared-mode flag", func(job *githubJob, i int) { job.Steps[i].Run += "=invalid" }},
		{"shadow flags", func(job *githubJob, i int) { job.Steps[i].Env["GOFLAGS"] = "-run=TestMissing" }},
		{"missing selector", func(job *githubJob, i int) {
			job.Steps[i].Run = "go test ./internal/kernel/repositorytransaction -run '^TestMissing$' -count=1 -v"
		}},
		{"ASCII substitution", func(job *githubJob, i int) {
			job.Steps[i].Run = "go test ./internal/kernel/repositorytransaction -run '^TestCanonicalDialectWholeLegacyASCIILifecycle$' -count=1 -timeout=90s -v"
		}},
		{"cached command", func(job *githubJob, i int) {
			job.Steps[i].Run = "go test ./internal/kernel/repositorytransaction -run '^TestCanonicalDialectWholeLegacyRecovery$' -v"
		}},
		{"no-op", func(job *githubJob, i int) { job.Steps[i].Run = "true" }},
		{"masked exit", func(job *githubJob, i int) { job.Steps[i].Run += " || true" }},
		{"background", func(job *githubJob, i int) { job.Steps[i].Run += " &" }},
		{"conditional", func(job *githubJob, i int) { job.Steps[i].If = "false" }},
		{"null condition", func(job *githubJob, i int) { job.Steps[i].ifPresent = true }},
		{"continue", func(job *githubJob, i int) { job.Steps[i].ContinueOnError = true }},
		{"wrong cwd", func(job *githubJob, i int) { job.Steps[i].WorkingDirectory = "elsewhere" }},
		{"late witness", func(job *githubJob, i int) {
			job.Steps[i], job.Steps[len(job.Steps)-1] = job.Steps[len(job.Steps)-1], job.Steps[i]
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			workflow := cloneWorkflow(t, base)
			job := workflow.Jobs["source-quality"]
			i, err := uniqueStepIndex(job.Steps, legacyUnicodeStep)
			if err != nil {
				t.Fatal(err)
			}
			mutation.apply(&job, i)
			workflow.Jobs["source-quality"] = job
			if err := validateCILegacyUnicodeStep(job); err == nil {
				t.Fatal("isolated required-mode predicate accepted mutation")
			}
			if err := validateCIRequiredAggregate(workflow); err == nil {
				t.Fatal("aggregate admitted weakened Unicode witness")
			}
		})
	}
	for _, mutation := range []string{"missing job", "missing dependency", "conditional job"} {
		workflow := cloneWorkflow(t, base)
		switch mutation {
		case "missing job":
			delete(workflow.Jobs, "source-quality")
		case "missing dependency":
			job := workflow.Jobs["ci-required-gate"]
			job.Needs = []any{"browser-runtime", "platform-smoke"}
			workflow.Jobs["ci-required-gate"] = job
		case "conditional job":
			job := workflow.Jobs["source-quality"]
			job.If = "false"
			workflow.Jobs["source-quality"] = job
		}
		if err := validateCIRequiredAggregate(workflow); err == nil {
			t.Fatal("aggregate accepted " + mutation)
		}
	}
}

func legacyNamedRecord(raw any, key, id string) (map[string]any, error) {
	rows, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("legacy witness record collection is absent")
	}
	var found map[string]any
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid legacy witness record")
		}
		if row[key] == id {
			if found != nil {
				return nil, fmt.Errorf("duplicate legacy witness record")
			}
			found = row
		}
	}
	if found == nil {
		return nil, fmt.Errorf("missing legacy witness record %s", id)
	}
	return found, nil
}

func validateLegacyWitnessPlan(plan, bindings map[string]any) error {
	report, code, err := witnessschedulerplan.Build(plan)
	if err != nil || code != 0 || report.State != "passed" {
		return fmt.Errorf("native scheduler did not admit legacy witness plan: state=%s code=%d error=%v", report.State, code, err)
	}
	if _, code, err := requirementbinding.BuildReport(bindings); err != nil || code != 0 {
		return fmt.Errorf("native binding admission failed")
	}
	command, err := legacyNamedRecord(plan["commands"], "id", legacyUnicodeWitness)
	if err != nil {
		return err
	}
	argv := []string{"go", "test", "./internal/kernel/repositorytransaction", "-run", "^TestCanonicalDialectWholeLegacyRecovery$", "-count=1", "-timeout=90s", "-v", "-args", "-proofkit-require-legacy-unicode-positive"}
	want := map[string]any{
		"schemaVersion": json.Number("1"), "id": legacyUnicodeWitness, "cwd": ".",
		"argv":        admit.StringSliceToAny(argv),
		"environment": map[string]any{"inherit": "allowlist", "allowlist": []any{"GOCACHE", "GOFLAGS", "GOMAXPROCS", "GOMODCACHE", "GOPATH", "GOROOT", "GOTOOLCHAIN", "HOME", "PATH", "TMPDIR"}, "classes": []any{legacyUnicodeClass}},
		"timeoutMs":   json.Number("120000"), "networkPolicy": "none", "credentialClass": "none", "cachePolicy": "disabled",
		"expectedArtifacts": []any{}, "parallelGroup": "local-go-static", "exitCodePolicy": map[string]any{"kind": "zero", "successCodes": []any{json.Number("0")}},
	}
	if !reflect.DeepEqual(command, want) {
		return fmt.Errorf("legacy positive command differs from exact owner declaration")
	}
	class, err := legacyNamedRecord(plan["vocabulary"].(map[string]any)["environmentClassPolicies"], "environmentClass", legacyUnicodeClass)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(class, map[string]any{"environmentClass": legacyUnicodeClass, "networkPolicies": []any{"none"}, "credentialClasses": []any{"none"}, "cachePolicies": []any{"disabled"}}) {
		return fmt.Errorf("legacy positive environment policy changed")
	}
	policy, err := legacyNamedRecord(plan["policies"], "commandId", legacyUnicodeWitness)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(policy["inputSelectors"], []any{".github/workflows/ci.yml", "go.mod", "go.sum", "internal/kernel/pathidentity", "internal/kernel/repositorytransaction", "proofkit/requirement-bindings.json", "proofkit/witness-plan.json", "scripts/workflow_legacy_unicode_test.go"}) ||
		!reflect.DeepEqual(policy["nonClaims"], []any{
			"Ordinary local-go runs may prove native refusal only and cannot satisfy this command's positive obligation.",
			"Owned transaction fixture preparation qualifies exact identities, spelling, bytes and modes, not a filesystem-wide Unicode equivalence relation.",
			"Successful required-mode execution demands exactly all 28 frozen Unicode positive lifecycle IDs; zero, duplicate, substituted and negative IDs do not satisfy this witness.",
			"The declared test argument enables required-positive mode independently of environment variables; ordinary execution without that argument does not satisfy this witness.",
		}) {
		return fmt.Errorf("legacy positive prerequisite or proof-class boundary changed")
	}
	bound, err := legacyNamedRecord(bindings["witnessCommands"], "commandId", legacyUnicodeWitness)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(bound, map[string]any{"commandId": legacyUnicodeWitness, "command": strings.Join(argv, " "), "environmentClass": legacyUnicodeClass}) {
		return fmt.Errorf("legacy required witness command/environment mismatch")
	}
	row, err := legacyNamedRecord(bindings["bindings"], "scenarioId", "proofkit.spec-proof-core.repository-transaction-required-unicode-positive")
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(row["commandIds"], []any{legacyUnicodeWitness}) || !reflect.DeepEqual(row["environmentClasses"], []any{legacyUnicodeClass}) {
		return fmt.Errorf("required Unicode witness was demoted to ordinary execution")
	}
	ordinary, err := legacyNamedRecord(bindings["bindings"], "scenarioId", "proofkit.spec-proof-core.repository-transaction-canonical-caseless")
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(ordinary["commandIds"], []any{"proofkit.go-test"}) || !reflect.DeepEqual(ordinary["environmentClasses"], []any{"local-go"}) {
		return fmt.Errorf("ordinary witness was promoted to positive execution")
	}
	return nil
}

func cloneLegacyWitnessRecord(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := admission.DecodeJSON(bytes.NewReader(content), 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	return raw.(map[string]any)
}

func TestLegacyUnicodeWitnessPlanClosure(t *testing.T) {
	plan, err := readJSONObject(filepath.Join("..", "proofkit", "witness-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := readJSONObject(filepath.Join("..", "proofkit", "requirement-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLegacyWitnessPlan(plan, bindings); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"command", "missing declared-mode flag", "disabled declared-mode flag", "invalid declared-mode flag", "allowlist", "class", "mode boundary", "inputs", "required demoted", "ordinary promoted", "display command", "quoted display command", "display class"} {
		t.Run(mutation, func(t *testing.T) {
			p, b := cloneLegacyWitnessRecord(t, plan), cloneLegacyWitnessRecord(t, bindings)
			command, _ := legacyNamedRecord(p["commands"], "id", legacyUnicodeWitness)
			policy, _ := legacyNamedRecord(p["policies"], "commandId", legacyUnicodeWitness)
			required, _ := legacyNamedRecord(b["bindings"], "scenarioId", "proofkit.spec-proof-core.repository-transaction-required-unicode-positive")
			ordinary, _ := legacyNamedRecord(b["bindings"], "scenarioId", "proofkit.spec-proof-core.repository-transaction-canonical-caseless")
			display, _ := legacyNamedRecord(b["witnessCommands"], "commandId", legacyUnicodeWitness)
			switch mutation {
			case "command":
				command["argv"] = []any{"go", "test", "./internal/kernel/repositorytransaction", "-run", "^TestMissing$"}
			case "missing declared-mode flag":
				command["argv"] = command["argv"].([]any)[:8]
			case "disabled declared-mode flag":
				argv := command["argv"].([]any)
				argv[len(argv)-1] = "-proofkit-require-legacy-unicode-positive=false"
			case "invalid declared-mode flag":
				argv := command["argv"].([]any)
				argv[len(argv)-1] = "-proofkit-require-legacy-unicode-positive=invalid"
			case "allowlist":
				command["environment"].(map[string]any)["allowlist"] = []any{"PATH"}
			case "class":
				command["environment"].(map[string]any)["classes"] = []any{"local-go"}
			case "mode boundary":
				policy["nonClaims"] = []any{}
			case "inputs":
				policy["inputSelectors"] = []any{}
			case "required demoted":
				required["commandIds"], required["environmentClasses"] = []any{"proofkit.go-test"}, []any{"local-go"}
			case "ordinary promoted":
				ordinary["commandIds"], ordinary["environmentClasses"] = []any{legacyUnicodeWitness}, []any{legacyUnicodeClass}
			case "display command":
				display["command"] = "go test ./..."
			case "quoted display command":
				display["command"] = legacyUnicodeCommand
			case "display class":
				display["environmentClass"] = "local-go"
			}
			if err := validateLegacyWitnessPlan(p, b); err == nil {
				t.Fatal("legacy witness owner mutation admitted")
			}
		})
	}
}
