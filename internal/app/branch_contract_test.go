package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const branchContractInput = `{"schemaVersion":1,"reportId":"proofkit.test.branch","branchRefs":[{"refId":"proofkit.test.default","refKind":"repository_default","observedBranch":"main","expectedBranch":"main","required":true,"evidenceRef":"  declared observation  ","nonClaims":["  not live  "]}],"preexistingFailures":[],"nonClaims":["  caller observation  "]}`

func TestBranchAuthorityCLIWireAndInputTransports(t *testing.T) {
	path := filepath.Join(t.TempDir(), "branch.json")
	if err := os.WriteFile(path, []byte(branchContractInput), 0600); err != nil {
		t.Fatal(err)
	}
	stdin := runCLI(t, []string{"branch-authority", "--input", "-"}, branchContractInput)
	file := runCLI(t, []string{"branch-authority", "--input", path}, "")
	pointer := runCLI(t, []string{"branch-authority", "--input", "-", "--input-pointer", "/payload"}, `{"payload":`+branchContractInput+`}`)
	if !bytes.Equal(stdin, file) || !bytes.Equal(stdin, pointer) {
		t.Fatal("branch transport changed the wire report")
	}
	var output map[string]any
	if err := json.Unmarshal(stdin, &output); err != nil {
		t.Fatal(err)
	}
	if len(output) != 8 || output["schemaVersion"] != float64(1) || output["reportKind"] != "proofkit.branch-authority" || output["reportId"] != "proofkit.test.branch" || output["state"] != "passed" {
		t.Fatalf("wrong branch report: %s", stdin)
	}
	diagnostics := output["diagnostics"].([]any)
	ref := diagnostics[1].(map[string]any)["value"].([]any)[0].(map[string]any)
	if len(ref) != 8 || ref["evidenceRef"] != "declared observation" || ref["nonClaims"].([]any)[0] != "not live" || ref["alignment"] != "aligned" {
		t.Fatalf("native normalized observation did not reach the wire: %#v", ref)
	}
	claims := output["nonClaims"].([]any)
	if len(claims) != 6 || !strings.Contains(string(stdin), `"caller observation"`) || strings.Contains(string(stdin), "  caller observation  ") {
		t.Fatalf("root nonClaim normalization drift: %#v", claims)
	}
}

func TestBranchAuthorityCLISeparatesFramingAdmissionAndEvaluation(t *testing.T) {
	for _, test := range []struct {
		name, input, pointer, state, diagnostic string
	}{
		{name: "empty refs", input: `{"schemaVersion":1,"reportId":"proofkit.test.branch","branchRefs":[],"preexistingFailures":[],"nonClaims":["caller observation"]}`, diagnostic: "branch authority branchRefs must be a non-empty array"},
		{name: "empty root nonClaims", input: strings.Replace(branchContractInput, `"nonClaims":["  caller observation  "]`, `"nonClaims":[]`, 1), diagnostic: "branch authority nonClaims must be non-empty"},
		{name: "empty ref nonClaims", input: strings.Replace(branchContractInput, `"nonClaims":["  not live  "]`, `"nonClaims":[]`, 1), diagnostic: "nonClaims must be non-empty"},
		{name: "required drift", input: strings.Replace(branchContractInput, `"observedBranch":"main"`, `"observedBranch":"other"`, 1), state: "failed"},
		{name: "prior failure", input: strings.Replace(branchContractInput, `"preexistingFailures":[]`, `"preexistingFailures":["earlier failure"]`, 1), state: "failed"},
		{name: "fraction token", input: strings.Replace(branchContractInput, `"schemaVersion":1`, `"schemaVersion":1.0`, 1), diagnostic: "schemaVersion"},
		{name: "duplicate root", input: strings.Replace(branchContractInput, `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1), diagnostic: "duplicate"},
		{name: "duplicate outside pointer", input: `{"payload":` + branchContractInput + `,"other":{"key":1,"key":2}}`, pointer: "/payload", diagnostic: "duplicate"},
		{name: "unknown safe count", input: strings.Replace(branchContractInput, `"schemaVersion":1`, `"schemaVersion":1,"private-caller-key":true`, 1), diagnostic: "branch authority input has unsupported field(s): 1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := []string{"branch-authority", "--input", "-"}
			if test.pointer != "" {
				args = append(args, "--input-pointer", test.pointer)
			}
			var stdout, stderr bytes.Buffer
			code := Run(t.Context(), args, strings.NewReader(test.input), &stdout, &stderr)
			if code != 1 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if test.state != "" {
				var output map[string]any
				if err := json.Unmarshal(stdout.Bytes(), &output); err != nil || output["state"] != test.state || output["reportKind"] != "proofkit.branch-authority" || stderr.Len() != 0 {
					t.Fatalf("failed evaluation lost its JSON report: %v %s %s", err, stdout.String(), stderr.String())
				}
			} else if stdout.Len() != 0 || !strings.Contains(stderr.String(), test.diagnostic) || strings.Contains(stderr.String(), "private-caller-key") {
				t.Fatalf("wrong admission/framing failure: %s %s", stdout.String(), stderr.String())
			}
		})
	}
}
