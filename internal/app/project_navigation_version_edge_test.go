package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/commandroute"
	"github.com/research-engineering/agentic-proofkit/internal/tools/releasechange"
)

const projectNavigationVersionEdgePath = "internal/app/testdata/v0.9-wire-observations.json"
const frozenProjectNavigationPredecessorPath = "internal/app/testdata/v0.8-wire-observations.json"
const frozenProjectNavigationPredecessorSHA256 = "ed0651c53c015c00d8ed7a0db681a213e9df6248302c5f12fc898e4b6a82c5ab"
const frozenProjectNavigationCommandContractPath = "internal/app/testdata/releases/v0.8.0/preserved-command-contracts.json"
const frozenProjectNavigationCommandContractSHA256 = "907259153bb1e45e982295ec6081b40eb9f02b219c25af6004eb8c29a12c328a"

type projectNavigationVersionEdge struct {
	AddedCommandContracts    []versionEdgeCommandContract  `json:"addedCommandContracts"`
	AdditionChangeIDs        []string                      `json:"additionChangeIds"`
	BreakingChangeIDs        []string                      `json:"breakingChangeIds"`
	ChangeClass              string                        `json:"changeClass"`
	ChangeRecordRef          string                        `json:"changeRecordRef"`
	ChangeRecordSHA256       string                        `json:"changeRecordSha256"`
	ChangedCommandRoutes     []versionEdgeRouteReplacement `json:"changedCommandRoutes"`
	CommandContractSelection string                        `json:"commandContractSelection"`
	CurrentPublicABISHA256   string                        `json:"currentPublicAbiSha256"`
	EdgeID                   string                        `json:"edgeId"`
	EvidenceClass            string                        `json:"evidenceClass"`
	MigrationSteps           []string                      `json:"migrationSteps"`
	NonClaims                []string                      `json:"nonClaims"`
	ProcessContractChanges   []versionEdgeProcessChange    `json:"processContractChanges"`
	PreviousPublicABISHA256  string                        `json:"previousPublicAbiSha256"`
	PreviousVersion          string                        `json:"previousVersion"`
	SchemaVersion            int                           `json:"schemaVersion"`
	Version                  string                        `json:"version"`
}

type versionEdgeProcessChange struct {
	ChangeID      string `json:"changeId"`
	CurrentValue  string `json:"currentValue"`
	JSONPointer   string `json:"jsonPointer"`
	PreviousState string `json:"previousState"`
}

type versionEdgeRouteReplacement struct {
	Command                 string                      `json:"command"`
	CurrentRoute            []string                    `json:"currentRoute"`
	PreservedInputContract  versionEdgeContractIdentity `json:"preservedInputContract"`
	PreservedOutputContract versionEdgeContractIdentity `json:"preservedOutputContract"`
	PreviousRoute           []string                    `json:"previousRoute"`
}

type frozenProjectNavigationCommandContract struct {
	Command             string                      `json:"command"`
	CommandRouteGrammar frozenCommandRouteGrammar   `json:"commandRouteGrammar"`
	InputContract       versionEdgeContractIdentity `json:"inputContract"`
	NonClaims           []string                    `json:"nonClaims"`
	ObservationKind     string                      `json:"observationKind"`
	OutputContract      versionEdgeContractIdentity `json:"outputContract"`
	PublicABISHA256     string                      `json:"publicAbiSha256"`
	ReleaseVersion      string                      `json:"releaseVersion"`
	Route               []string                    `json:"route"`
	SchemaVersion       int                         `json:"schemaVersion"`
}

type frozenCommandRouteGrammar struct {
	AmbiguityPolicy string `json:"ambiguityPolicy"`
	MaximumTokens   int    `json:"maximumTokens"`
	MinimumTokens   int    `json:"minimumTokens"`
	Separator       string `json:"separator"`
	TokenPattern    string `json:"tokenPattern"`
}

func TestProjectNavigationVersionEdgeClosesPublicRoutes(t *testing.T) {
	record := readProjectNavigationVersionEdge(t)
	root := repoRoot(t)
	if err := validateProjectNavigationVersionEdge(record, root, root, currentCLIContractPublicABISHA256(t)); err != nil {
		t.Fatal(err)
	}
	assertProjectNavigationRouteCutover(t)

	mutants := []func(*projectNavigationVersionEdge){
		func(value *projectNavigationVersionEdge) { value.CurrentPublicABISHA256 += "0" },
		func(value *projectNavigationVersionEdge) {
			value.PreviousPublicABISHA256 = value.CurrentPublicABISHA256
		},
		func(value *projectNavigationVersionEdge) { value.ChangeClass = "compatible" },
		func(value *projectNavigationVersionEdge) {
			value.AddedCommandContracts = value.AddedCommandContracts[1:]
		},
		func(value *projectNavigationVersionEdge) {
			value.AddedCommandContracts[0].Route = []string{"project-next"}
		},
		func(value *projectNavigationVersionEdge) {
			value.AddedCommandContracts[1].OutputContract.ContractSHA256 += "0"
		},
		func(value *projectNavigationVersionEdge) {
			value.ChangedCommandRoutes[0].PreviousRoute = []string{"change", "plan"}
		},
		func(value *projectNavigationVersionEdge) {
			value.ChangedCommandRoutes[0].CurrentRoute = []string{"change-workflow-plan"}
		},
		func(value *projectNavigationVersionEdge) {
			value.ChangedCommandRoutes[0].PreservedInputContract.ContractID += ".drift"
		},
		func(value *projectNavigationVersionEdge) {
			value.ChangedCommandRoutes[0].Command = "different-command"
		},
		func(value *projectNavigationVersionEdge) {
			value.ChangedCommandRoutes[0].PreservedInputContract.ContractSHA256 += "0"
		},
		func(value *projectNavigationVersionEdge) {
			value.ChangedCommandRoutes[0].PreservedOutputContract.ContractID += ".drift"
		},
		func(value *projectNavigationVersionEdge) {
			value.ChangedCommandRoutes[0].PreservedOutputContract.ContractSHA256 += "0"
		},
		func(value *projectNavigationVersionEdge) { value.ChangedCommandRoutes = nil },
		func(value *projectNavigationVersionEdge) { value.BreakingChangeIDs = nil },
		func(value *projectNavigationVersionEdge) { value.AdditionChangeIDs = value.AdditionChangeIDs[1:] },
		func(value *projectNavigationVersionEdge) { value.MigrationSteps = nil },
		func(value *projectNavigationVersionEdge) { value.ChangeRecordSHA256 += "0" },
		func(value *projectNavigationVersionEdge) { value.CommandContractSelection = "all_digest_changes" },
		func(value *projectNavigationVersionEdge) { value.ProcessContractChanges = nil },
		func(value *projectNavigationVersionEdge) { value.ProcessContractChanges[0].CurrentValue = "different" },
		func(value *projectNavigationVersionEdge) { value.NonClaims = nil },
	}
	for index, mutate := range mutants {
		t.Run(fmt.Sprintf("mutant-%d", index), func(t *testing.T) {
			value := cloneProjectNavigationVersionEdge(record)
			mutate(&value)
			if err := validateProjectNavigationVersionEdge(value, root, root, currentCLIContractPublicABISHA256(t)); err == nil {
				t.Fatal("project navigation version-edge mutant was admitted")
			}
		})
	}
}

func TestProjectNavigationVersionEdgeRejectsCoordinatedChangeRecordDrift(t *testing.T) {
	record := readProjectNavigationVersionEdge(t)
	content, err := os.ReadFile(filepath.Join(repoRoot(t), record.ChangeRecordRef))
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	root := value.(map[string]any)
	root["breakingChanges"].([]any)[0].(map[string]any)["changeId"] = "proofkit.agent-workflow.change-plan-route.drift"
	mutantContent, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	mutantContent = append(mutantContent, '\n')
	mutantRoot := t.TempDir()
	path := filepath.Join(mutantRoot, filepath.FromSlash(record.ChangeRecordRef))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, mutantContent, 0o600); err != nil {
		t.Fatal(err)
	}
	mutant := cloneProjectNavigationVersionEdge(record)
	digest := sha256.Sum256(mutantContent)
	mutant.ChangeRecordSHA256 = fmt.Sprintf("sha256:%x", digest)
	if err := validateProjectNavigationVersionEdge(mutant, repoRoot(t), mutantRoot, currentCLIContractPublicABISHA256(t)); err == nil || !strings.Contains(err.Error(), "contradicts") {
		t.Fatalf("coordinated change-record mutant error=%v, want inventory contradiction", err)
	}
}

func TestProjectNavigationVersionEdgePreservesFrozenPredecessor(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repoRoot(t), frozenProjectNavigationPredecessorPath))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if got := fmt.Sprintf("%x", digest); got != frozenProjectNavigationPredecessorSHA256 {
		t.Fatalf("frozen predecessor digest=%s, want %s", got, frozenProjectNavigationPredecessorSHA256)
	}
	frozen := readFrozenProjectNavigationCommandContract(t)
	record := readProjectNavigationVersionEdge(t)
	replacement := record.ChangedCommandRoutes[0]
	if record.PreviousVersion != frozen.ReleaseVersion || record.PreviousPublicABISHA256 != frozen.PublicABISHA256 || replacement.Command != frozen.Command || !slices.Equal(replacement.PreviousRoute, frozen.Route) || replacement.PreservedInputContract != frozen.InputContract || replacement.PreservedOutputContract != frozen.OutputContract {
		t.Fatalf("version edge does not preserve the frozen predecessor contract: edge=%#v frozen=%#v", replacement, frozen)
	}
}

func readFrozenProjectNavigationCommandContract(t *testing.T) frozenProjectNavigationCommandContract {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), frozenProjectNavigationCommandContractPath))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if got := fmt.Sprintf("%x", digest); got != frozenProjectNavigationCommandContractSHA256 {
		t.Fatalf("frozen command contract digest=%s, want %s", got, frozenProjectNavigationCommandContractSHA256)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		t.Fatal("frozen command contract observation must be an object")
	}
	assertExactObjectKeys(t, root, []string{"command", "commandRouteGrammar", "inputContract", "nonClaims", "observationKind", "outputContract", "publicAbiSha256", "releaseVersion", "route", "schemaVersion"}, "frozen command contract observation")
	assertExactObjectKeys(t, root["commandRouteGrammar"].(map[string]any), []string{"ambiguityPolicy", "maximumTokens", "minimumTokens", "separator", "tokenPattern"}, "frozen command route grammar")
	assertExactObjectKeys(t, root["inputContract"].(map[string]any), []string{"contractId", "contractSha256"}, "frozen input contract")
	assertExactObjectKeys(t, root["outputContract"].(map[string]any), []string{"contractId", "contractSha256"}, "frozen output contract")
	var record frozenProjectNavigationCommandContract
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatal(err)
	}
	wantGrammar := frozenCommandRouteGrammar{
		AmbiguityPolicy: "no_route_is_prefix_of_another",
		MaximumTokens:   4,
		MinimumTokens:   1,
		Separator:       " ",
		TokenPattern:    "^[a-z0-9]+(?:-[a-z0-9]+)*$",
	}
	if record.SchemaVersion != 1 || record.ObservationKind != "proofkit.frozen-command-contract-observation" || record.ReleaseVersion != "0.8.0" || record.PublicABISHA256 != "sha256:b5ea707ee5851cea6b75442e4faf20e93879371faf3636e96a98ccd23b527463" || record.Command != "change-workflow-plan" || record.CommandRouteGrammar != wantGrammar || !slices.Equal(record.Route, []string{"change-workflow-plan"}) || !slices.Equal(record.NonClaims, []string{"This frozen source observation does not authenticate registry publication, provider state, consumer migration, or runtime compatibility."}) {
		t.Fatalf("frozen command contract observation is invalid: %#v", record)
	}
	return record
}

func readProjectNavigationVersionEdge(t *testing.T) projectNavigationVersionEdge {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), projectNavigationVersionEdgePath))
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		t.Fatal("project navigation version edge must be an object")
	}
	assertExactObjectKeys(t, root, []string{"addedCommandContracts", "additionChangeIds", "breakingChangeIds", "changeClass", "changeRecordRef", "changeRecordSha256", "changedCommandRoutes", "commandContractSelection", "currentPublicAbiSha256", "edgeId", "evidenceClass", "migrationSteps", "nonClaims", "previousPublicAbiSha256", "previousVersion", "processContractChanges", "schemaVersion", "version"}, "project navigation version edge")
	for index, raw := range root["addedCommandContracts"].([]any) {
		item := raw.(map[string]any)
		assertExactObjectKeys(t, item, []string{"command", "outputContract", "route"}, fmt.Sprintf("added command contract %d", index))
		assertExactObjectKeys(t, item["outputContract"].(map[string]any), []string{"contractId", "contractSha256"}, fmt.Sprintf("added command contract %d output", index))
	}
	for index, raw := range root["changedCommandRoutes"].([]any) {
		item := raw.(map[string]any)
		assertExactObjectKeys(t, item, []string{"command", "currentRoute", "preservedInputContract", "preservedOutputContract", "previousRoute"}, fmt.Sprintf("changed command route %d", index))
		for _, field := range []string{"preservedInputContract", "preservedOutputContract"} {
			assertExactObjectKeys(t, item[field].(map[string]any), []string{"contractId", "contractSha256"}, fmt.Sprintf("changed command route %d %s", index, field))
		}
	}
	for index, raw := range root["processContractChanges"].([]any) {
		assertExactObjectKeys(t, raw.(map[string]any), []string{"changeId", "currentValue", "jsonPointer", "previousState"}, fmt.Sprintf("process contract change %d", index))
	}
	var record projectNavigationVersionEdge
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func validateProjectNavigationVersionEdge(record projectNavigationVersionEdge, contractRoot, changeRecordRoot, currentABI string) error {
	if record.SchemaVersion != 1 || record.EdgeID != "proofkit.public-wire.0.8.0-to-0.9.0" || record.EvidenceClass != "owner_authored_current_version_edge_observation" {
		return fmt.Errorf("project navigation version-edge identity is invalid")
	}
	if record.PreviousVersion != "0.8.0" || record.Version != "0.9.0" || record.ChangeClass != "breaking" {
		return fmt.Errorf("project navigation version-edge release identity is invalid")
	}
	if record.CommandContractSelection != "added_commands_changed_routes_and_process_contract" {
		return fmt.Errorf("project navigation command-contract selection policy is invalid")
	}
	if record.PreviousPublicABISHA256 != "sha256:b5ea707ee5851cea6b75442e4faf20e93879371faf3636e96a98ccd23b527463" || record.CurrentPublicABISHA256 != "sha256:"+currentABI || record.PreviousPublicABISHA256 == record.CurrentPublicABISHA256 {
		return fmt.Errorf("project navigation version-edge ABI identity is invalid")
	}
	currentAdded, err := currentVersionEdgeCommandContracts(contractRoot, []string{"next", "status"})
	if err != nil {
		return err
	}
	if !slices.EqualFunc(record.AddedCommandContracts, currentAdded, equalVersionEdgeCommandContract) {
		return fmt.Errorf("project navigation added command contracts are not exact")
	}
	currentRoute, err := currentVersionEdgeRouteReplacement(contractRoot)
	if err != nil {
		return err
	}
	if !slices.EqualFunc(record.ChangedCommandRoutes, []versionEdgeRouteReplacement{currentRoute}, equalVersionEdgeRouteReplacement) {
		return fmt.Errorf("project navigation route replacement is not exact")
	}
	processChanges := []versionEdgeProcessChange{{
		ChangeID: "proofkit.cli-contract.omitted-route-policy", CurrentValue: commandroute.OmittedRoutePolicy,
		JSONPointer: "/processContract/commandRouteGrammar/omittedRoutePolicy", PreviousState: "absent",
	}}
	if !slices.Equal(record.ProcessContractChanges, processChanges) || currentOmittedRoutePolicy(contractRoot) != commandroute.OmittedRoutePolicy {
		return fmt.Errorf("project navigation process-contract change is not exact")
	}
	if !slices.Equal(record.BreakingChangeIDs, []string{"proofkit.agent-workflow.change-plan-route", "proofkit.cli-contract.omitted-route-policy"}) || !slices.Equal(record.AdditionChangeIDs, []string{"proofkit.project-state.next-action", "proofkit.project-state.status"}) {
		return fmt.Errorf("project navigation change inventory is not exact")
	}
	if record.ChangeRecordRef != releasechange.RecordPath {
		return fmt.Errorf("project navigation change record reference is not exact")
	}
	changeRecordPath := filepath.Join(changeRecordRoot, filepath.FromSlash(record.ChangeRecordRef))
	changeRecordContent, err := os.ReadFile(changeRecordPath)
	if err != nil {
		return fmt.Errorf("read project navigation change record: %w", err)
	}
	digest := sha256.Sum256(changeRecordContent)
	if record.ChangeRecordSHA256 != fmt.Sprintf("sha256:%x", digest) {
		return fmt.Errorf("project navigation change record digest is not exact")
	}
	changeRecord, err := releasechange.Read(changeRecordPath)
	if err != nil {
		return fmt.Errorf("admit project navigation change record: %w", err)
	}
	if changeRecord.PreviousVersion != record.PreviousVersion || changeRecord.Version != record.Version || changeRecord.ChangeClass != record.ChangeClass || !changeRecord.Migration.Required || !slices.Equal(record.MigrationSteps, changeRecord.Migration.Steps) {
		return fmt.Errorf("project navigation change record identity is inconsistent")
	}
	if !slices.Equal(record.BreakingChangeIDs, releaseChangeIDs(changeRecord.BreakingChanges)) || !slices.Equal(record.AdditionChangeIDs, releaseChangeIDs(changeRecord.Additions)) {
		return fmt.Errorf("project navigation change inventory contradicts the bound change record")
	}
	if !slices.Equal(record.NonClaims, []string{"This owner-authored version-edge observation binds source and contract identities; it does not authenticate registry publication, provider ingestion, consumer migration, native witness truth, rollout, or production readiness."}) {
		return fmt.Errorf("project navigation version-edge non-claims are not exact")
	}
	return nil
}

func currentVersionEdgeCommandContracts(root string, names []string) ([]versionEdgeCommandContract, error) {
	contract, err := readVersionEdgeCLIContract(root)
	if err != nil {
		return nil, err
	}
	result := make([]versionEdgeCommandContract, 0, len(names))
	for _, name := range names {
		command, err := findVersionEdgeCommand(contract, name)
		if err != nil {
			return nil, err
		}
		metadata := generatedCommandContractMetadataByName[name]
		if command.InputContract != nil || metadata.InputContractSHA256 != "" || metadata.OutputContractSHA256 == "" {
			return nil, fmt.Errorf("current CLI contract has unexpected input or incomplete output metadata for %s", name)
		}
		result = append(result, versionEdgeCommandContract{
			Command: name,
			OutputContract: versionEdgeContractIdentity{
				ContractID:     contractIDFromRaw(command.OutputContract),
				ContractSHA256: metadata.OutputContractSHA256,
			},
			Route: effectiveContractRoute(command),
		})
	}
	return result, nil
}

func currentVersionEdgeRouteReplacement(root string) (versionEdgeRouteReplacement, error) {
	contract, err := readVersionEdgeCLIContract(root)
	if err != nil {
		return versionEdgeRouteReplacement{}, err
	}
	command, err := findVersionEdgeCommand(contract, "change-workflow-plan")
	if err != nil {
		return versionEdgeRouteReplacement{}, err
	}
	metadata := generatedCommandContractMetadataByName[command.Command]
	if command.InputContract == nil || metadata.InputContractSHA256 == "" || metadata.OutputContractSHA256 == "" {
		return versionEdgeRouteReplacement{}, fmt.Errorf("current change plan contract metadata is incomplete")
	}
	return versionEdgeRouteReplacement{
		Command:       command.Command,
		PreviousRoute: []string{"change-workflow-plan"},
		CurrentRoute:  effectiveContractRoute(command),
		PreservedInputContract: versionEdgeContractIdentity{
			ContractID: contractIDFromRaw(command.InputContract), ContractSHA256: metadata.InputContractSHA256,
		},
		PreservedOutputContract: versionEdgeContractIdentity{
			ContractID: contractIDFromRaw(command.OutputContract), ContractSHA256: metadata.OutputContractSHA256,
		},
	}, nil
}

func readVersionEdgeCLIContract(root string) (cliContract, error) {
	content, err := os.ReadFile(filepath.Join(root, "proofkit", "cli-contract.v2.json"))
	if err != nil {
		return cliContract{}, fmt.Errorf("read current CLI contract: %w", err)
	}
	contract, err := admission.DecodeTypedJSON[cliContract](bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return cliContract{}, fmt.Errorf("admit current CLI contract: %w", err)
	}
	return contract, nil
}

func findVersionEdgeCommand(contract cliContract, name string) (cliContractCommand, error) {
	for _, command := range contract.Commands {
		if command.Command == name {
			return command, nil
		}
	}
	return cliContractCommand{}, fmt.Errorf("current CLI contract is missing %s", name)
}

func equalVersionEdgeRouteReplacement(left, right versionEdgeRouteReplacement) bool {
	return left.Command == right.Command && slices.Equal(left.PreviousRoute, right.PreviousRoute) && slices.Equal(left.CurrentRoute, right.CurrentRoute) && left.PreservedInputContract == right.PreservedInputContract && left.PreservedOutputContract == right.PreservedOutputContract
}

func cloneProjectNavigationVersionEdge(record projectNavigationVersionEdge) projectNavigationVersionEdge {
	record.AddedCommandContracts = append([]versionEdgeCommandContract(nil), record.AddedCommandContracts...)
	for index := range record.AddedCommandContracts {
		record.AddedCommandContracts[index].Route = append([]string(nil), record.AddedCommandContracts[index].Route...)
	}
	record.ChangedCommandRoutes = append([]versionEdgeRouteReplacement(nil), record.ChangedCommandRoutes...)
	for index := range record.ChangedCommandRoutes {
		record.ChangedCommandRoutes[index].PreviousRoute = append([]string(nil), record.ChangedCommandRoutes[index].PreviousRoute...)
		record.ChangedCommandRoutes[index].CurrentRoute = append([]string(nil), record.ChangedCommandRoutes[index].CurrentRoute...)
	}
	record.ProcessContractChanges = append([]versionEdgeProcessChange(nil), record.ProcessContractChanges...)
	record.AdditionChangeIDs = append([]string(nil), record.AdditionChangeIDs...)
	record.BreakingChangeIDs = append([]string(nil), record.BreakingChangeIDs...)
	record.MigrationSteps = append([]string(nil), record.MigrationSteps...)
	record.NonClaims = append([]string(nil), record.NonClaims...)
	return record
}

func currentOmittedRoutePolicy(root string) string {
	content, err := os.ReadFile(filepath.Join(root, "proofkit", "cli-contract.v2.json"))
	if err != nil {
		return ""
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return ""
	}
	record, _ := value.(map[string]any)
	process, _ := record["processContract"].(map[string]any)
	grammar, _ := process["commandRouteGrammar"].(map[string]any)
	policy, _ := grammar["omittedRoutePolicy"].(string)
	return policy
}

func assertProjectNavigationRouteCutover(t *testing.T) {
	t.Helper()
	status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"change-workflow-plan", "--input", "-"}, panicReader{}, PresentationCapabilities{})
	if status != 1 || stdout != "" || !strings.Contains(stderr, "unsupported command: change-workflow-plan") {
		t.Fatalf("retired route status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	status, stdout, stderr = executeAgentWorkflowCLI(t, []string{"change", "plan", "--input", "-"}, bytes.NewBufferString(validChangeWorkflowInput), PresentationCapabilities{})
	if status != 0 || stdout == "" || stderr != "" {
		t.Fatalf("current route status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
}
