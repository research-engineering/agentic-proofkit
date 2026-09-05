package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/commandroute"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

const frozenProjectNavigationPublicABIPath = "internal/app/testdata/releases/v0.8.0/public-abi-observation.json"
const frozenProjectNavigationPublicABISHA256 = "ffff23ca84e014176d854104ea07eb92b10b4d6db7822f14f7859f6f6d360997"

const projectNavigationCommandFingerprintPolicy = "semantic_command_contract_without_native_source_digests"

type frozenProjectNavigationPublicABI struct {
	CommandFingerprintPolicy string            `json:"commandFingerprintPolicy"`
	Commands                 map[string]string `json:"commands"`
	ContractDefinitions      map[string]string `json:"contractDefinitions"`
	ContractID               string            `json:"contractId"`
	ContractSchemaVersion    int               `json:"contractSchemaVersion"`
	NonClaims                []string          `json:"nonClaims"`
	ObservationKind          string            `json:"observationKind"`
	OrderingPolicy           string            `json:"orderingPolicy"`
	PackageName              string            `json:"packageName"`
	ProcessContractSHA256    string            `json:"processContractSha256"`
	PublicABISHA256          string            `json:"publicAbiSha256"`
	ReleaseVersion           string            `json:"releaseVersion"`
	SchemaVersion            int               `json:"schemaVersion"`
}

func TestProjectNavigationVersionEdgeClosesCompletePublicABIDiff(t *testing.T) {
	frozen := readFrozenProjectNavigationPublicABI(t)
	current := readProjectNavigationCLIContractRaw(t)
	if err := verifyCompleteProjectNavigationABIDiff(frozen, current); err != nil {
		t.Fatal(err)
	}
}

func TestProjectNavigationVersionEdgeRejectsUndeclaredPublicABIDrift(t *testing.T) {
	frozen := readFrozenProjectNavigationPublicABI(t)
	current := readProjectNavigationCLIContractRaw(t)
	commands := current["commands"].([]any)
	for index, raw := range commands {
		record := raw.(map[string]any)
		if record["command"] != "impact" {
			continue
		}
		mutant := clonePublicABIRecord(record)
		mutant["route"] = []any{"impact-drift"}
		commands[index] = mutant
		if err := verifyCompleteProjectNavigationABIDiff(frozen, current); err == nil {
			t.Fatal("undeclared existing-command ABI drift was admitted")
		}
		return
	}
	t.Fatal("current CLI contract is missing impact")
}

func readFrozenProjectNavigationPublicABI(t *testing.T) frozenProjectNavigationPublicABI {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), frozenProjectNavigationPublicABIPath))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if got := fmt.Sprintf("%x", sum); got != frozenProjectNavigationPublicABISHA256 {
		t.Fatalf("frozen public ABI observation digest=%s, want %s", got, frozenProjectNavigationPublicABISHA256)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		t.Fatal("frozen public ABI observation must be an object")
	}
	assertExactObjectKeys(t, root, []string{"commandFingerprintPolicy", "commands", "contractDefinitions", "contractId", "contractSchemaVersion", "nonClaims", "observationKind", "orderingPolicy", "packageName", "processContractSha256", "publicAbiSha256", "releaseVersion", "schemaVersion"}, "frozen public ABI observation")
	var observation frozenProjectNavigationPublicABI
	if err := json.Unmarshal(content, &observation); err != nil {
		t.Fatal(err)
	}
	if observation.SchemaVersion != 1 || observation.ObservationKind != "proofkit.frozen-public-abi-observation" || observation.ReleaseVersion != "0.8.0" || observation.ContractID != "proofkit.cli-contract.v2" || observation.ContractSchemaVersion != 2 || observation.PackageName != "@research-engineering/agentic-proofkit" || observation.OrderingPolicy != "lexicographic_by_identity" || observation.CommandFingerprintPolicy != projectNavigationCommandFingerprintPolicy || observation.PublicABISHA256 != "sha256:b5ea707ee5851cea6b75442e4faf20e93879371faf3636e96a98ccd23b527463" || len(observation.Commands) == 0 || len(observation.ContractDefinitions) == 0 || !slices.Equal(observation.NonClaims, []string{"Per-command fingerprints omit only native source canonical digests; the exact raw contract remains bound by publicAbiSha256.", "This frozen source observation does not authenticate registry publication, provider state, consumer migration, or runtime compatibility."}) {
		t.Fatalf("frozen public ABI observation is invalid: %#v", observation)
	}
	for context, values := range map[string]map[string]string{"command": observation.Commands, "definition": observation.ContractDefinitions} {
		for id, value := range values {
			if id == "" {
				t.Fatalf("frozen %s identity is empty", context)
			}
			if _, err := admit.SHA256Ref(value, "frozen "+context+" digest"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := admit.SHA256Ref(observation.ProcessContractSHA256, "frozen process contract digest"); err != nil {
		t.Fatal(err)
	}
	return observation
}

func readProjectNavigationCLIContractRaw(t *testing.T) map[string]any {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), "proofkit", "cli-contract.v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		t.Fatal("current CLI contract must be an object")
	}
	return root
}

func verifyCompleteProjectNavigationABIDiff(frozen frozenProjectNavigationPublicABI, current map[string]any) error {
	schemaVersion, err := admit.CanonicalInteger(current["schemaVersion"], "current CLI contract schemaVersion")
	if err != nil || int(schemaVersion) != frozen.ContractSchemaVersion || current["contractId"] != frozen.ContractID || current["packageName"] != frozen.PackageName {
		return fmt.Errorf("current CLI contract header differs from the frozen predecessor")
	}
	commands, commandOrder, err := indexPublicABIRecords(current["commands"], "command")
	if err != nil {
		return err
	}
	if !slices.IsSorted(commandOrder) {
		return fmt.Errorf("current CLI command order is not canonical")
	}
	addedCommands := differenceKeys(commands, frozen.Commands)
	if !slices.Equal(addedCommands, []string{"next", "status"}) {
		return fmt.Errorf("current CLI contract has undeclared command additions: %v", addedCommands)
	}
	for name, wantDigest := range frozen.Commands {
		record, ok := commands[name]
		if !ok {
			return fmt.Errorf("current CLI contract removed predecessor command %s", name)
		}
		if name == "change-workflow-plan" {
			record = clonePublicABIRecord(record)
			delete(record, "route")
		}
		normalized, err := normalizePublicABICommandFingerprint(record)
		if err != nil {
			return fmt.Errorf("normalize current command %s: %w", name, err)
		}
		gotDigest, err := digest.StableJSONSHA256Ref(normalized)
		if err != nil {
			return fmt.Errorf("fingerprint current command %s: %w", name, err)
		}
		if gotDigest != wantDigest {
			return fmt.Errorf("current CLI command %s has undeclared ABI drift", name)
		}
	}

	definitions, definitionOrder, err := indexPublicABIRecords(current["contractDefinitions"], "definitionId")
	if err != nil {
		return err
	}
	if !slices.IsSorted(definitionOrder) {
		return fmt.Errorf("current CLI definition order is not canonical")
	}
	for id, wantDigest := range frozen.ContractDefinitions {
		record, ok := definitions[id]
		if !ok {
			return fmt.Errorf("current CLI contract removed predecessor definition %s", id)
		}
		gotDigest, err := digest.StableJSONSHA256Ref(record)
		if err != nil {
			return fmt.Errorf("fingerprint current definition %s: %w", id, err)
		}
		if gotDigest != wantDigest {
			return fmt.Errorf("current CLI definition %s has undeclared ABI drift", id)
		}
	}
	addedDefinitions := differenceKeys(definitions, frozen.ContractDefinitions)
	expectedDefinitions, err := addedCommandDefinitionClosure(commands, definitions, frozen.ContractDefinitions, []string{"next", "status"})
	if err != nil {
		return err
	}
	if !slices.Equal(addedDefinitions, expectedDefinitions) {
		return fmt.Errorf("current CLI definition additions are not exactly closed by added commands: got %v want %v", addedDefinitions, expectedDefinitions)
	}

	process, ok := current["processContract"].(map[string]any)
	if !ok {
		return fmt.Errorf("current CLI process contract is invalid")
	}
	normalizedProcess := clonePublicABIRecord(process)
	grammar, ok := process["commandRouteGrammar"].(map[string]any)
	if !ok {
		return fmt.Errorf("current CLI command route grammar is invalid")
	}
	normalizedGrammar := clonePublicABIRecord(grammar)
	if normalizedGrammar["omittedRoutePolicy"] != commandroute.OmittedRoutePolicy {
		return fmt.Errorf("current CLI omitted route policy is invalid")
	}
	delete(normalizedGrammar, "omittedRoutePolicy")
	normalizedProcess["commandRouteGrammar"] = normalizedGrammar
	processDigest, err := digest.StableJSONSHA256Ref(normalizedProcess)
	if err != nil {
		return fmt.Errorf("fingerprint normalized process contract: %w", err)
	}
	if processDigest != frozen.ProcessContractSHA256 {
		return fmt.Errorf("current CLI process contract has undeclared ABI drift")
	}
	return nil
}

func indexPublicABIRecords(raw any, identityField string) (map[string]map[string]any, []string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("CLI contract %s inventory must be an array", identityField)
	}
	indexed := make(map[string]map[string]any, len(values))
	order := make([]string, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("CLI contract %s record must be an object", identityField)
		}
		identity, ok := record[identityField].(string)
		if !ok || identity == "" {
			return nil, nil, fmt.Errorf("CLI contract %s record has no identity", identityField)
		}
		if _, exists := indexed[identity]; exists {
			return nil, nil, fmt.Errorf("CLI contract repeats %s %s", identityField, identity)
		}
		indexed[identity] = record
		order = append(order, identity)
	}
	return indexed, order, nil
}

func addedCommandDefinitionClosure(commands, definitions map[string]map[string]any, frozenDefinitions map[string]string, commandNames []string) ([]string, error) {
	queue := []string{}
	for _, name := range commandNames {
		command, ok := commands[name]
		if !ok {
			return nil, fmt.Errorf("current CLI contract is missing added command %s", name)
		}
		for _, field := range []string{"inputContract", "outputContract"} {
			contract, ok := command[field].(map[string]any)
			if !ok {
				continue
			}
			if root, ok := contract["rootDefinitionRef"].(string); ok && root != "" {
				queue = append(queue, root)
			}
		}
	}
	visited := map[string]bool{}
	result := []string{}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if visited[id] {
			continue
		}
		visited[id] = true
		definition, ok := definitions[id]
		if !ok {
			return nil, fmt.Errorf("added command references missing definition %s", id)
		}
		if _, existed := frozenDefinitions[id]; !existed {
			result = append(result, id)
		}
		references, ok := definition["definitionRefs"].([]any)
		if !ok {
			return nil, fmt.Errorf("definition %s has invalid definitionRefs", id)
		}
		for _, raw := range references {
			reference, ok := raw.(string)
			if !ok || reference == "" {
				return nil, fmt.Errorf("definition %s has invalid referenced identity", id)
			}
			queue = append(queue, reference)
		}
	}
	slices.Sort(result)
	return result, nil
}

func differenceKeys[V any, W any](current map[string]V, previous map[string]W) []string {
	result := []string{}
	for key := range current {
		if _, exists := previous[key]; !exists {
			result = append(result, key)
		}
	}
	slices.Sort(result)
	return result
}

func clonePublicABIRecord(value map[string]any) map[string]any {
	clone := make(map[string]any, len(value))
	for key, item := range value {
		clone[key] = item
	}
	return clone
}

func normalizePublicABICommandFingerprint(value map[string]any) (map[string]any, error) {
	normalized := clonePublicABIRecord(value)
	for _, contractField := range []string{"inputContract", "outputContract"} {
		rawContract, exists := normalized[contractField]
		if !exists || rawContract == nil {
			continue
		}
		contract, ok := rawContract.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", contractField)
		}
		contract = clonePublicABIRecord(contract)
		if rawSource, exists := contract["nativeSource"]; exists {
			source, ok := rawSource.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s nativeSource must be an object", contractField)
			}
			source = clonePublicABIRecord(source)
			if _, exists := source["canonicalDigest"]; !exists {
				return nil, fmt.Errorf("%s nativeSource has no canonicalDigest", contractField)
			}
			delete(source, "canonicalDigest")
			contract["nativeSource"] = source
		}
		if rawSources, exists := contract["nativeSources"]; exists {
			sources, ok := rawSources.([]any)
			if !ok {
				return nil, fmt.Errorf("%s nativeSources must be an array", contractField)
			}
			normalizedSources := make([]any, len(sources))
			for index, rawSource := range sources {
				source, ok := rawSource.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("%s nativeSources[%d] must be an object", contractField, index)
				}
				source = clonePublicABIRecord(source)
				if _, exists := source["canonicalDigest"]; !exists {
					return nil, fmt.Errorf("%s nativeSources[%d] has no canonicalDigest", contractField, index)
				}
				delete(source, "canonicalDigest")
				normalizedSources[index] = source
			}
			contract["nativeSources"] = normalizedSources
		}
		normalized[contractField] = contract
	}
	return normalized, nil
}
