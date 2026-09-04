package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

const compactOwnerImportPath = "github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"

const compactCurrentProductionConsumersPath = "internal/app/testdata/compact-current-production-consumers.json"

const proofkitModuleImportPath = "github.com/research-engineering/agentic-proofkit"

var compactConsumerRoots = []string{"."}

const compactProductionConsumerEvidenceClass = "conservative_static_candidate_inventory"

const compactProductionConsumerNonClaim = "Candidate inclusion proves a bounded static dependency or schema signal only; it does not prove runtime invocation, semantic ownership, or an absence of consumers that violate the declared static signal policy."

type compactProductionConsumerInventory struct {
	EvidenceClass string   `json:"evidenceClass"`
	InventoryID   string   `json:"inventoryId"`
	NonClaims     []string `json:"nonClaims"`
	Paths         []string `json:"paths"`
	SchemaVersion int      `json:"schemaVersion"`
}

var compactDistinctiveKeys = map[string]struct{}{
	"authority_state":                       {},
	"bindingRecordId":                       {},
	"binding_columns":                       {},
	"bindingVerifyCommands":                 {},
	"declaredMutationResistanceClaimId":     {},
	"declared_mutation_resistance_claim_id": {},
	"declaredWitnessRoutes":                 {},
	"witnessRouteId":                        {},
}

var compactDistinctiveFieldNames = map[string]struct{}{
	"BindingRecordID":                   {},
	"BindingVerifyCommands":             {},
	"DeclaredMutationResistanceClaimID": {},
	"DeclaredWitnessRoutes":             {},
	"WitnessRouteID":                    {},
}

var compactReviewedWrappers = map[string]map[string]struct{}{
	"github.com/research-engineering/agentic-proofkit/internal/command/conformanceprofile": {
		"BuildProfile": {}, "BuildVerification": {}, "List": {},
	},
	"github.com/research-engineering/agentic-proofkit/internal/command/impact": {
		"Build": {},
	},
	"github.com/research-engineering/agentic-proofkit/internal/command/pilotadmission": {
		"Build": {}, "BuildAllFromContractEnvelope": {}, "BuildFromContractEnvelope": {},
	},
	"github.com/research-engineering/agentic-proofkit/internal/command/proofbindingtestinventory": {
		"BuildNormalized": {}, "BuildReport": {},
	},
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding": {
		"BuildResolver": {},
	},
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageinput": {
		"Build": {},
	},
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview": {
		"AdmitOutput": {}, "BuildBrowserDocument": {}, "BuildHTML": {}, "BuildJSON": {}, "BuildMarkdown": {},
	},
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementimpactinput": {
		"Build": {},
	},
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofsourceset": {
		"Build": {},
	},
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofview": {
		"BuildBrowserDocument": {}, "BuildHTML": {}, "BuildJSON": {}, "BuildMarkdown": {},
	},
}

var compactSemanticSinks = []compactSemanticSink{{
	Sink: compactSymbolID{
		PackagePath: "github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory",
		Symbol:      "sortedWitnessRefs",
	},
	RequiredCaller: compactSymbolID{
		PackagePath: "github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory",
		Symbol:      "admitEntry",
	},
}}

func TestCompactProductionConsumerCandidateInventoryIsClosed(t *testing.T) {
	inventory := readCompactProductionConsumerInventory(t)
	actual, err := discoverCompactSymbolConsumersAcrossReleaseBuilds(repoRoot(t), compactConsumerRoots, compactReviewedWrappers, compactSemanticSinks)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(actual, inventory.Paths) {
		t.Fatalf("compact production consumer candidates=%v want literal current inventory %v", actual, inventory.Paths)
	}
}

func TestCompactV2ProductionSurfacesContainNoLegacyVocabulary(t *testing.T) {
	inventory := readCompactProductionConsumerInventory(t)
	paths := append([]string{}, inventory.Paths...)
	paths = append(paths,
		"docs/proofkit-contract-map.md",
		"docs/specs/proofkit-spec-proof-core/overview.md",
		"docs/specs/proofkit-spec-proof-core/requirements.v1.json",
		"internal/kernel/compactproofcontract/compactproofcontract.go",
		"internal/kernel/compactproofcontract/identity.go",
		"proofkit/cli-contract.v2.json",
	)
	sort.Strings(paths)
	legacy := map[string]map[string]struct{}{
		"changedRecordIds":                         {},
		"checkedWitnessSelectorCount":              {},
		"mutationResistanceContext":                {},
		"mutation_resistance_state":                {},
		"proofContractState":                       {},
		"proof_contract_state":                     {},
		"proofkit.compact.v1":                      {},
		"requirement-proof-bindings/fragment/v1":   {"internal/command/requirementproofsourceset/requirementproofsourceset.go": {}},
		"requirement-proof-bindings/fragment/v2":   {"internal/command/requirementproofsourceset/requirementproofsourceset.go": {}},
		"requirement-proof-bindings/source-set/v1": {"internal/command/requirementproofsourceset/requirementproofsourceset.go": {}},
	}
	root := repoRoot(t)
	for _, path := range paths {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read compact v2 production surface %s: %v", path, err)
		}
		for token, allowedPaths := range legacy {
			if !strings.Contains(string(content), token) {
				continue
			}
			if _, allowed := allowedPaths[path]; allowed {
				continue
			}
			t.Errorf("legacy compact vocabulary %q escaped into production surface %s", token, path)
		}
	}
}

func readCompactProductionConsumerInventory(t *testing.T) compactProductionConsumerInventory {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), compactCurrentProductionConsumersPath))
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		t.Fatal("compact production consumer inventory must be an object")
	}
	assertExactObjectKeys(t, record, []string{"evidenceClass", "inventoryId", "nonClaims", "paths", "schemaVersion"}, "compact production consumer inventory")
	if number, ok := record["schemaVersion"].(json.Number); !ok || number.String() != "1" {
		t.Fatalf("compact production consumer inventory schemaVersion=%v want 1", record["schemaVersion"])
	}
	inventory, err := admission.DecodeTypedJSON[compactProductionConsumerInventory](bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if inventory.InventoryID != "proofkit.compact.production-consumer-candidates.current" || inventory.EvidenceClass != compactProductionConsumerEvidenceClass {
		t.Fatal("compact production consumer inventory identity is invalid")
	}
	if !slices.Equal(inventory.NonClaims, []string{compactProductionConsumerNonClaim}) {
		t.Fatal("compact production consumer inventory non-claims are not exact")
	}
	if !sort.StringsAreSorted(inventory.Paths) || hasAdjacentDuplicate(inventory.Paths) {
		t.Fatal("compact production consumer inventory paths must be sorted and unique")
	}
	return inventory
}

func TestCompactReviewedWrappersResolveToCompactConsumerCandidates(t *testing.T) {
	if _, err := discoverCompactSymbolConsumersAcrossReleaseBuilds(repoRoot(t), compactConsumerRoots, compactReviewedWrappers, nil); err != nil {
		t.Fatal(err)
	}
}
