package app

import (
	"encoding/json"
	"slices"
	"testing"
)

// Pilot fixes narrowed admission (stale sourcePlan) and set a value the
// previous contract text left open (the verification route). Neither changes a
// wire shape or makes earlier contract text false, so both directions keep
// their contract identities and state the rule in their compatibility summary.
const (
	sourcePlanFreshnessContractPolicy = "sourcePlan is admitted only when its planId equals the sourcePlanId recorded in proofkit/project.v1.json or its repositoryInventory equals a fresh inventory of --repo-root; any other sourcePlan is refused as stale before any write."
	verificationRouteContractPolicy   = "verification_required names commandRoute [native-evidence-guidance], the read-only guide for running native witnesses and admitting their evidence; an empty commandRoute means only an owner stop. Records whose verification_required action names an empty route are refused."
)

func TestPilotSemanticChangesKeepTheirContractIdentities(t *testing.T) {
	commands, _, err := indexPublicABIRecords(readCLIContractRaw(t)["commands"], "command")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ command, direction, wire, semantic, policy string }{
		{"adopt-materialize-plan", "input", "2", "3", sourcePlanFreshnessContractPolicy},
		{"adopt-materialize-apply", "input", "2", "3", sourcePlanFreshnessContractPolicy},
		{"status", "output", "1", "1", verificationRouteContractPolicy},
		{"next", "output", "1", "1", verificationRouteContractPolicy},
	} {
		value, _ := commands[row.command][row.direction+"Contract"].(map[string]any)
		summary, _ := value["compatibilitySummary"].([]any)
		if value["contractId"] != "proofkit."+row.command+"."+row.direction+".v"+row.semantic || value["schemaVersion"] != json.Number(row.wire) || !slices.Contains(summary, any(row.policy)) {
			t.Fatalf("%s %s contract = %v %v, want semantic v%s on wire %s stating %q", row.command, row.direction, value["contractId"], value["schemaVersion"], row.semantic, row.wire, row.policy)
		}
	}
}
