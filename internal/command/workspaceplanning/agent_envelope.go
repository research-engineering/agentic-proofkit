package workspaceplanning

import "github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"

type omissionSeed struct {
	ID          string
	Count       int
	Reason      string
	EvidenceRef string
}

func BuildChangedPackagePlanEnvelope(plan map[string]any) map[string]any {
	changedPaths := stringArrayFromAny(plan["changedPaths"])
	rootPackageNames := stringArrayFromAny(plan["rootPackageNames"])
	fullWorkspace, _ := plan["fullWorkspace"].(bool)
	sourceRefs := map[string]string{
		"changedPaths":      "proofkit.workspace.changed.context.changed-paths",
		"escalationReasons": "proofkit.workspace.changed.context.escalation-reasons",
		"rootPackageNames":  "proofkit.workspace.changed.context.root-package-names",
	}
	omitted := workspaceOmissions([]omissionSeed{
		{"proofkit.workspace.changed.omitted.changed-paths", len(changedPaths), "Changed path values remain in the source report.", sourceRefs["changedPaths"]},
		{"proofkit.workspace.changed.omitted.root-package-names", len(rootPackageNames), "Selected package names remain in the source report.", sourceRefs["rootPackageNames"]},
	})
	fanout := "bounded"
	if fullWorkspace {
		fanout = "full-gate"
	} else if len(rootPackageNames) > 20 {
		fanout = "wide"
	}
	escalation := "Inspect the source report when selected package names are insufficient for the caller-owned proof decision."
	if fullWorkspace {
		escalation = "Run the caller-owned full workspace gate because the source plan declares escalation reasons."
	}
	clarification := []map[string]any{}
	if len(rootPackageNames) == 0 && !fullWorkspace {
		clarification = append(clarification, map[string]any{
			"askWhen":            "Changed paths did not select any package roots and no full-workspace escalation was declared.",
			"blocking":           false,
			"evidenceRefs":       []any{sourceRefs["changedPaths"]},
			"expectedAnswerKind": "policy_choice",
			"nonClaim":           "The clarification question does not infer a proof route.",
			"owner":              "consumer_repository",
			"question":           "Which caller-owned non-package or full-gate proof should cover this change?",
			"questionId":         "proofkit.workspace.changed.clarify.no-package-roots",
		})
	}
	applyInstruction := "Run caller-owned package gates for the selected root package names."
	applyRationale := "Selected root packages are the narrowest package scope admitted by the caller-provided graph facts."
	applyEvidence := []any{sourceRefs["rootPackageNames"]}
	if fullWorkspace {
		applyInstruction = "Run the caller-owned full workspace gate required by the escalation reasons."
		applyRationale = "Escalation reasons are explicit caller policy and must not be weakened by package selection."
		applyEvidence = []any{sourceRefs["escalationReasons"]}
	}
	return agentenvelope.Build(agentenvelope.Input{
		EnvelopeID: "proofkit.workspace-changed-package-plan.agent-envelope",
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Workspace changed-package plans are caller-provided facts and do not prove graph freshness.",
			"reportId":    "proofkit.workspace-changed-package-plan",
			"reportKind":  "proofkit.workspace-changed-package-plan",
			"stableHash":  nil,
			"state":       "passed",
		},
		Bounds: map[string]any{
			"escalation":      escalation,
			"fanout":          fanout,
			"maxActionItems":  3,
			"maxCommandRefs":  0,
			"maxContextRefs":  3,
			"maxOmittedItems": len(omitted),
			"maxReceiptRefs":  0,
			"maxTokenBudget":  2500,
			"nonClaim":        "Workspace planning envelope bounds do not prove package graph freshness, command adequacy, or merge satisfaction.",
			"omittedCount":    omittedCount(omitted),
		},
		ContextRefs: []map[string]any{
			contextRef(sourceRefs["changedPaths"], "json-pointer", "supporting", "/changedPaths", "Caller-provided changed paths that produced the selected package plan.", "Changed path refs do not prove git diff freshness or path ownership."),
			contextRef(sourceRefs["escalationReasons"], "json-pointer", "rule_reference", "/escalationReasons", "Caller-owned escalation reasons that force a full workspace plan.", "Escalation reasons do not prove command execution or merge approval."),
			contextRef(sourceRefs["rootPackageNames"], "json-pointer", "supporting", "/rootPackageNames", "Selected package roots for caller-owned package gates.", "Selected package roots do not prove dependency graph freshness or gate success."),
		},
		RouteQuestions:        workspaceQuestions([]any{sourceRefs["changedPaths"], sourceRefs["rootPackageNames"], sourceRefs["escalationReasons"]}),
		ClarificationQuestion: clarification,
		ActionPlan: []map[string]any{
			action("proofkit.workspace.changed.action.route-owner-policy", "route", "Load the caller-owned command registry and owner policy for the selected package plan.", "Proofkit selects package roots from caller facts but does not own command ids or proof adequacy.", []any{sourceRefs["rootPackageNames"]}, []any{"Workspace planning actions do not execute native witnesses or approve merge."}),
			action("proofkit.workspace.changed.action.apply-plan", "verify", applyInstruction, applyRationale, applyEvidence, []any{"Proofkit does not own the command registry, CI scheduling, proof freshness, or pass result."}),
			action("proofkit.workspace.changed.action-record-receipts", "verify", "Record caller-owned receipts for the native gates that were run.", "Planning output is not receipt evidence; merge decisions need admitted run facts from the consumer.", []any{sourceRefs["rootPackageNames"]}, []any{"The envelope does not create, authenticate, or freshen receipts."}),
		},
		Commands:             []map[string]any{},
		BlockedPreconditions: []map[string]any{},
		Omitted:              omitted,
		ReceiptRefs:          []map[string]any{},
		NonClaims: []string{
			"Workspace changed-package plan envelopes do not execute package gates.",
			"Workspace changed-package plan envelopes do not infer command ids.",
			"Workspace changed-package plan envelopes do not prove graph freshness, receipt freshness, merge approval, release approval, or rollout approval.",
		},
	})
}

func BuildShardPartitionEnvelope(partition map[string]any) map[string]any {
	failures := stringArrayFromAny(partition["failures"])
	rootPackageNames := stringArrayFromAny(partition["rootPackageNames"])
	shards, _ := partition["shards"].([]any)
	shardTotal, _ := partition["shardTotal"].(int)
	failed := len(failures) > 0
	sourceRefs := map[string]string{
		"failures":         "proofkit.workspace.shards.context.failures",
		"matrixRows":       "proofkit.workspace.shards.context.matrix-rows",
		"rootPackageNames": "proofkit.workspace.shards.context.root-package-names",
		"shards":           "proofkit.workspace.shards.context.shards",
	}
	omitted := workspaceOmissions([]omissionSeed{
		{"proofkit.workspace.shards.omitted.shards", len(shards), "Shard payloads remain in the source report.", sourceRefs["shards"]},
		{"proofkit.workspace.shards.omitted.root-package-names", len(rootPackageNames), "Root package names remain in the source report.", sourceRefs["rootPackageNames"]},
	})
	fanout := "bounded"
	if failed {
		fanout = "full-gate"
	} else if shardTotal > 8 {
		fanout = "wide"
	}
	escalation := "Use the matrix rows only with the caller-owned CI scheduler and command registry."
	if failed {
		escalation = "Fix the caller-owned shard input or run the caller-owned full gate before trusting the partition."
	}
	applyInstruction := "Pass packageShards.include to the caller-owned CI matrix and run caller-owned package gates per shard."
	applyRationale := "A passed partition gives deterministic shard rows without owning CI runner scheduling."
	applyEvidence := []any{sourceRefs["matrixRows"]}
	if failed {
		applyInstruction = "Use a caller-owned full gate or repair the shard input before running sharded package gates."
		applyRationale = "Fail-closed shard diagnostics prevent hidden package omission or duplicate execution."
		applyEvidence = []any{sourceRefs["failures"]}
	}
	blockers := []map[string]any{}
	if failed {
		blockers = append(blockers, map[string]any{
			"description":    "Shard partition has fail-closed diagnostics.",
			"evidenceRefs":   []any{sourceRefs["failures"]},
			"nonClaim":       "This blocker does not choose the consumer repository fallback gate.",
			"owner":          "consumer_repository",
			"preconditionId": "proofkit.workspace.shards.blocked.failed-partition",
		})
	}
	state := "passed"
	if failed {
		state = "failed"
	}
	return agentenvelope.Build(agentenvelope.Input{
		EnvelopeID: "proofkit.workspace-shard-partition.agent-envelope",
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Workspace shard partitions are caller-provided planning facts and do not prove CI execution.",
			"reportId":    "proofkit.workspace-shard-partition",
			"reportKind":  "proofkit.workspace-shard-partition",
			"stableHash":  nil,
			"state":       state,
		},
		Bounds: map[string]any{
			"escalation":      escalation,
			"fanout":          fanout,
			"maxActionItems":  3,
			"maxCommandRefs":  0,
			"maxContextRefs":  4,
			"maxOmittedItems": len(omitted),
			"maxReceiptRefs":  0,
			"maxTokenBudget":  2500,
			"nonClaim":        "Workspace shard envelope bounds do not prove dependency graph freshness, runner capacity, command success, or merge satisfaction.",
			"omittedCount":    omittedCount(omitted),
		},
		ContextRefs: []map[string]any{
			contextRef(sourceRefs["failures"], "json-pointer", "rule_reference", "/failures", "Fail-closed shard diagnostics when partition coverage is invalid.", "Failure refs do not repair the caller-owned graph or CI policy."),
			contextRef(sourceRefs["matrixRows"], "json-pointer", "supporting", "/packageShards/include", "Caller-consumable CI matrix rows for shard execution.", "Matrix rows do not schedule runners or execute commands."),
			contextRef(sourceRefs["rootPackageNames"], "json-pointer", "supporting", "/rootPackageNames", "Caller-provided root package universe covered by the shard partition.", "Root package refs do not prove dependency freshness or gate pass evidence."),
			contextRef(sourceRefs["shards"], "json-pointer", "supporting", "/shards", "Shard ownership and dependency-closure diagnostics.", "Shard diagnostics do not prove native execution, cache validity, or runner capacity."),
		},
		RouteQuestions:        workspaceQuestions([]any{sourceRefs["rootPackageNames"], sourceRefs["matrixRows"], sourceRefs["failures"]}),
		ClarificationQuestion: []map[string]any{},
		ActionPlan: []map[string]any{
			action("proofkit.workspace.shards.action-check-failures", "route", "Inspect shard partition failures before using any matrix rows.", "A failed partition must not be treated as a safe selective CI plan.", []any{sourceRefs["failures"]}, []any{"Failure inspection does not execute native witnesses or approve merge."}),
			action("proofkit.workspace.shards.action-apply-matrix", "verify", applyInstruction, applyRationale, applyEvidence, []any{"Proofkit does not own runner capacity, command execution, receipt creation, or merge approval."}),
			action("proofkit.workspace.shards.action-record-receipts", "verify", "Record caller-owned receipts for every shard command that CI executes.", "Shard planning is not proof evidence without admitted run receipts.", []any{sourceRefs["matrixRows"]}, []any{"The envelope does not create, authenticate, or freshen receipts."}),
		},
		Commands:             []map[string]any{},
		BlockedPreconditions: blockers,
		Omitted:              omitted,
		ReceiptRefs:          []map[string]any{},
		NonClaims: []string{
			"Workspace shard partition envelopes do not execute package gates.",
			"Workspace shard partition envelopes do not schedule CI runners.",
			"Workspace shard partition envelopes do not prove dependency graph freshness, receipt freshness, merge approval, release approval, or rollout approval.",
		},
	})
}

func workspaceQuestions(evidence []any) []map[string]any {
	return []map[string]any{
		routeQuestion("proofkit.workspace.question.what-changed", "what changed", []any{evidence[0]}, "The route question points to source context only and does not prove freshness."),
		routeQuestion("proofkit.workspace.question.what-proves-it", "what proves it", []any{evidence[1]}, "The route question does not infer or execute native witness commands."),
		routeQuestion("proofkit.workspace.question.who-owns-it", "who owns it", []any{evidence[2]}, "Ownership remains with the consuming repository."),
	}
}

func contextRef(refID string, kind string, role string, ref string, purpose string, nonClaim string) map[string]any {
	return map[string]any{"kind": kind, "nonClaim": nonClaim, "owner": "consumer_repository", "purpose": purpose, "ref": ref, "refId": refID, "role": role}
}

func routeQuestion(id string, question string, evidence []any, nonClaim string) map[string]any {
	return map[string]any{"evidenceRefs": evidence, "nonClaim": nonClaim, "question": question, "questionId": id}
}

func action(id string, phase string, instruction string, rationale string, evidence []any, nonClaims []any) map[string]any {
	return map[string]any{"commandIds": []any{}, "evidenceRefs": evidence, "instruction": instruction, "nonClaims": nonClaims, "owner": "consumer_repository", "phase": phase, "rationale": rationale, "stepId": id}
}

func workspaceOmissions(seeds []omissionSeed) []map[string]any {
	result := []map[string]any{}
	for _, seed := range seeds {
		if seed.Count > 0 {
			result = append(result, map[string]any{
				"escalation":   "Inspect the source workspace planning JSON when exact values are needed.",
				"evidenceRefs": []any{seed.EvidenceRef},
				"nonClaim":     "Omitted values remain in the source report; this envelope is a bounded routing artifact only.",
				"omissionId":   seed.ID,
				"omittedCount": seed.Count,
				"reason":       seed.Reason,
			})
		}
	}
	return result
}

func omittedCount(items []map[string]any) int {
	total := 0
	for _, item := range items {
		total += item["omittedCount"].(int)
	}
	return total
}
