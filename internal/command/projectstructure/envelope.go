package projectstructure

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

const (
	envelopeContextLimit = 12
	envelopeCommandLimit = 8
	envelopeBlockedLimit = 8
)

func BuildEnvelopeFromResult(scaffold Result) (map[string]any, int, error) {
	manifest := scaffold.Manifest
	allContextRefs := contextRefs(anyArray(manifest["files"]))
	contextRefs := takeMaps(allContextRefs, envelopeContextLimit)
	allCommands := commandRefs(anyArray(manifest["nextCommands"]))
	commands := takeMaps(allCommands, envelopeCommandLimit)
	allBlocked := blockedPreconditions(anyArray(manifest["files"]))
	blocked := takeMaps(allBlocked, envelopeBlockedLimit)
	contextOmitted := len(allContextRefs) - len(contextRefs)
	commandOmitted := len(allCommands) - len(commands)
	blockedOmitted := len(allBlocked) - len(blocked)
	evidenceRefs := contextRefIDs(contextRefs)
	if len(evidenceRefs) == 0 {
		evidenceRefs = []any{manifest["manifestId"]}
	}
	omitted := omissions(contextOmitted, commandOmitted, blockedOmitted, evidenceRefs)
	commandIDs := commandIDs(commands)
	contextIDs := contextRefIDs(contextRefs)
	sourceHash, err := digest.StableJSONSHA256Ref(scaffold.Record.JSONValue())
	if err != nil {
		return nil, 1, err
	}
	actionPlan := []map[string]any{
		{
			"commandIds":   []any{},
			"evidenceRefs": contextIDs,
			"instruction":  "Load the bounded project-structure file refs and inspect the full scaffold result when payload content or omitted refs are needed.",
			"nonClaims": []any{
				"Route guidance does not approve repository edits.",
				"Route guidance does not prove file existence.",
			},
			"owner":     "consumer_repository",
			"phase":     "route",
			"rationale": "The envelope routes first adoption work without embedding starter payload bodies.",
			"stepId":    "proofkit.project-structure.action.route",
		},
		{
			"commandIds":   []any{},
			"evidenceRefs": contextIDs,
			"instruction":  "Materialize only caller-reviewed payload files and author caller-content-required files under consumer repository policy.",
			"nonClaims": []any{
				"Candidate-change guidance does not decide overwrite safety or final content.",
				"Candidate-change guidance does not write files.",
			},
			"owner":     "consumer_repository",
			"phase":     "candidate-change",
			"rationale": "Project-structure scaffolds describe candidate files, while file writes and overwrite choices remain caller-owned.",
			"stepId":    "proofkit.project-structure.action.candidate-change",
		},
		{
			"commandIds":   []any{},
			"evidenceRefs": contextIDs,
			"instruction":  "Review the generated starter profile, proof binding, workflow input, and caller-owned module spec before admitting them as repository truth.",
			"nonClaims": []any{
				"Bind guidance does not admit profile correctness.",
				"Bind guidance does not prove requirement coverage.",
			},
			"owner":     "consumer_repository",
			"phase":     "bind",
			"rationale": "Starter payloads are useful only after caller review binds them to real repository meaning.",
			"stepId":    "proofkit.project-structure.action.bind",
		},
		verifyAction(commandIDs, contextIDs),
	}
	envelope := agentenvelope.Build(agentenvelope.Input{
		EnvelopeID: fmt.Sprintf("%s.agent-envelope", scaffold.Record.ReportID),
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Project-structure source report identity does not prove file creation, payload review, witness execution, freshness, or caller approval.",
			"reportId":    scaffold.Record.ReportID,
			"reportKind":  scaffold.Record.ReportKind,
			"stableHash":  sourceHash,
			"state":       scaffold.Record.State,
		},
		Bounds: map[string]any{
			"escalation":      "Inspect the full project-structure scaffold result when omitted refs, starter payload content, or write decisions are needed.",
			"fanout":          "bounded",
			"maxActionItems":  len(actionPlan),
			"maxCommandRefs":  len(commands),
			"maxContextRefs":  len(contextRefs),
			"maxOmittedItems": len(omitted),
			"maxReceiptRefs":  0,
			"maxTokenBudget":  nil,
			"nonClaim":        "Project-structure envelope bounds cover item counts only and do not prove tokenizer-specific budget coverage.",
			"omittedCount":    omittedCount(omitted),
		},
		ContextRefs: contextRefs,
		RouteQuestions: []map[string]any{
			{
				"evidenceRefs": contextIDs,
				"nonClaim":     "File refs describe candidate materialization targets and do not prove repository changes.",
				"question":     "what changed",
				"questionId":   "proofkit.project-structure.question.what-changed",
			},
			{
				"evidenceRefs": proofEvidenceRefs(commandIDs, manifest),
				"nonClaim":     "Command refs are planned commands, not command pass evidence.",
				"question":     "what proves it",
				"questionId":   "proofkit.project-structure.question.what-proves-it",
			},
			{
				"evidenceRefs": []any{"consumer_repository"},
				"nonClaim":     "The consuming repository owns file writes, final content, native execution, receipts, merge, release, and rollout.",
				"question":     "who owns it",
				"questionId":   "proofkit.project-structure.question.who-owns-it",
			},
		},
		ClarificationQuestion: clarificationQuestions(blocked),
		ActionPlan:            actionPlan,
		Commands:              commands,
		BlockedPreconditions:  blocked,
		Omitted:               omitted,
		ReceiptRefs:           []map[string]any{},
		NonClaims: []string{
			"Project-structure agent envelopes do not approve merge, release, rollout, or consumer policy.",
			"Project-structure agent envelopes do not discover repository state.",
			"Project-structure agent envelopes do not execute native witnesses.",
			"Project-structure agent envelopes do not include starter payload bodies.",
			"Project-structure agent envelopes do not write files.",
		},
	})
	return envelope, scaffold.ExitCode, nil
}

func contextRefs(files []any) []map[string]any {
	refs := make([]map[string]any, 0, len(files))
	for index, rawFile := range files {
		file := mapValue(rawFile)
		refs = append(refs, map[string]any{
			"kind":     "path",
			"nonClaim": "Project-structure file refs route materialization review only and do not prove file existence, freshness, or correctness.",
			"owner":    "consumer_repository",
			"purpose":  projectStructureFilePurpose(file),
			"ref":      file["path"],
			"refId":    fmt.Sprintf("proofkit.project-structure.context.file.%03d", index+1),
			"role":     projectStructureFileRole(file),
		})
	}
	return refs
}

func commandRefs(commands []any) []map[string]any {
	refs := make([]map[string]any, 0, len(commands))
	for index, command := range commands {
		refs = append(refs, map[string]any{
			"command":   command,
			"commandId": fmt.Sprintf("proofkit.project-structure.command.%03d", index+1),
			"nonClaim":  "Project-structure command refs preserve command display text only; they do not invent argv, execute commands, or prove pass evidence.",
			"owner":     "consumer_repository",
			"purpose":   "Caller-owned follow-up command emitted by project-structure scaffold planning.",
		})
	}
	return refs
}

func blockedPreconditions(files []any) []map[string]any {
	blocked := []map[string]any{}
	for _, rawFile := range files {
		file := mapValue(rawFile)
		if file["materializationStatus"] == "caller_content_required" {
			blocked = append(blocked, map[string]any{
				"description":    fmt.Sprintf("%s requires caller-authored or caller-reviewed content before materialization.", file["path"]),
				"evidenceRefs":   []any{file["path"]},
				"nonClaim":       "Caller-content preconditions identify required repository-owned content and do not authorize generated content.",
				"owner":          "consumer_repository",
				"preconditionId": fmt.Sprintf("proofkit.project-structure.blocked.%d.caller-content", len(blocked)+1),
			})
		}
		if file["source"] == "repo_profile_scaffold" {
			blocked = append(blocked, map[string]any{
				"description":    fmt.Sprintf("%s is a starter repository profile draft and requires caller review before it becomes repository policy.", file["path"]),
				"evidenceRefs":   []any{file["path"]},
				"nonClaim":       "Profile-review preconditions identify caller-owned policy review and do not admit final profile correctness.",
				"owner":          "consumer_repository",
				"preconditionId": fmt.Sprintf("proofkit.project-structure.blocked.%d.profile-review", len(blocked)+1),
			})
		}
	}
	return blocked
}

func omissions(contextOmitted int, commandOmitted int, blockedOmitted int, evidenceRefs []any) []map[string]any {
	values := []map[string]any{}
	if contextOmitted > 0 {
		values = append(values, map[string]any{
			"escalation":   "Inspect the full project-structure scaffold result before materializing omitted files.",
			"evidenceRefs": evidenceRefs,
			"nonClaim":     "Omitted context refs are not proof failures; they require full-manifest review.",
			"omissionId":   "proofkit.project-structure.omitted.context-refs",
			"omittedCount": contextOmitted,
			"reason":       "project-structure manifest has more file refs than the bounded envelope includes",
		})
	}
	if commandOmitted > 0 {
		values = append(values, map[string]any{
			"escalation":   "Inspect the full project-structure scaffold result before deciding the command plan is complete.",
			"evidenceRefs": evidenceRefs,
			"nonClaim":     "Omitted command refs are not command pass evidence and do not approve skipping commands.",
			"omissionId":   "proofkit.project-structure.omitted.command-refs",
			"omittedCount": commandOmitted,
			"reason":       "project-structure manifest has more next commands than the bounded envelope includes",
		})
	}
	if blockedOmitted > 0 {
		values = append(values, map[string]any{
			"escalation":   "Inspect the full project-structure scaffold result before authoring or materializing caller-owned content.",
			"evidenceRefs": evidenceRefs,
			"nonClaim":     "Omitted blocked preconditions remain caller-owned obligations.",
			"omissionId":   "proofkit.project-structure.omitted.blocked-preconditions",
			"omittedCount": blockedOmitted,
			"reason":       "project-structure manifest has more caller-content-required files than the bounded envelope lists",
		})
	}
	return values
}

func verifyAction(commandIDs []any, contextIDs []any) map[string]any {
	instruction := "No command refs are included; inspect the full scaffold manifest and caller policy before treating adoption work as routed."
	evidenceRefs := contextIDs
	if len(commandIDs) > 0 {
		instruction = "Run the listed caller-owned proofkit commands after materialization review and collect native witness receipts separately."
		evidenceRefs = commandIDs
	}
	return map[string]any{
		"commandIds":   commandIDs,
		"evidenceRefs": evidenceRefs,
		"instruction":  instruction,
		"nonClaims": []any{
			"Verify guidance does not execute commands.",
			"Verify guidance does not prove receipt freshness, merge approval, release approval, or rollout approval.",
		},
		"owner":     "consumer_repository",
		"phase":     "verify",
		"rationale": "Proofkit can list follow-up commands, but command execution and receipts remain outside the scaffold envelope.",
		"stepId":    "proofkit.project-structure.action.verify",
	}
}

func clarificationQuestions(blocked []map[string]any) []map[string]any {
	questions := make([]map[string]any, 0, len(blocked))
	for _, precondition := range blocked {
		questions = append(questions, map[string]any{
			"askWhen":            precondition["description"],
			"blocking":           true,
			"evidenceRefs":       precondition["evidenceRefs"],
			"expectedAnswerKind": "owner_decision",
			"nonClaim":           "Clarification questions do not generate or approve caller-owned content.",
			"owner":              precondition["owner"],
			"question":           "What caller-authored content should be used before materializing this file?",
			"questionId":         fmt.Sprintf("proofkit.project-structure.clarification.%s", precondition["preconditionId"]),
		})
	}
	return questions
}

func proofEvidenceRefs(commandIDs []any, manifest map[string]any) []any {
	if len(commandIDs) > 0 {
		return commandIDs
	}
	return []any{manifest["manifestId"]}
}
