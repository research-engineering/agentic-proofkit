package agentenvelope

import "github.com/research-engineering/agentic-proofkit/internal/kernel/admit"

type preparedLocalReferences struct {
	actionPlan             []map[string]any
	blockedPreconditions   []map[string]any
	clarificationQuestions []map[string]any
	commands               []map[string]any
	contextRefs            []map[string]any
	omitted                []map[string]any
	receiptRefs            []map[string]any
	routeQuestions         []map[string]any
	removedReferenceCount  int
	identityDegraded       bool
}

type localIdentityMultiplicity struct {
	commands map[string]int
	contexts map[string]int
	receipts map[string]int
}

type localReferenceAdmission struct {
	identityDegraded    bool
	removedCount        int
	standaloneOmissions int
	values              []map[string]any
}

func prepareLocalReferences(input Input) preparedLocalReferences {
	prepared := preparedLocalReferences{
		actionPlan:             cloneMapList(input.ActionPlan),
		blockedPreconditions:   cloneMapList(input.BlockedPreconditions),
		clarificationQuestions: cloneMapList(input.ClarificationQuestion),
		commands:               cloneMapList(input.Commands),
		contextRefs:            cloneMapList(input.ContextRefs),
		omitted:                cloneMapList(input.Omitted),
		receiptRefs:            cloneMapList(input.ReceiptRefs),
		routeQuestions:         cloneMapList(input.RouteQuestions),
	}

	rejectedTargets := map[string]struct{}{}
	var unsafeTargets int
	prepared.commands, unsafeTargets = admitLocalTargetRecords(prepared.commands, "commandId", rejectedTargets)
	var count int
	prepared.contextRefs, count = admitLocalTargetRecords(prepared.contextRefs, "refId", rejectedTargets)
	unsafeTargets += count
	prepared.receiptRefs, count = admitLocalTargetRecords(prepared.receiptRefs, "receiptRefId", rejectedTargets)
	unsafeTargets += count

	multiplicity := localIdentityMultiplicity{
		commands: localIdentityCounts(prepared.commands, "commandId"),
		contexts: localIdentityCounts(prepared.contextRefs, "refId"),
		receipts: localIdentityCounts(prepared.receiptRefs, "receiptRefId"),
	}
	ambiguous := ambiguousLocalIdentities(multiplicity)
	prepared.commands = removeAmbiguousTargets(prepared.commands, "commandId", ambiguous)
	prepared.contextRefs = removeAmbiguousTargets(prepared.contextRefs, "refId", ambiguous)
	prepared.receiptRefs = removeAmbiguousTargets(prepared.receiptRefs, "receiptRefId", ambiguous)

	if unsafeTargets > 0 {
		prepared.omitted = append(prepared.omitted, omissionRecord("unsafeLocalIdentity", "localTargetIds", unsafeTargets))
		prepared.identityDegraded = true
	}
	if len(ambiguous) > 0 {
		prepared.omitted = append(prepared.omitted, omissionRecord("ambiguousLocalIdentity", "localTargetIds", len(ambiguous)))
		prepared.identityDegraded = true
	}

	uniqueTargets := collectLocalReferenceTargets(prepared.commands, prepared.contextRefs, prepared.receiptRefs)
	standaloneReferenceOmissions := 0
	for _, records := range []*[]map[string]any{
		&prepared.actionPlan,
		&prepared.blockedPreconditions,
		&prepared.clarificationQuestions,
		&prepared.routeQuestions,
		&prepared.omitted,
		&prepared.commands,
		&prepared.contextRefs,
		&prepared.receiptRefs,
	} {
		admission := admitRecordLocalReferences(*records, uniqueTargets, rejectedTargets, ambiguous)
		*records = admission.values
		prepared.removedReferenceCount += admission.removedCount
		standaloneReferenceOmissions += admission.standaloneOmissions
		prepared.identityDegraded = prepared.identityDegraded || admission.identityDegraded
	}
	if standaloneReferenceOmissions > 0 {
		prepared.omitted = append(prepared.omitted, omissionRecord("unsafeLocalReference", "localReferences", standaloneReferenceOmissions))
		prepared.identityDegraded = true
	}
	return prepared
}

func admitLocalTargetRecords(values []map[string]any, key string, rejected map[string]struct{}) ([]map[string]any, int) {
	result := make([]map[string]any, 0, len(values))
	omitted := 0
	for _, value := range values {
		if _, ok := losslessLocalIdentity(value[key]); !ok {
			if identity, isText := value[key].(string); isText {
				rejected[identity] = struct{}{}
			}
			omitted++
			continue
		}
		result = append(result, value)
	}
	return result, omitted
}

func losslessLocalIdentity(raw any) (string, bool) {
	value, ok := raw.(string)
	if !ok {
		return "", false
	}
	admitted, err := admit.RuleID(value, "agent envelope local identity")
	return admitted, err == nil && admitted == value
}

func losslessExternalReference(raw any) (string, bool) {
	value, ok := raw.(string)
	if !ok || value == "" {
		return "", false
	}
	return value, admit.RedactStructuralText(value) == value
}

func localIdentityCounts(values []map[string]any, key string) map[string]int {
	result := map[string]int{}
	for _, value := range values {
		identity, _ := losslessLocalIdentity(value[key])
		result[identity]++
	}
	return result
}

func ambiguousLocalIdentities(multiplicity localIdentityMultiplicity) map[string]struct{} {
	result := map[string]struct{}{}
	domainCount := map[string]int{}
	for _, domain := range []map[string]int{multiplicity.commands, multiplicity.contexts, multiplicity.receipts} {
		for identity, count := range domain {
			if count != 1 {
				result[identity] = struct{}{}
			}
			domainCount[identity]++
		}
	}
	for identity, count := range domainCount {
		if count != 1 {
			result[identity] = struct{}{}
		}
	}
	return result
}

func removeAmbiguousTargets(values []map[string]any, key string, ambiguous map[string]struct{}) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		identity, _ := losslessLocalIdentity(value[key])
		if _, found := ambiguous[identity]; found {
			continue
		}
		result = append(result, value)
	}
	return result
}

func admitRecordLocalReferences(values []map[string]any, targets localReferenceTargets, rejected map[string]struct{}, ambiguous map[string]struct{}) localReferenceAdmission {
	admission := localReferenceAdmission{}
	result := make([]map[string]any, len(values))
	for index, value := range values {
		cloned := copyMap(value)
		if raw, exists := cloned["evidenceRefs"]; exists {
			kept := []any{}
			for _, item := range referenceItems(raw) {
				identity, ok := losslessExternalReference(item)
				if !ok {
					admission.removedCount++
					admission.identityDegraded = true
					if identity, isText := item.(string); !isText || !isRejectedIdentity(identity, rejected, ambiguous) {
						admission.standaloneOmissions++
					}
					continue
				}
				if _, found := rejected[identity]; found {
					admission.removedCount++
					admission.identityDegraded = true
					continue
				}
				if _, found := ambiguous[identity]; found {
					admission.removedCount++
					admission.identityDegraded = true
					continue
				}
				kept = append(kept, identity)
			}
			cloned["evidenceRefs"] = kept
		}
		if raw, exists := cloned["commandIds"]; exists {
			kept := []any{}
			for _, item := range referenceItems(raw) {
				identity, ok := losslessLocalIdentity(item)
				if !ok {
					admission.removedCount++
					admission.identityDegraded = true
					if identity, isText := item.(string); !isText || !isRejectedIdentity(identity, rejected, ambiguous) {
						admission.standaloneOmissions++
					}
					continue
				}
				if _, found := ambiguous[identity]; found {
					admission.removedCount++
					admission.identityDegraded = true
					continue
				}
				if _, found := targets.commands[identity]; !found {
					admission.removedCount++
					continue
				}
				kept = append(kept, identity)
			}
			cloned["commandIds"] = kept
		}
		result[index] = cloned
	}
	admission.values = result
	return admission
}

func isRejectedIdentity(identity string, rejected map[string]struct{}, ambiguous map[string]struct{}) bool {
	if _, found := rejected[identity]; found {
		return true
	}
	_, found := ambiguous[identity]
	return found
}

func referenceItems(raw any) []any {
	switch values := raw.(type) {
	case []any:
		return values
	case []string:
		result := make([]any, len(values))
		for index, value := range values {
			result[index] = value
		}
		return result
	default:
		return []any{raw}
	}
}

func cloneMapList(values []map[string]any) []map[string]any {
	result := make([]map[string]any, len(values))
	for index, value := range values {
		result[index] = copyMap(value)
	}
	return result
}
