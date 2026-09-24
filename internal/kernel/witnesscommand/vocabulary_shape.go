package witnesscommand

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

var vocabularyShape = makeVocabularyShape()

func makeVocabularyShape() jsonshape.Shape {
	text := jsonshape.String()
	texts := jsonshape.Array(text, 0)
	policy := jsonshape.Object(
		jsonshape.Required("cachePolicies", texts),
		jsonshape.Required("credentialClasses", texts),
		jsonshape.Required("environmentClass", text),
		jsonshape.Required("networkPolicies", texts),
	)
	return jsonshape.Object(
		jsonshape.Required("artifactKinds", texts),
		jsonshape.Required("credentialClasses", texts),
		jsonshape.Required("environmentClasses", texts),
		jsonshape.Optional("environmentClassPolicies", jsonshape.Nullable(jsonshape.Array(policy, 0))),
		jsonshape.Optional("maxTimeoutMs", jsonshape.Nullable(jsonshape.Number())),
		jsonshape.Optional("nonCacheableCredentialClasses", jsonshape.Nullable(texts)),
		jsonshape.Optional("parallelGroups", jsonshape.Nullable(texts)),
	)
}

// AdmitVocabularySnapshot returns native policy and its detached wire value.
// The wire value preserves optional presence, nulls and numeric spelling; it
// does not insert the native defaults. Callers must not mutate raw during a call.
func AdmitVocabularySnapshot(raw any) (Vocabulary, map[string]any, error) {
	snapshot, err := vocabularyShape.Admit(raw, "witness vocabulary")
	if err != nil {
		return Vocabulary{}, nil, err
	}
	record := snapshot.(map[string]any)
	vocabulary, err := admitVocabulary(record)
	if err != nil {
		return Vocabulary{}, nil, err
	}
	return vocabulary, record, nil
}
