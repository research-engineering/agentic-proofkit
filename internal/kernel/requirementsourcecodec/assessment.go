package requirementsourcecodec

import "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"

type AssessmentResult struct {
	Assessment requirementsourcemodel.Assessment
	SourceMap  SourceMap
}

// Assess uses Parse's borrowed-byte contract, but retains every policy
// violation. Only a structurally admitted source receives an assessment.
func Assess(source []byte) (AssessmentResult, error) {
	return AssessWithLimits(source, DefaultLimits(), requirementsourcemodel.DefaultLimits())
}

func AssessWithLimits(source []byte, codecLimits Limits, modelLimits requirementsourcemodel.Limits) (AssessmentResult, error) {
	decoded, err := decodeSource(source, codecLimits, modelLimits)
	if err != nil {
		return AssessmentResult{}, err
	}
	assessment, err := requirementsourcemodel.AssessWithLimits(decoded.draft, modelLimits)
	if err != nil {
		return AssessmentResult{}, modelDiagnostic(source, decoded.locations, decoded.wire, err)
	}
	return AssessmentResult{Assessment: assessment, SourceMap: sourceMap(source, decoded.locations)}, nil
}
