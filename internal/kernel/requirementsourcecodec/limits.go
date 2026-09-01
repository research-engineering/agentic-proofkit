package requirementsourcecodec

import (
	"errors"
	"math"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

const (
	defaultMaxNesting           = 64
	minimumJSONNesting          = 7
	canonicalByteBaseOverhead   = 4096
	lexicalTokenBaseOverhead    = 1024
	lexicalTokenItemCoefficient = 32
)

type limitCoefficient struct {
	ID          string
	Count       int
	Coefficient uint64
}

func DefaultLimits() Limits {
	modelLimits := requirementsourcemodel.DefaultLimits()
	maxOutput, err := MaxCanonicalBytes(modelLimits)
	if err != nil {
		panic("requirementsourcecodec: invalid default model limits")
	}
	maxTokens, err := MaxLexicalTokens(modelLimits)
	if err != nil {
		panic("requirementsourcecodec: invalid default token bound")
	}
	return Limits{
		MaxRawBytes:    maxOutput,
		MaxTokens:      maxTokens,
		MaxNesting:     defaultMaxNesting,
		MaxOutputBytes: maxOutput,
	}
}

func MaxCanonicalBytes(limits requirementsourcemodel.Limits) (int64, error) {
	values := []int{
		limits.MaxDefinitions, limits.MaxDerivations, limits.MaxExamples,
		limits.MaxGroups, limits.MaxMembers, limits.MaxProfiles,
		limits.MaxScenarios, limits.MaxTerms, limits.MaxCollectionItems,
		limits.MaxTotalTextBytes,
	}
	for _, value := range values {
		if value <= 0 {
			return 0, errors.New("model limits must be positive")
		}
	}
	total := uint64(canonicalByteBaseOverhead)
	for _, term := range canonicalByteCoefficients(limits) {
		product, ok := checkedMultiply(uint64(term.Count), term.Coefficient)
		if !ok {
			return 0, errors.New("canonical byte bound overflows")
		}
		var okAdd bool
		total, okAdd = checkedAdd(total, product)
		if !okAdd || total > math.MaxInt64 {
			return 0, errors.New("canonical byte bound overflows")
		}
	}
	return int64(total), nil
}

func MaxLexicalTokens(limits requirementsourcemodel.Limits) (int, error) {
	total := uint64(lexicalTokenBaseOverhead)
	for _, term := range lexicalTokenCoefficients(limits) {
		if term.Count <= 0 {
			return 0, errors.New("model limits must be positive")
		}
		product, ok := checkedMultiply(uint64(term.Count), term.Coefficient)
		if !ok {
			return 0, errors.New("token bound overflows")
		}
		total, ok = checkedAdd(total, product)
		if !ok || total > uint64(math.MaxInt) {
			return 0, errors.New("token bound overflows")
		}
	}
	return int(total), nil
}

func canonicalByteCoefficients(limits requirementsourcemodel.Limits) []limitCoefficient {
	return []limitCoefficient{
		{ID: "total_text_bytes", Count: limits.MaxTotalTextBytes, Coefficient: 3},
		{ID: "collection_items", Count: limits.MaxCollectionItems, Coefficient: 32},
		{ID: "definitions", Count: limits.MaxDefinitions, Coefficient: 96},
		{ID: "terms", Count: limits.MaxTerms, Coefficient: 160},
		{ID: "derivations", Count: limits.MaxDerivations, Coefficient: 384},
		{ID: "profiles", Count: limits.MaxProfiles, Coefficient: 448},
		{ID: "groups", Count: limits.MaxGroups, Coefficient: 320},
		{ID: "members", Count: limits.MaxMembers, Coefficient: 768},
		{ID: "scenarios", Count: limits.MaxScenarios, Coefficient: 896},
		{ID: "examples", Count: limits.MaxExamples, Coefficient: 256},
	}
}

func lexicalTokenCoefficients(limits requirementsourcemodel.Limits) []limitCoefficient {
	return []limitCoefficient{
		{ID: "collection_items", Count: limits.MaxCollectionItems, Coefficient: lexicalTokenItemCoefficient},
		{ID: "definitions", Count: limits.MaxDefinitions, Coefficient: lexicalTokenItemCoefficient},
		{ID: "derivations", Count: limits.MaxDerivations, Coefficient: lexicalTokenItemCoefficient},
		{ID: "examples", Count: limits.MaxExamples, Coefficient: lexicalTokenItemCoefficient},
		{ID: "groups", Count: limits.MaxGroups, Coefficient: lexicalTokenItemCoefficient},
		{ID: "members", Count: limits.MaxMembers, Coefficient: lexicalTokenItemCoefficient},
		{ID: "profiles", Count: limits.MaxProfiles, Coefficient: lexicalTokenItemCoefficient},
		{ID: "scenarios", Count: limits.MaxScenarios, Coefficient: lexicalTokenItemCoefficient},
		{ID: "terms", Count: limits.MaxTerms, Coefficient: lexicalTokenItemCoefficient},
	}
}

func validateLimits(codec Limits, model requirementsourcemodel.Limits) error {
	if err := requirementsourcemodel.ValidateLimits(model); err != nil {
		return errors.New("invalid model limits")
	}
	maxOutput, err := MaxCanonicalBytes(model)
	if err != nil {
		return err
	}
	maxTokens, err := MaxLexicalTokens(model)
	if err != nil {
		return err
	}
	if codec.MaxRawBytes <= 0 || codec.MaxOutputBytes <= 0 || codec.MaxOutputBytes < maxOutput || codec.MaxRawBytes < codec.MaxOutputBytes {
		return errors.New("codec byte limits do not cover the paired model")
	}
	if codec.MaxTokens < maxTokens || codec.MaxNesting < minimumJSONNesting || codec.MaxNesting > defaultMaxNesting {
		return errors.New("codec structural limits do not cover the paired model")
	}
	return nil
}

func checkedMultiply(left uint64, right uint64) (uint64, bool) {
	if right != 0 && left > math.MaxUint64/right {
		return 0, false
	}
	return left * right, true
}

func checkedAdd(left uint64, right uint64) (uint64, bool) {
	if left > math.MaxUint64-right {
		return 0, false
	}
	return left + right, true
}
