package scenarioidentity

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const sourcePatternBody = `(?:` + admit.RuleIDPatternBody + `|` + admit.RuleIDPatternBody + `::` + admit.RuleIDPatternBody + `)`

var sourcePattern = regexp.MustCompile(`\A` + sourcePatternBody + `\z`)

func SourcePatternBody() string { return sourcePatternBody }

func AdmitSourceID(value string, context string) (string, error) {
	if !sourcePattern.MatchString(value) {
		return "", fmt.Errorf("%s must use a rule id or surface_id::stable_anchor scenario identity", context)
	}
	if strings.Contains(value, "::") {
		canonical, _, err := AdmitScoped(value, context)
		return canonical, err
	}
	return admit.RuleID(value, context)
}

// AdmitScoped preserves the exact surface_id::stable_anchor identity shared
// by source-declared scenario bodies and compact proof bindings.
func AdmitScoped(value string, context string) (string, string, error) {
	parts := strings.Split(value, "::")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("%s must use surface_id::stable_anchor scenario identity", context)
	}
	surfaceID, err := admit.RuleID(parts[0], context+" surface_id")
	if err != nil {
		return "", "", err
	}
	anchor, err := admit.RuleID(parts[1], context+" anchor")
	if err != nil {
		return "", "", err
	}
	return surfaceID + "::" + anchor, surfaceID, nil
}
