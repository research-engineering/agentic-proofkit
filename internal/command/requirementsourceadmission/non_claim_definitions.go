package requirementsourceadmission

import (
	"fmt"
	"reflect"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

// NonClaimDefinitions is a detached dictionary for one enclosing sourceId.
// Its zero value is empty; the dictionary grants no source or proof authority.
type NonClaimDefinitions struct {
	values     []requirementsourcemodel.NonClaimDefinition
	statements map[string]string
}

func (source Source) NonClaimDefinitions() NonClaimDefinitions {
	return definitionDictionary(source.model.NonClaimDefinitions())
}

func definitionDictionary(values []requirementsourcemodel.NonClaimDefinition) NonClaimDefinitions {
	result := NonClaimDefinitions{values: append([]requirementsourcemodel.NonClaimDefinition{}, values...), statements: make(map[string]string, len(values))}
	for _, value := range values {
		result.statements[value.NonClaimID] = value.Statement
	}
	return result
}

func AdmitNonClaimDefinitions(raw any) (NonClaimDefinitions, error) {
	rows, ok := raw.([]any)
	if !ok || len(rows) > requirementsourcemodel.DefaultLimits().MaxDefinitions {
		return NonClaimDefinitions{}, fmt.Errorf("non-claim definitions must be a bounded array")
	}
	values := make([]requirementsourcemodel.NonClaimDefinition, len(rows))
	for i, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return NonClaimDefinitions{}, fmt.Errorf("non-claim definition must be an object")
		}
		if err := admit.KnownKeys(row, []string{"nonClaimId", "statement"}, "non-claim definition"); err != nil {
			return NonClaimDefinitions{}, err
		}
		id, idOK := row["nonClaimId"].(string)
		statement, statementOK := row["statement"].(string)
		if !idOK || !statementOK {
			return NonClaimDefinitions{}, fmt.Errorf("non-claim definition requires text identity and statement")
		}
		values[i] = requirementsourcemodel.NonClaimDefinition{NonClaimID: id, Statement: statement}
	}
	canonical, err := requirementsourcemodel.NormalizeNonClaimDefinitions(values)
	if err != nil {
		return NonClaimDefinitions{}, err
	}
	if !reflect.DeepEqual(values, canonical) {
		return NonClaimDefinitions{}, fmt.Errorf("non-claim definitions must be canonical and sorted by identity")
	}
	return definitionDictionary(canonical), nil
}

// Select takes a query union, so repeated refs are deduplicated. Reference
// arrays in individual semantic records are validated separately by CheckScope.
func (definitions NonClaimDefinitions) Select(refs []string) (NonClaimDefinitions, error) {
	wanted, err := definitions.referenceSet(refs)
	if err != nil {
		return NonClaimDefinitions{}, err
	}
	selected := make([]requirementsourcemodel.NonClaimDefinition, 0, len(wanted))
	for _, value := range definitions.values {
		if _, ok := wanted[value.NonClaimID]; ok {
			selected = append(selected, value)
		}
	}
	return definitionDictionary(selected), nil
}

func (definitions NonClaimDefinitions) referenceSet(refs []string) (map[string]struct{}, error) {
	wanted := make(map[string]struct{}, min(len(refs), len(definitions.values)))
	for _, ref := range refs {
		if _, exists := definitions.statements[ref]; !exists {
			return nil, fmt.Errorf("local non-claim reference has no source-scoped definition")
		}
		wanted[ref] = struct{}{}
	}
	return wanted, nil
}

func (definitions NonClaimDefinitions) Value() []any {
	values := make([]any, len(definitions.values))
	for i, value := range definitions.values {
		values[i] = map[string]any{"nonClaimId": value.NonClaimID, "statement": value.Statement}
	}
	return values
}

func (definitions NonClaimDefinitions) CheckScope(direct, refs []string) error {
	return requirementsourcemodel.ValidateResolvedNonClaimScope(direct, refs, definitions.statements)
}

func (definitions NonClaimDefinitions) RequireExactRefs(refs []string) error {
	selected, err := definitions.referenceSet(refs)
	if err != nil {
		return err
	}
	if len(selected) != len(definitions.values) {
		return fmt.Errorf("non-claim support contains unreferenced definitions")
	}
	return nil
}
