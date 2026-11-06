package readinesscloseout

import (
	"fmt"
	"slices"
	"strings"

	"github.com/yuin/goldmark/v2/ast"
	"github.com/yuin/goldmark/v2/extension"
	tableast "github.com/yuin/goldmark/v2/extension/ast"
	"github.com/yuin/goldmark/v2/parser"
)

const (
	maxPolicyMarkdownBytes  = 256 << 10
	maxPolicyMarkdownLine   = 16 << 10
	maxPotentialPolicyCells = 128 << 10
)

func parseRows(markdownText string) (parsedRows, error) {
	if len(markdownText) > maxPolicyMarkdownBytes {
		return parsedRows{}, fmt.Errorf("readiness closeout markdownText exceeds the %d-byte table parsing limit", maxPolicyMarkdownBytes)
	}
	source := []byte(markdownText)
	lineBreaks, err := policyMarkdownLineBreaks(source)
	if err != nil {
		return parsedRows{}, err
	}
	document := parser.New(parser.WithExtensions(extension.NewTableParser())).Parse(source)
	rowsByID := map[string]backlogRow{}
	duplicates := []string{}
	section := ""
	for node := document.FirstChild(); node != nil; node = node.NextSibling() {
		switch block := node.(type) {
		case *ast.Heading:
			if block.Level < 3 {
				section = ""
			} else if block.Level == 3 {
				section = literalBlockText(block, source)
			}
		case *tableast.Table:
			body := readinessTableBody(block, source)
			if body == nil {
				continue
			}
			for row := body.FirstChild(); row != nil; row = row.NextSibling() {
				cells := readinessCells(row, source)
				if !statusPattern.MatchString(cells[0]) || !rowIDPattern.MatchString(cells[1]) {
					continue
				}
				line, _ := slices.BinarySearch(lineBreaks, row.Pos())
				line++
				context := fmt.Sprintf("readiness closeout markdown line %d", line)
				id, err := rowID(cells[1], context+".rowId")
				if err != nil {
					return parsedRows{}, err
				}
				status, err := statusText(cells[0], context+".status")
				if err != nil {
					return parsedRows{}, err
				}
				if existing, ok := rowsByID[id]; ok {
					duplicates = append(duplicates, fmt.Sprintf("%s appears more than once in backlog tables at lines %d and %d", id, existing.LineNumber, line))
					continue
				}
				rowsByID[id] = backlogRow{CompletionCondition: cells[3], LineNumber: line, OwnerScope: cells[2], RowID: id, Section: section, Status: status}
			}
		}
	}
	rows := make([]backlogRow, 0, len(rowsByID))
	for _, row := range rowsByID {
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(left, right backlogRow) int { return strings.Compare(left.RowID, right.RowID) })
	slices.Sort(duplicates)
	return parsedRows{DuplicateFailures: duplicates, Rows: rows}, nil
}

// The parser may pad a body row to its delimiter width, including in a
// nested block that we later ignore. Count all physical pipes before parsing.
func policyMarkdownLineBreaks(source []byte) ([]int, error) {
	lineBreaks := []int{}
	width, widest, lineStart := 1, 1, 0
	for offset, char := range source {
		switch char {
		case '|':
			width++
		case '\r', '\n':
			if char == '\r' && offset+1 < len(source) && source[offset+1] == '\n' {
				continue
			}
			lineEnd := offset
			if char == '\n' && offset > lineStart && source[offset-1] == '\r' {
				lineEnd--
			}
			if lineEnd-lineStart > maxPolicyMarkdownLine {
				return nil, policyTableLineError()
			}
			lineStart = offset + 1
			lineBreaks = append(lineBreaks, offset)
			widest = max(widest, width)
			width = 1
			if widest > maxPotentialPolicyCells/(len(lineBreaks)+1) {
				return nil, policyTableBudgetError()
			}
		}
	}
	if len(source)-lineStart > maxPolicyMarkdownLine {
		return nil, policyTableLineError()
	}
	if max(widest, width) > maxPotentialPolicyCells/(len(lineBreaks)+1) {
		return nil, policyTableBudgetError()
	}
	return lineBreaks, nil
}

func policyTableLineError() error {
	return fmt.Errorf("readiness closeout markdownText contains a line above the %d-byte parsing limit", maxPolicyMarkdownLine)
}

func policyTableBudgetError() error {
	return fmt.Errorf("readiness closeout markdownText exceeds the %d-cell table parsing limit", maxPotentialPolicyCells)
}

func readinessTableBody(table *tableast.Table, source []byte) *tableast.TableBody {
	header, ok := table.FirstChild().(*tableast.TableHeader)
	if !ok {
		return nil
	}
	cells := readinessCells(header, source)
	if cells[0] != "Status" || cells[1] != "ID" {
		return nil
	}
	body, _ := header.NextSibling().(*tableast.TableBody)
	return body
}

func readinessCells(row ast.Node, source []byte) [4]string {
	var cells [4]string
	for column, cell := 0, row.FirstChild(); column < len(cells) && cell != nil; column, cell = column+1, cell.NextSibling() {
		if block, ok := cell.(*tableast.TableCell); ok {
			cells[column] = literalBlockText(block, source)
		}
	}
	return cells
}

func literalBlockText(block ast.BlockNode, source []byte) string {
	segments := block.Source()
	if len(segments) == 0 {
		return ""
	}
	return strings.TrimSpace(string(segments[0].Bytes(source)))
}
