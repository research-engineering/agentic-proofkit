package requirementcoverageview

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/markdownfmt"
)

func TestRequirementDenialsKeepTheirScopeAcrossRenderings(t *testing.T) {
	input := validCoverageInput(t).(map[string]any)
	source := input["requirementSource"].(map[string]any)
	source["sourceNonClaims"] = []any{"Source boundary only."}
	group := coverageSourceGroup(source)
	first := group["members"].([]any)[0].(map[string]any)
	second := cloneCoverageJSONValue(first).(map[string]any)
	second["requirementId"] = "REQ-PROOFKIT-COVERAGE-002"
	second["fields"].(map[string]any)["claimLevel"] = "advisory"
	denials := []string{"First boundary <a>&[only].", "Second boundary is independent."}
	first["fields"].(map[string]any)["nonClaims"] = []any{denials[0]}
	second["fields"].(map[string]any)["nonClaims"] = []any{denials[1]}
	group["members"] = []any{first, second}
	value, exit, err := BuildJSON(input, Options{})
	if err != nil || exit != 0 {
		t.Fatalf("JSON: %v exit=%d", err, exit)
	}
	rows := value.(map[string]any)["requirementCoverage"].([]any)
	if len(rows) != 2 {
		t.Fatal("expected both requirement rows")
	}
	md, exit, err := BuildMarkdown(input)
	if err != nil || exit != 0 {
		t.Fatalf("Markdown: %v exit=%d", err, exit)
	}
	document, exit, err := BuildHTML(input)
	if err != nil || exit != 0 {
		t.Fatalf("HTML: %v exit=%d", err, exit)
	}
	articles := regexp.MustCompile(`(?s)<article\b[^>]*>.*?</article>`).FindAllString(document, -1)
	if len(articles) < 2 {
		t.Fatal("requirement cards are missing")
	}
	for i, raw := range rows {
		row := raw.(map[string]any)
		if !reflect.DeepEqual(row["nonClaims"], []any{denials[i]}) {
			t.Fatal("JSON moved an individual denial")
		}
		heading := "### " + markdownfmt.Text(row["requirementId"].(string)) + "\n"
		start := strings.Index(md, heading)
		if start < 0 {
			t.Fatal("requirement heading missing")
		}
		section := md[start+len(heading):]
		if end := strings.Index(section, "\n##"); end >= 0 {
			section = section[:end]
		}
		if !strings.Contains(section, markdownfmt.Text(denials[i])) || strings.Contains(section, markdownfmt.Text(denials[1-i])) || strings.Contains(section, "Source boundary") {
			t.Fatal("Markdown lost or moved a scoped denial")
		}
		article := ""
		for _, candidate := range articles {
			if strings.Contains(candidate, `<span class="proofkit-id">`+row["requirementId"].(string)+`</span>`) {
				article = candidate
				break
			}
		}
		wantHTML := []string{"First boundary &lt;a&gt;&amp;[only].", denials[1]}[i]
		if !strings.Contains(article, "<li>"+wantHTML+"</li>") || strings.Contains(article, denials[1-i]) || strings.Contains(article, "Source boundary") {
			t.Fatal("HTML lost or moved a scoped denial")
		}
	}
	if !strings.Contains(md, `First boundary &lt;a&gt;&amp;\[only\]\.`) || strings.Contains(md, "<a>") || !strings.Contains(md, "Source boundary only\\.") {
		t.Fatal("Markdown escaping or source boundary changed")
	}
}
