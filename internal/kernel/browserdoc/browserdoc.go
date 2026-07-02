package browserdoc

import (
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"html"
	"regexp"
	"sort"
	"strings"
)

type Fragment struct {
	html string
}

type DefinitionItem struct {
	Label string
	Value Fragment
}

type Document struct {
	Title             string
	Authority         string
	SummaryItems      []SummaryItem
	HierarchySections []HierarchySection
	Filters           []Filter
	Cards             []Card
	Table             *Table
	ExportFiles       []ExportFile
	NonClaims         []string
}

type SummaryItem struct {
	Label string
	Value Fragment
}

type HierarchySection struct {
	Title string
	Items []HierarchyItem
}

type HierarchyItem struct {
	Label  string
	Detail string
	Href   string
}

type Filter struct {
	Key    string
	Label  string
	Values []string
}

type Card struct {
	ID           string
	Title        string
	GroupID      string
	GroupLabel   string
	Body         Fragment
	SearchText   string
	FilterValues []FilterValue
}

type FilterValue struct {
	Key   string
	Value string
}

type Table struct {
	Columns []Column
	Rows    []Row
}

type Column struct {
	Key   string
	Label string
}

type Row struct {
	ID           string
	Cells        []Cell
	SearchText   string
	FilterValues []FilterValue
}

type Cell struct {
	Key   string
	Value Fragment
}

type ExportFile struct {
	Label    string
	FileName string
	Content  string
}

var filterKeyPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func HTML(input Document) string {
	hasTable := input.Table != nil
	parts := []string{
		"<!doctype html>",
		"<html lang=\"en\" data-show-ids=\"true\">",
		"<head>",
		"<meta charset=\"utf-8\">",
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
		fmt.Sprintf("<title>%s</title>", Escape(input.Title)),
		fmt.Sprintf("<style>%s</style>", css()),
		"</head>",
		"<body data-proofkit-browser-view=\"true\">",
		"<main>",
		fmt.Sprintf("<header><p class=\"eyebrow\">Proofkit rendered view</p><h1>%s</h1></header>", Escape(input.Title)),
		"<section class=\"summary\" aria-label=\"View summary\">",
		"<dl>",
		fmt.Sprintf("<dt>Authority</dt><dd>%s</dd>", Escape(input.Authority)),
	}
	for _, item := range input.SummaryItems {
		parts = append(parts, fmt.Sprintf("<dt>%s</dt><dd>%s</dd>", Escape(item.Label), item.Value.html))
	}
	parts = append(parts,
		"</dl>",
		"</section>",
		hierarchy(input.HierarchySections),
		controls(input.Filters, hasTable),
		exports(input.ExportFiles),
		fmt.Sprintf("<p class=\"result-count\"><span id=\"proofkit-visible-count\">%d</span> of %d records shown</p>", len(input.Cards), len(input.Cards)),
		cards(input.Cards),
	)
	if hasTable {
		parts = append(parts, table(*input.Table))
	}
	parts = append(parts,
		"<section class=\"non-claims\" aria-label=\"View non-claims\">",
		"<h2>View Non-Claims</h2>",
		ListOrNone(input.NonClaims, false).html,
		"</section>",
		"</main>",
		fmt.Sprintf("<script>%s</script>", script()),
		"</body>",
		"</html>",
		"",
	)
	return strings.Join(parts, "\n")
}

func Text(value string) Fragment {
	return Fragment{html: Escape(value)}
}

func Code(value string) Fragment {
	return Fragment{html: "<code>" + Escape(value) + "</code>"}
}

func Concat(values ...Fragment) Fragment {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, value.html)
	}
	return Fragment{html: strings.Join(parts, "\n")}
}

func Heading(level int, value string) Fragment {
	if level < 2 || level > 3 {
		level = 3
	}
	return Fragment{html: fmt.Sprintf("<h%d>%s</h%d>", level, Escape(value), level)}
}

func Definition(label string, value Fragment) DefinitionItem {
	return DefinitionItem{Label: label, Value: value}
}

func DefinitionList(items ...DefinitionItem) Fragment {
	parts := []string{"<dl>"}
	for _, item := range items {
		parts = append(parts, "<dt>"+Escape(item.Label)+"</dt><dd>"+item.Value.html+"</dd>")
	}
	parts = append(parts, "</dl>")
	return Fragment{html: strings.Join(parts, "\n")}
}

func Details(summary string, values ...Fragment) Fragment {
	parts := []string{"<details><summary>" + Escape(summary) + "</summary>"}
	for _, value := range values {
		parts = append(parts, value.html)
	}
	parts = append(parts, "</details>")
	return Fragment{html: strings.Join(parts, "\n")}
}

func Section(title string, values ...Fragment) Fragment {
	parts := []string{"<section class=\"scenario-block\">", "<h3>" + Escape(title) + "</h3>"}
	for _, value := range values {
		parts = append(parts, value.html)
	}
	parts = append(parts, "</section>")
	return Fragment{html: strings.Join(parts, "\n")}
}

func Summary(label string, value string, code bool) SummaryItem {
	if code {
		return SummaryItem{Label: label, Value: Code(value)}
	}
	return SummaryItem{Label: label, Value: Text(value)}
}

func NewFilter(key string, label string, values []string) Filter {
	return Filter{Key: safeFilterKey(key), Label: label, Values: sortedUnique(values)}
}

func SearchText(values []string) string {
	return strings.ToLower(strings.Join(values, " "))
}

func TableCell(key string, value string, code bool) Cell {
	if code {
		return Cell{Key: key, Value: Code(value)}
	}
	return Cell{Key: key, Value: Text(value)}
}

func ListOrNone(values []string, code bool) Fragment {
	if len(values) == 0 {
		return Text("none")
	}
	items := make([]string, 0, len(values))
	for _, value := range values {
		if code {
			items = append(items, "<li><code>"+Escape(value)+"</code></li>")
			continue
		}
		items = append(items, "<li>"+Escape(value)+"</li>")
	}
	return Fragment{html: "<ul>" + strings.Join(items, "") + "</ul>"}
}

func Export(label string, fileName string, content string) ExportFile {
	return ExportFile{Label: label, FileName: SafeFileName(fileName), Content: content}
}

func SafeFileName(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\\", "-"), "/", "-"))
	var builder strings.Builder
	lastDash := false
	for _, char := range strings.ToLower(value) {
		switch {
		case (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '_':
			builder.WriteRune(char)
			lastDash = false
		case char == '-' || char == ' ':
			if !lastDash && builder.Len() > 0 {
				builder.WriteByte('-')
				lastDash = true
			}
		default:
			if !lastDash && builder.Len() > 0 {
				builder.WriteByte('-')
				lastDash = true
			}
		}
	}
	result := strings.Trim(builder.String(), "-.")
	if result == "" || result == "." || result == ".." {
		return "proofkit-rendered-view"
	}
	if len(result) > 120 {
		result = strings.Trim(result[:120], "-.")
	}
	if result == "" {
		return "proofkit-rendered-view"
	}
	return result
}

func Escape(value string) string {
	return html.EscapeString(value)
}

func FragmentID(value string) string {
	builder := strings.Builder{}
	lastDash := false
	for _, char := range strings.ToLower(value) {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			builder.WriteRune(char)
			lastDash = false
			continue
		}
		if !lastDash && builder.Len() > 0 {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	normalized := strings.Trim(builder.String(), "-")
	if normalized == "" {
		normalized = "section"
	}
	if len(normalized) > 64 {
		normalized = normalized[:64]
		normalized = strings.Trim(normalized, "-")
	}
	return "proofkit-" + normalized + "-" + stableSuffix(value)
}

func hierarchy(sections []HierarchySection) string {
	if len(sections) == 0 {
		return ""
	}
	parts := []string{"<nav class=\"hierarchy\" aria-label=\"Specification hierarchy\">"}
	for _, section := range sections {
		parts = append(parts, "<section><h2>"+Escape(section.Title)+"</h2>", hierarchyItems(section.Items), "</section>")
	}
	parts = append(parts, "</nav>")
	return strings.Join(parts, "\n")
}

func hierarchyItems(items []HierarchyItem) string {
	if len(items) == 0 {
		return "<p>none</p>"
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		label := Escape(item.Label)
		if href := safeHref(item.Href); href != "" {
			label = fmt.Sprintf("<a href=\"%s\">%s</a>", Escape(href), label)
		}
		detail := ""
		if item.Detail != "" {
			detail = " <span>" + Escape(item.Detail) + "</span>"
		}
		parts = append(parts, "<li>"+label+detail+"</li>")
	}
	return "<ul>" + strings.Join(parts, "") + "</ul>"
}

func controls(filters []Filter, hasTable bool) string {
	parts := []string{
		"<section class=\"controls\" aria-label=\"View filters\">",
		"<label class=\"search-label\" for=\"proofkit-search\">Search</label>",
		"<input id=\"proofkit-search\" type=\"search\" autocomplete=\"off\" placeholder=\"Filter records\">",
	}
	if hasTable {
		parts = append(parts, "<label for=\"proofkit-view-mode\">View</label><select id=\"proofkit-view-mode\"><option value=\"cards\">Cards</option><option value=\"table\">Table</option></select>")
	}
	parts = append(parts,
		"<label class=\"toggle\"><input id=\"proofkit-show-ids\" type=\"checkbox\" checked> Show IDs</label>",
		"<label class=\"toggle\"><input id=\"proofkit-open-details\" type=\"checkbox\"> Open details</label>",
	)
	for _, filter := range filters {
		key := safeFilterKey(filter.Key)
		parts = append(parts,
			fmt.Sprintf("<label for=\"proofkit-filter-%s\">%s</label>", Escape(key), Escape(filter.Label)),
			fmt.Sprintf("<select id=\"proofkit-filter-%s\" data-proofkit-filter data-filter-key=\"%s\">", Escape(key), Escape(key)),
			"<option value=\"\">All</option>",
		)
		for _, value := range filter.Values {
			parts = append(parts, fmt.Sprintf("<option value=\"%s\">%s</option>", Escape(value), Escape(value)))
		}
		parts = append(parts, "</select>")
	}
	parts = append(parts, "</section>")
	return strings.Join(parts, "\n")
}

func exports(files []ExportFile) string {
	if len(files) == 0 {
		return ""
	}
	parts := []string{"<section class=\"exports\" aria-label=\"View downloads\">", "<h2>Downloads</h2>"}
	for _, file := range files {
		fileName := SafeFileName(file.FileName)
		encoded := base64.StdEncoding.EncodeToString([]byte(file.Content))
		parts = append(parts, fmt.Sprintf("<button type=\"button\" data-proofkit-download data-download-file=\"%s\" data-download-content=\"%s\">%s</button>", Escape(fileName), Escape(encoded), Escape(file.Label)))
	}
	parts = append(parts, "</section>")
	return strings.Join(parts, "\n")
}

func cards(items []Card) string {
	groups := cardGroups(items)
	parts := []string{"<section class=\"cards\" data-proofkit-card-section aria-label=\"Rendered records\">"}
	for _, group := range groups {
		parts = append(parts,
			fmt.Sprintf("<section class=\"card-group\" data-proofkit-card-group id=\"%s\">", Escape(group.AnchorID)),
			fmt.Sprintf("<h2>%s <span>%d</span></h2>", Escape(group.Label), len(group.Cards)),
		)
		for _, card := range group.Cards {
			parts = append(parts, browserCard(card))
		}
		parts = append(parts, "</section>")
	}
	parts = append(parts, "</section>")
	return strings.Join(parts, "\n")
}

func browserCard(card Card) string {
	attributes := filterAttributes(card.FilterValues)
	return strings.Join([]string{
		fmt.Sprintf("<article class=\"card\" data-proofkit-card data-search=\"%s\"%s>", Escape(strings.ToLower(card.SearchText)), attributes),
		fmt.Sprintf("<h2><span class=\"proofkit-id\">%s</span><span class=\"proofkit-title\">%s</span></h2>", Escape(card.ID), Escape(card.Title)),
		card.Body.html,
		"</article>",
	}, "\n")
}

func table(input Table) string {
	parts := []string{
		"<section class=\"table-view\" data-proofkit-table-section aria-label=\"Rendered table\" hidden>",
		"<div class=\"table-scroll\">",
		"<table>",
		"<thead>",
		"<tr>",
	}
	for _, column := range input.Columns {
		parts = append(parts, fmt.Sprintf("<th scope=\"col\">%s</th>", Escape(column.Label)))
	}
	parts = append(parts, "</tr>", "</thead>", "<tbody>")
	for _, row := range input.Rows {
		parts = append(parts, tableRow(row, input.Columns))
	}
	parts = append(parts, "</tbody>", "</table>", "</div>", "</section>")
	return strings.Join(parts, "\n")
}

func tableRow(row Row, columns []Column) string {
	cells := map[string]string{}
	for _, cell := range row.Cells {
		cells[cell.Key] = cell.Value.html
	}
	parts := []string{fmt.Sprintf("<tr data-proofkit-table-row data-search=\"%s\"%s>", Escape(strings.ToLower(row.SearchText)), filterAttributes(row.FilterValues))}
	for _, column := range columns {
		parts = append(parts, "<td>"+cells[column.Key]+"</td>")
	}
	parts = append(parts, "</tr>")
	return strings.Join(parts, "\n")
}

func filterAttributes(values []FilterValue) string {
	parts := make([]string, 0, len(values))
	for _, filter := range values {
		parts = append(parts, fmt.Sprintf(" data-filter-%s=\"%s\"", Escape(safeFilterKey(filter.Key)), Escape(filter.Value)))
	}
	return strings.Join(parts, "")
}

type cardGroup struct {
	AnchorID string
	Label    string
	Cards    []Card
}

func cardGroups(cards []Card) []cardGroup {
	byKey := map[string]cardGroup{}
	for _, card := range cards {
		label := card.GroupLabel
		if label == "" {
			label = "Records"
		}
		key := card.GroupID
		if key == "" {
			key = label
		}
		group := byKey[key]
		group.Label = label
		group.Cards = append(group.Cards, card)
		byKey[key] = group
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		leftGroup := byKey[keys[left]]
		rightGroup := byKey[keys[right]]
		if leftGroup.Label != rightGroup.Label {
			return leftGroup.Label < rightGroup.Label
		}
		return keys[left] < keys[right]
	})
	result := make([]cardGroup, 0, len(keys))
	for _, key := range keys {
		group := byKey[key]
		group.AnchorID = FragmentID(key)
		result = append(result, group)
	}
	return result
}

func sortedUnique(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func safeFilterKey(value string) string {
	if filterKeyPattern.MatchString(value) {
		return value
	}
	return "invalid-filter-key-" + stableSuffix(value)
}

func safeHref(value string) string {
	if strings.HasPrefix(value, "#proofkit-") && !strings.ContainsAny(value, "\"'<> \t\r\n") {
		return value
	}
	return ""
}

func stableSuffix(value string) string {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(value))
	return fmt.Sprintf("%08x", hash.Sum32())
}

func css() string {
	return strings.Join([]string{
		":root{color-scheme:light dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;line-height:1.45;background:#f7f7f4;color:#1f2428}",
		"body{margin:0}",
		"main{max-width:1120px;margin:0 auto;padding:32px 20px 56px}",
		"header{margin-bottom:20px}",
		"h1{font-size:clamp(1.7rem,2.8vw,2.6rem);line-height:1.1;margin:0}",
		"h2{font-size:1.05rem;margin:0 0 12px}",
		"h3{font-size:.95rem;margin:18px 0 8px}",
		".eyebrow{font-size:.78rem;font-weight:700;letter-spacing:0;text-transform:uppercase;color:#586069;margin:0 0 8px}",
		"a{color:#0969da;text-decoration:none}a:hover{text-decoration:underline}",
		".summary,.hierarchy,.controls,.exports,.card,.table-view,.non-claims{background:#fff;border:1px solid #d8dee4;border-radius:8px;box-shadow:0 1px 2px rgba(31,35,40,.04)}",
		".summary{padding:16px;margin-bottom:16px}",
		".hierarchy{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;padding:16px;margin-bottom:16px}",
		".hierarchy section{min-width:0}",
		".hierarchy h2,.card-group>h2{font-size:.88rem;text-transform:uppercase;letter-spacing:0;color:#586069;margin:0 0 10px}",
		".hierarchy ul{margin:0;padding-left:18px}",
		".hierarchy li{margin:4px 0}.hierarchy span,.card-group>h2 span{font-weight:400;color:#586069}",
		"dl{display:grid;grid-template-columns:minmax(140px,220px) 1fr;gap:8px 14px;margin:0}",
		"dt{font-weight:700;color:#4b5563}",
		"dd{margin:0;min-width:0}",
		"code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em;background:#f1f5f9;border-radius:4px;padding:.1em .3em}",
		".controls{display:grid;grid-template-columns:minmax(180px,1fr) repeat(auto-fit,minmax(130px,200px));gap:10px;align-items:end;padding:14px;margin-bottom:10px;position:sticky;top:0;z-index:1}",
		".search-label{position:absolute;left:-10000px}",
		"input[type=search],select{width:100%;box-sizing:border-box;border:1px solid #c9d1d9;border-radius:6px;padding:8px 10px;background:#fff;color:inherit}",
		".toggle{white-space:nowrap;font-size:.92rem}",
		".exports{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:14px;margin-bottom:10px}",
		".exports h2{font-size:.88rem;text-transform:uppercase;letter-spacing:0;color:#586069;margin:0 8px 0 0}",
		"button{border:1px solid #c9d1d9;border-radius:6px;background:#f6f8fa;color:inherit;padding:8px 10px;cursor:pointer}button:hover{background:#eef2f6}",
		".result-count{margin:12px 2px;color:#586069}",
		".cards{display:grid;gap:18px}",
		".card-group{display:grid;gap:12px;scroll-margin-top:86px}",
		".card-group>h2{border-bottom:1px solid #d8dee4;padding-bottom:8px}",
		".card{padding:18px}",
		".proofkit-id{display:inline-block;margin-right:8px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em}",
		"html[data-show-ids=false] .proofkit-id{display:none}",
		".proofkit-title{font-weight:700}",
		"details{border:1px solid #d8dee4;border-radius:6px;margin-top:12px;padding:10px 12px}",
		"summary{cursor:pointer;font-weight:700}",
		".table-view{padding:0;overflow:hidden}",
		".table-scroll{overflow:auto}",
		"table{width:100%;border-collapse:collapse;font-size:.92rem}",
		"th,td{border-bottom:1px solid #d8dee4;padding:10px 12px;text-align:left;vertical-align:top}",
		"th{position:sticky;top:0;background:#f6f8fa;font-size:.78rem;text-transform:uppercase;letter-spacing:0;color:#586069}",
		".non-claims{margin-top:18px;padding:18px}",
		"ul{margin:8px 0 0;padding-left:22px}",
		"@media (max-width:720px){main{padding:24px 12px 40px}.controls{grid-template-columns:1fr;position:static}dl{grid-template-columns:1fr}.summary,.controls,.exports,.card,.non-claims{border-radius:6px}}",
		"@media (prefers-color-scheme:dark){:root{background:#101418;color:#e6edf3}.summary,.hierarchy,.controls,.exports,.card,.table-view,.non-claims{background:#161b22;border-color:#30363d}.eyebrow,.result-count,dt,.hierarchy h2,.card-group>h2,.hierarchy span,.card-group>h2 span,th,.exports h2{color:#9da7b1}input[type=search],select,th{background:#0d1117;border-color:#30363d}button{background:#21262d;border-color:#30363d}button:hover{background:#30363d}code{background:#0d1117}details,th,td,.card-group>h2{border-color:#30363d}a{color:#58a6ff}}",
	}, "")
}

func script() string {
	return strings.Join([]string{
		"const search=document.getElementById('proofkit-search');",
		"const showIds=document.getElementById('proofkit-show-ids');",
		"const openDetails=document.getElementById('proofkit-open-details');",
		"const viewMode=document.getElementById('proofkit-view-mode');",
		"const count=document.getElementById('proofkit-visible-count');",
		"const cards=Array.from(document.querySelectorAll('[data-proofkit-card]'));",
		"const cardGroups=Array.from(document.querySelectorAll('[data-proofkit-card-group]'));",
		"const cardSection=document.querySelector('[data-proofkit-card-section]');",
		"const tableSection=document.querySelector('[data-proofkit-table-section]');",
		"const rows=Array.from(document.querySelectorAll('[data-proofkit-table-row]'));",
		"const filters=Array.from(document.querySelectorAll('[data-proofkit-filter]'));",
		"function matchesFilters(item,query){",
		"const matchesSearch=query===''||(item.getAttribute('data-search')||'').includes(query);",
		"const matchesFieldFilters=filters.every((filter)=>{const value=filter.value;return value===''||(item.getAttribute('data-filter-'+filter.getAttribute('data-filter-key'))===value);});",
		"return matchesSearch&&matchesFieldFilters;",
		"}",
		"function applyFilters(){",
		"const query=(search.value||'').trim().toLowerCase();",
		"let visible=0;",
		"for(const card of cards){",
		"const shown=matchesFilters(card,query);",
		"card.hidden=!shown;",
		"if(shown) visible+=1;",
		"}",
		"for(const row of rows){row.hidden=!matchesFilters(row,query);}",
		"for(const group of cardGroups){group.hidden=Array.from(group.querySelectorAll('[data-proofkit-card]')).every((card)=>card.hidden);}",
		"const mode=viewMode?viewMode.value:'cards';",
		"if(cardSection) cardSection.hidden=mode==='table';",
		"if(tableSection) tableSection.hidden=mode!=='table';",
		"document.documentElement.dataset.showIds=showIds.checked?'true':'false';",
		"for(const detail of document.querySelectorAll('details')) detail.open=openDetails.checked;",
		"count.textContent=String(visible);",
		"}",
		"function installDownloads(){",
		"for(const button of document.querySelectorAll('[data-proofkit-download]')){",
		"button.addEventListener('click',()=>{",
		"const binary=atob(button.getAttribute('data-download-content')||'');",
		"const bytes=new Uint8Array(binary.length);",
		"for(let index=0;index<binary.length;index++) bytes[index]=binary.charCodeAt(index);",
		"const blob=new Blob([bytes],{type:'application/octet-stream'});",
		"const link=document.createElement('a');",
		"link.href=URL.createObjectURL(blob);",
		"link.download=button.getAttribute('data-download-file')||'proofkit-rendered-view';",
		"document.body.appendChild(link);",
		"link.click();",
		"link.remove();",
		"URL.revokeObjectURL(link.href);",
		"});",
		"}",
		"}",
		"search.addEventListener('input',applyFilters);",
		"showIds.addEventListener('change',applyFilters);",
		"openDetails.addEventListener('change',applyFilters);",
		"if(viewMode) viewMode.addEventListener('change',applyFilters);",
		"for(const filter of filters) filter.addEventListener('change',applyFilters);",
		"installDownloads();",
		"applyFilters();",
	}, "")
}
