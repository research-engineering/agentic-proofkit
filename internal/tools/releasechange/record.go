package releasechange

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	RecordPath       = "release/change-record.v2.json"
	maxRecordBytes   = 1 << 20
	maxListItems     = 128
	maxEntryTextByte = 4096
)

type Record struct {
	Additions            []Change
	BreakingChanges      []Change
	ChangeClass          string
	KnownLimitations     []string
	Migration            Migration
	PlatformRequirements []string
	PreviousVersion      string
	RollbackStrategy     string
	SchemaVersion        int
	Version              string
}

type Change struct {
	ChangeID string
	Summary  string
}

type Migration struct {
	Required bool
	Steps    []string
}

func Read(path string) (Record, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Record{}, fmt.Errorf("read release change record: %w", err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), maxRecordBytes)
	if err != nil {
		return Record{}, fmt.Errorf("decode release change record: %w", err)
	}
	return Admit(value)
}

func Admit(raw any) (Record, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Record{}, fmt.Errorf("release change record must be an object")
	}
	if err := admit.KnownKeys(record, []string{"additions", "breakingChanges", "changeClass", "knownLimitations", "migration", "platformRequirements", "previousVersion", "rollback", "schemaVersion", "version"}, "release change record"); err != nil {
		return Record{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 2) {
		return Record{}, fmt.Errorf("release change record schemaVersion must be 2")
	}
	version, err := boundedText(record["version"], "release change record version")
	if err != nil {
		return Record{}, err
	}
	previousVersion, err := boundedText(record["previousVersion"], "release change record previousVersion")
	if err != nil {
		return Record{}, err
	}
	currentSemVer, err := parseCanonicalSemVer(version)
	if err != nil {
		return Record{}, fmt.Errorf("release change record version: %w", err)
	}
	previousSemVer, err := parseCanonicalSemVer(previousVersion)
	if err != nil {
		return Record{}, fmt.Errorf("release change record previousVersion: %w", err)
	}
	if compareSemVer(currentSemVer, previousSemVer) <= 0 {
		return Record{}, fmt.Errorf("release change record version must be greater than previousVersion")
	}
	changeClass, err := admit.Enum(record["changeClass"], map[string]struct{}{"breaking": {}, "compatible": {}}, "release change record changeClass")
	if err != nil {
		return Record{}, err
	}
	breaking, err := admitChanges(record["breakingChanges"], "release change record breakingChanges")
	if err != nil {
		return Record{}, err
	}
	additions, err := admitChanges(record["additions"], "release change record additions")
	if err != nil {
		return Record{}, err
	}
	if err := uniqueChangeIDs(breaking, additions); err != nil {
		return Record{}, err
	}
	migration, err := admitMigration(record["migration"])
	if err != nil {
		return Record{}, err
	}
	requiredClass := "compatible"
	if len(breaking) > 0 || migration.Required {
		requiredClass = "breaking"
	}
	if changeClass != requiredClass {
		return Record{}, fmt.Errorf("release change record changeClass does not match breakingChanges and migration")
	}
	if changeClass == "breaking" && !isBreakingBump(previousSemVer, currentSemVer) {
		return Record{}, fmt.Errorf("release change record breaking change requires a SemVer major bump or a pre-1.0 minor bump")
	}
	if changeClass == "compatible" && currentSemVer.Major != previousSemVer.Major {
		return Record{}, fmt.Errorf("release change record compatible change must not change the SemVer major version")
	}
	platforms, err := orderedUniqueText(record["platformRequirements"], "release change record platformRequirements", true)
	if err != nil {
		return Record{}, err
	}
	limitations, err := orderedUniqueText(record["knownLimitations"], "release change record knownLimitations", true)
	if err != nil {
		return Record{}, err
	}
	rollback, ok := record["rollback"].(map[string]any)
	if !ok {
		return Record{}, fmt.Errorf("release change record rollback must be an object")
	}
	if err := admit.KnownKeys(rollback, []string{"strategy"}, "release change record rollback"); err != nil {
		return Record{}, err
	}
	strategy, err := admit.NonEmptyText(rollback["strategy"], "release change record rollback strategy")
	if err != nil {
		return Record{}, err
	}
	if strategy != "previous_admitted_version" {
		return Record{}, fmt.Errorf("release change record rollback strategy must be previous_admitted_version")
	}
	return Record{
		Additions: additions, BreakingChanges: breaking, ChangeClass: changeClass, KnownLimitations: limitations,
		Migration: migration, PlatformRequirements: platforms, RollbackStrategy: strategy,
		PreviousVersion: previousVersion, SchemaVersion: 2, Version: version,
	}, nil
}

func RequireVersion(record Record, version string) error {
	if record.Version != version {
		return fmt.Errorf("release change record version %s does not match package version %s", record.Version, version)
	}
	return nil
}

func RenderMarkdown(record Record, npmPackage, pythonPackage string, pypiPublished bool) string {
	lines := []string{
		fmt.Sprintf("# %s %s", npmPackage, record.Version),
		"",
		"## Breaking Contract Changes",
		"",
	}
	lines = appendChanges(lines, record.BreakingChanges)
	lines = append(lines, "", "## Additions", "")
	lines = appendChanges(lines, record.Additions)
	lines = append(lines, "", "## Migration", "")
	if record.Migration.Required {
		lines = append(lines, "Migration is required:", "")
		lines = appendTextList(lines, record.Migration.Steps)
	} else {
		lines = append(lines, "No consumer migration is required.")
	}
	lines = append(lines, "", "## Platform Requirements", "")
	lines = appendTextList(lines, record.PlatformRequirements)
	lines = append(lines, "", "## Known Limitations", "")
	lines = appendTextList(lines, record.KnownLimitations)
	lines = append(lines,
		"", "## Install", "", "Primary npm channel:", "", "```bash",
		fmt.Sprintf("npm install --save-dev --save-exact %s@%s", npmPackage, record.Version), "```",
	)
	if current, err := parseCanonicalSemVer(record.Version); err == nil && current.Major == 0 {
		lines = append(lines, "", "Pre-1.0 npm consumers must keep this dependency exact-pinned.")
	}
	if pypiPublished {
		lines = append(lines,
			"", "Python/uv channel:", "", "```bash",
			fmt.Sprintf("uv tool install %s==%s", pythonPackage, record.Version), "```",
		)
	} else {
		lines = append(lines, "", "Python wheels are candidate artifacts until a PyPI release workflow publishes them.")
	}
	lines = append(lines,
		"", "GitHub Release assets and checksums are archive and provenance evidence, not package-manager dependency authority.",
		"", "## Rollback", "",
		"- First follow the migration and persistent-state compatibility restrictions above; changing a package pin does not roll back repository state.",
		fmt.Sprintf("- Pin npm consumers to the previous admitted version %s with `npm install --save-dev --save-exact %s@%s`.", record.PreviousVersion, npmPackage, record.PreviousVersion),
	)
	if pypiPublished {
		lines = append(lines, fmt.Sprintf("- Pin Python/uv consumers with `uv tool install %s==%s`.", pythonPackage, record.PreviousVersion))
	}
	lines = append(lines, "- Treat local package artifacts as candidates until registry identity is proven.")
	return strings.Join(lines, "\n") + "\n"
}

type semVer struct {
	Major uint64
	Minor uint64
	Patch uint64
}

func parseCanonicalSemVer(value string) (semVer, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return semVer{}, fmt.Errorf("must be canonical SemVer")
	}
	numbers := [3]uint64{}
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return semVer{}, fmt.Errorf("must be canonical SemVer")
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return semVer{}, fmt.Errorf("must be canonical SemVer")
			}
		}
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return semVer{}, fmt.Errorf("must be canonical SemVer")
		}
		numbers[index] = number
	}
	return semVer{Major: numbers[0], Minor: numbers[1], Patch: numbers[2]}, nil
}

func compareSemVer(left, right semVer) int {
	for _, pair := range [][2]uint64{{left.Major, right.Major}, {left.Minor, right.Minor}, {left.Patch, right.Patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	return 0
}

func isBreakingBump(previous, current semVer) bool {
	if current.Major > previous.Major {
		return true
	}
	if previous.Major == 0 && current.Major == 0 && current.Minor > previous.Minor {
		return true
	}
	return false
}

func admitChanges(raw any, context string) ([]Change, error) {
	values, ok := raw.([]any)
	if !ok || len(values) > maxListItems {
		return nil, fmt.Errorf("%s must be an array with at most %d records", context, maxListItems)
	}
	changes := make([]Change, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", context, index)
		}
		if err := admit.KnownKeys(record, []string{"changeId", "summary"}, fmt.Sprintf("%s[%d]", context, index)); err != nil {
			return nil, err
		}
		changeID, err := admit.RuleID(record["changeId"], fmt.Sprintf("%s[%d] changeId", context, index))
		if err != nil {
			return nil, err
		}
		summary, err := boundedText(record["summary"], fmt.Sprintf("%s[%d] summary", context, index))
		if err != nil {
			return nil, err
		}
		changes = append(changes, Change{ChangeID: changeID, Summary: summary})
	}
	return changes, nil
}

func admitMigration(raw any) (Migration, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Migration{}, fmt.Errorf("release change record migration must be an object")
	}
	if err := admit.KnownKeys(record, []string{"required", "steps"}, "release change record migration"); err != nil {
		return Migration{}, err
	}
	required, ok := record["required"].(bool)
	if !ok {
		return Migration{}, fmt.Errorf("release change record migration required must be boolean")
	}
	steps, err := orderedUniqueText(record["steps"], "release change record migration steps", !required)
	if err != nil {
		return Migration{}, err
	}
	if !required && len(steps) != 0 {
		return Migration{}, fmt.Errorf("release change record migration steps must be empty when migration is not required")
	}
	return Migration{Required: required, Steps: steps}, nil
}

func orderedUniqueText(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) > maxListItems {
		return nil, fmt.Errorf("%s must be an array with at most %d values", context, maxListItems)
	}
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for index, value := range values {
		text, err := boundedText(value, fmt.Sprintf("%s[%d]", context, index))
		if err != nil {
			return nil, err
		}
		if _, exists := seen[text]; exists {
			return nil, fmt.Errorf("%s must be unique", context)
		}
		seen[text] = struct{}{}
		result = append(result, text)
	}
	return result, nil
}

func boundedText(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("%s must be single-line text", context)
	}
	if len(value) > maxEntryTextByte {
		return "", fmt.Errorf("%s exceeds %d bytes", context, maxEntryTextByte)
	}
	return value, nil
}

func uniqueChangeIDs(groups ...[]Change) error {
	seen := map[string]struct{}{}
	for _, changes := range groups {
		for _, change := range changes {
			if _, exists := seen[change.ChangeID]; exists {
				return fmt.Errorf("release change record changeId must be unique: %s", change.ChangeID)
			}
			seen[change.ChangeID] = struct{}{}
		}
	}
	return nil
}

func appendChanges(lines []string, changes []Change) []string {
	if len(changes) == 0 {
		return append(lines, "- None.")
	}
	for _, change := range changes {
		lines = append(lines, fmt.Sprintf("- `%s`: %s", change.ChangeID, change.Summary))
	}
	return lines
}

func appendTextList(lines []string, values []string) []string {
	if len(values) == 0 {
		return append(lines, "- None.")
	}
	for _, value := range values {
		lines = append(lines, "- "+value)
	}
	return lines
}
