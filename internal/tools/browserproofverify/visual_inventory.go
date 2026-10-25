package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// The visual reference inventory is owned here: every rendered view in each
// engine, color scheme and width, plus one README scene. References are
// canonical RGBA digests with dimensions; no image is stored in the
// repository. The harness renders these views; the record and the committed
// inventory must equal this set.
const (
	visualTestRoot              = "tests/visual"
	visualEnvironmentPath       = "tests/visual/environment.json"
	visualReferencesPath        = "tests/visual/references.json"
	visualFontConfigPath        = "tests/visual/fonts.conf"
	visualCaptureDigestScript   = "scripts/browser-visual-capture-digests.mjs"
	visualObservedRunFile       = "observed-environment.json"
	visualCandidateRunFile      = "candidate-references.json"
	visualCaptureRunDirectory   = "captures"
	visualUnstableRunDirectory  = "unstable"
	visualClipHeight            = 2400
	readmeSceneView             = "readme-scene"
	readmeSceneWidth            = 1440
	readmeSceneHeight           = 960
	visualMaxCaptureDigestBytes = 1 << 20
)

var (
	visualEngines = []string{"chromium", "firefox", "webkit"}
	visualSchemes = []string{"light", "dark"}
	visualWidths  = []int{320, 1440}
	// Five static renderings in Cards and Table modes, then four workspace tabs.
	visualViews = []string{
		"static-source-cards", "static-source-table",
		"static-spec-tree-cards", "static-spec-tree-table",
		"static-proof-structured-cards", "static-proof-structured-table",
		"static-proof-compact-cards", "static-proof-compact-table",
		"static-coverage-cards", "static-coverage-table",
		"workspace-specifications", "workspace-coverage", "workspace-diff", "workspace-traceability",
	}
	// Controls run in every engine: a routed unchanged stylesheet copy must
	// keep the admitted digest, and each mutated copy must change it.
	visualControlTitles = []string{
		"a change of the monospace family to sans-serif differs from its reference",
		"a change of the sans-serif family to serif differs from its reference",
		"a font-weight change from 400 to 700 differs from its reference",
		"a one-pixel shift differs from its reference",
		"a one-unit text color change differs from its reference",
		"a routed unchanged stylesheet keeps its reference",
	}
	// The font-face check runs in every engine: each product font stack must
	// draw its intended face.
	visualFontFaceTitles = []string{
		"each product font stack draws its intended face",
	}
	// Fields of the observed environment tuple compared before any browser
	// launch. The CPU is recorded in every run but is not compared.
	visualComparedEnvironmentFields = []string{"architecture", "dockerImage", "emulation", "engines", "fontConfig", "fontMatches", "os", "packages"}
)

type visualReference struct {
	Engine string
	View   string
	Scheme string
	Width  int
}

// id is the reference ID <engine>/<view>.<scheme>.<width>.
func (reference visualReference) id() string {
	return fmt.Sprintf("%s/%s.%s.%d", reference.Engine, reference.View, reference.Scheme, reference.Width)
}

func (reference visualReference) isReadmeScene() bool {
	return reference.View == readmeSceneView
}

func (reference visualReference) testID() string {
	if reference.isReadmeScene() {
		return fmt.Sprintf("%s/readme-scene.spec.mjs::readme-scene.spec.mjs > %s %s %dx%d", visualTestRoot, reference.View, reference.Scheme, readmeSceneWidth, readmeSceneHeight)
	}
	return fmt.Sprintf("%s/references.spec.mjs::references.spec.mjs > %s %s %d", visualTestRoot, reference.View, reference.Scheme, reference.Width)
}

// admitDimensions bounds a reference's dimensions: a view is exactly its
// width and at most clipHeight tall; the README scene is exactly 1440x960.
func (reference visualReference) admitDimensions(width, height int) error {
	if reference.isReadmeScene() {
		if width != readmeSceneWidth || height != readmeSceneHeight {
			return fmt.Errorf("visual reference %s must be %dx%d", reference.id(), readmeSceneWidth, readmeSceneHeight)
		}
		return nil
	}
	if width != reference.Width || height < 1 || height > visualClipHeight {
		return fmt.Errorf("visual reference %s must be %d CSS pixels wide and 1 to %d tall", reference.id(), reference.Width, visualClipHeight)
	}
	return nil
}

// expectedVisualReferences returns the exact Cartesian inventory sorted by ID.
func expectedVisualReferences() []visualReference {
	references := make([]visualReference, 0, len(visualViews)*len(visualEngines)*len(visualSchemes)*len(visualWidths)+1)
	for _, engine := range visualEngines {
		for _, view := range visualViews {
			for _, scheme := range visualSchemes {
				for _, width := range visualWidths {
					references = append(references, visualReference{Engine: engine, View: view, Scheme: scheme, Width: width})
				}
			}
		}
	}
	references = append(references, visualReference{Engine: "chromium", View: readmeSceneView, Scheme: "light", Width: readmeSceneWidth})
	sort.Slice(references, func(left, right int) bool { return references[left].id() < references[right].id() })
	return references
}

// expectedVisualProjectTests is the exact test identity set each project must
// pass: one comparison per reference of that engine plus the controls and the
// font-face check.
func expectedVisualProjectTests() map[string][]string {
	result := make(map[string][]string, len(visualEngines))
	for _, engine := range visualEngines {
		ids := []string{}
		for _, title := range visualControlTitles {
			ids = append(ids, fmt.Sprintf("%s/controls.spec.mjs::controls.spec.mjs > %s", visualTestRoot, title))
		}
		for _, title := range visualFontFaceTitles {
			ids = append(ids, fmt.Sprintf("%s/font-faces.spec.mjs::font-faces.spec.mjs > %s", visualTestRoot, title))
		}
		for _, reference := range expectedVisualReferences() {
			if reference.Engine == engine {
				ids = append(ids, reference.testID())
			}
		}
		slices.Sort(ids)
		result[engine] = ids
	}
	return result
}

type visualEnvironment struct {
	EnvironmentID   string
	Observed        map[string]any
	BrowserVersions map[string]string
	Raw             map[string]any
}

// loadVisualEnvironment admits the recorded reference environment and returns
// its identity: the SHA-256 of its canonical compact JSON.
func loadVisualEnvironment(root string) (visualEnvironment, error) {
	value, err := readRepositoryJSON(root, visualEnvironmentPath, 1<<20)
	if err != nil {
		return visualEnvironment{}, fmt.Errorf("read visual reference environment: %w", err)
	}
	record, ok := value.(map[string]any)
	if !ok || admit.KnownKeys(record, []string{"browserVersions", "image", "kind", "observed", "schemaVersion"}, "visual reference environment") != nil ||
		!admit.JSONNumberEquals(record["schemaVersion"], 1) || record["kind"] != "proofkit.browser-visual-environment" {
		return visualEnvironment{}, fmt.Errorf("visual reference environment identity is invalid")
	}
	if err := admitVisualImage(record["image"]); err != nil {
		return visualEnvironment{}, err
	}
	observed, ok := record["observed"].(map[string]any)
	if !ok || admit.KnownKeys(observed, visualComparedEnvironmentFields, "visual reference environment observed tuple") != nil || len(observed) != len(visualComparedEnvironmentFields) {
		return visualEnvironment{}, fmt.Errorf("visual reference environment must record exactly the compared tuple")
	}
	if err := admitObservedTuple(observed, true); err != nil {
		return visualEnvironment{}, err
	}
	versions, ok := record["browserVersions"].(map[string]any)
	if !ok || admit.KnownKeys(versions, visualEngines, "visual reference environment browserVersions") != nil || len(versions) != len(visualEngines) {
		return visualEnvironment{}, fmt.Errorf("visual reference environment must record one browser version per engine")
	}
	browserVersions := make(map[string]string, len(versions))
	for _, engine := range visualEngines {
		version, err := admit.NonEmptyText(versions[engine], "visual reference environment browser version")
		if err != nil {
			return visualEnvironment{}, err
		}
		browserVersions[engine] = version
	}
	encoded, err := stablejson.MarshalLayout(record, stablejson.LayoutCompact)
	if err != nil {
		return visualEnvironment{}, err
	}
	return visualEnvironment{
		EnvironmentID:   digest.SHA256TextRef(strings.TrimSuffix(string(encoded), "\n")),
		Observed:        observed,
		BrowserVersions: browserVersions,
		Raw:             record,
	}, nil
}

func admitVisualImage(raw any) error {
	image, ok := raw.(map[string]any)
	if !ok || admit.KnownKeys(image, []string{"indexDigest", "name", "platform", "platformDigests", "tag"}, "visual reference environment image") != nil || len(image) != 5 {
		return fmt.Errorf("visual reference environment image is invalid")
	}
	for _, key := range []string{"name", "tag", "platform"} {
		if _, err := admit.NonEmptyText(image[key], "visual reference environment image "+key); err != nil {
			return err
		}
	}
	if _, err := admit.SHA256Ref(image["indexDigest"], "visual reference environment image indexDigest"); err != nil {
		return err
	}
	platforms, ok := image["platformDigests"].(map[string]any)
	if !ok || len(platforms) == 0 {
		return fmt.Errorf("visual reference environment image must record its platform digests")
	}
	if _, recorded := platforms[fmt.Sprint(image["platform"])]; !recorded {
		return fmt.Errorf("visual reference environment image platform digest is missing")
	}
	for platform, value := range platforms {
		if _, err := admit.NonEmptyText(platform, "visual reference environment image platform"); err != nil {
			return err
		}
		if _, err := admit.SHA256Ref(value, "visual reference environment image platform digest"); err != nil {
			return err
		}
	}
	return nil
}

// admitObservedTuple checks the closed shape of an observed tuple. A reference
// environment must observe every field; a run may observe absent fields.
func admitObservedTuple(observed map[string]any, reference bool) error {
	for _, field := range visualComparedEnvironmentFields {
		value, present := observed[field]
		if !present {
			return fmt.Errorf("observed environment omits a compared field")
		}
		if value == nil {
			if reference {
				return fmt.Errorf("visual reference environment field must be observed")
			}
			continue
		}
		switch field {
		case "architecture", "emulation":
			if _, err := admit.NonEmptyText(value, "observed environment "+field); err != nil {
				return err
			}
		case "fontConfig":
			if _, err := admit.SHA256Ref(value, "observed environment fontConfig"); err != nil {
				return err
			}
		case "os":
			os, ok := value.(map[string]any)
			if !ok || admit.KnownKeys(os, []string{"id", "versionId"}, "observed environment os") != nil {
				return fmt.Errorf("observed environment os is invalid")
			}
		case "dockerImage", "engines", "fontMatches", "packages":
			fields, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("observed environment %s must be an object", field)
			}
			for key, item := range fields {
				if _, err := admit.NonEmptyText(key, "observed environment key"); err != nil {
					return err
				}
				if item != nil {
					if _, ok := item.(string); !ok {
						return fmt.Errorf("observed environment %s values must be text or null", field)
					}
				}
			}
		}
	}
	if reference && observed["emulation"] != "none" {
		return fmt.Errorf("visual reference environment must not be emulated")
	}
	return nil
}

// visualEnvironmentDivergence lists the compared fields whose observed value
// differs from the reference value.
func visualEnvironmentDivergence(reference, observed map[string]any) ([]string, error) {
	divergent := []string{}
	for _, field := range visualComparedEnvironmentFields {
		left, err := stablejson.MarshalLayout(reference[field], stablejson.LayoutCompact)
		if err != nil {
			return nil, err
		}
		right, err := stablejson.MarshalLayout(observed[field], stablejson.LayoutCompact)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(left, right) {
			divergent = append(divergent, field)
		}
	}
	return divergent, nil
}

type visualReferenceInventory struct {
	EnvironmentID    string
	ReferencesDigest string
	Count            int
}

type visualReferenceDigest struct {
	ID         string
	Width      int
	Height     int
	RGBASHA256 string
}

// admitVisualReferenceEntries admits a closed digest inventory: exactly the
// expected ID set in ID order with no duplicate, a lowercase SHA-256 digest
// per entry, and dimensions within each reference's bounds.
func admitVisualReferenceEntries(raw any, context string) ([]visualReferenceDigest, error) {
	entries, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must list its references", context)
	}
	expected := expectedVisualReferences()
	byID := make(map[string]visualReference, len(expected))
	for _, reference := range expected {
		byID[reference.id()] = reference
	}
	result := make([]visualReferenceDigest, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for index, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]any)
		if !ok || admit.KnownKeys(entry, []string{"height", "id", "rgbaSHA256", "width"}, context+" reference") != nil || len(entry) != 4 {
			return nil, fmt.Errorf("%s entry %d must be exactly {height, id, rgbaSHA256, width}", context, index)
		}
		id, _ := entry["id"].(string)
		reference, known := byID[id]
		if !known {
			return nil, fmt.Errorf("%s entry %d names an ID outside the expected inventory", context, index)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("%s lists %s more than once", context, id)
		}
		seen[id] = struct{}{}
		if index > 0 && id <= result[index-1].ID {
			return nil, fmt.Errorf("%s must be sorted by ID", context)
		}
		hash, err := admit.LowercaseSHA256(entry["rgbaSHA256"], context+" rgbaSHA256")
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", context, id, err)
		}
		width, widthErr := admit.CanonicalInteger(entry["width"], context+" width")
		height, heightErr := admit.CanonicalInteger(entry["height"], context+" height")
		if widthErr != nil || heightErr != nil {
			return nil, fmt.Errorf("%s %s dimensions must be integers", context, id)
		}
		if err := reference.admitDimensions(int(width), int(height)); err != nil {
			return nil, err
		}
		result = append(result, visualReferenceDigest{ID: id, Width: int(width), Height: int(height), RGBASHA256: hash})
	}
	if len(result) != len(expected) {
		missing := []string{}
		for _, reference := range expected {
			if _, ok := seen[reference.id()]; !ok {
				missing = append(missing, reference.id())
			}
		}
		return nil, fmt.Errorf("%s must list all %d expected references; missing %d, first %s", context, len(expected), len(missing), firstOrNone(missing))
	}
	return result, nil
}

func firstOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return values[0]
}

// verifyVisualReferences admits the committed digest inventory: it must bind
// the current environment identity and equal the expected closed ID set.
func verifyVisualReferences(root string) (visualReferenceInventory, error) {
	environment, err := loadVisualEnvironment(root)
	if err != nil {
		return visualReferenceInventory{}, err
	}
	raw, err := readRepositoryFile(root, visualReferencesPath, 4<<20)
	if err != nil {
		return visualReferenceInventory{}, fmt.Errorf("read visual reference inventory: %w", err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return visualReferenceInventory{}, err
	}
	record, ok := value.(map[string]any)
	if !ok || admit.KnownKeys(record, []string{"clipHeight", "environmentId", "kind", "references", "schemaVersion"}, "visual reference inventory") != nil ||
		!admit.JSONNumberEquals(record["schemaVersion"], 1) || record["kind"] != "proofkit.browser-visual-references" ||
		!admit.JSONNumberEquals(record["clipHeight"], visualClipHeight) {
		return visualReferenceInventory{}, fmt.Errorf("visual reference inventory identity is invalid")
	}
	if record["environmentId"] != environment.EnvironmentID {
		return visualReferenceInventory{}, fmt.Errorf("visual reference inventory environmentId does not match the recorded environment; re-admit the references")
	}
	entries, err := admitVisualReferenceEntries(record["references"], "visual reference inventory")
	if err != nil {
		return visualReferenceInventory{}, err
	}
	return visualReferenceInventory{EnvironmentID: environment.EnvironmentID, ReferencesDigest: digest.SHA256BytesRef(raw), Count: len(entries)}, nil
}

// buildVisualReferenceInventoryFromRun is the owner action that admits the
// captures of one gate run. It admits only a run whose recorded observed
// environment equals the recorded reference environment, with no unstable
// directory and exactly one regular capture file per expected ID. It
// recomputes every digest from the PNG files and refuses a run whose candidate
// inventory disagrees. It cannot authenticate the run directory as unmodified
// gate output; only a passing gate on the admitting tree proves the admitted
// digests. The gate never calls it.
func buildVisualReferenceInventoryFromRun(root, runDirectory string) ([]byte, error) {
	environment, err := loadVisualEnvironment(root)
	if err != nil {
		return nil, err
	}
	if err := admitRunObservedEnvironment(runDirectory, environment); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(runDirectory, visualUnstableRunDirectory)); err == nil {
		return nil, fmt.Errorf("visual run has unstable captures; every capture must be double-captured byte-equal")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	captures := filepath.Join(runDirectory, visualCaptureRunDirectory)
	if err := admitRunCaptureFiles(captures); err != nil {
		return nil, err
	}
	recomputed, err := recomputeCaptureDigests(root, captures)
	if err != nil {
		return nil, err
	}
	if err := crossCheckCandidateInventory(runDirectory, recomputed); err != nil {
		return nil, err
	}
	references := make([]any, 0, len(recomputed))
	for _, entry := range recomputed {
		references = append(references, map[string]any{"height": entry.Height, "id": entry.ID, "rgbaSHA256": entry.RGBASHA256, "width": entry.Width})
	}
	return stablejson.MarshalLayout(map[string]any{
		"clipHeight":    visualClipHeight,
		"environmentId": environment.EnvironmentID,
		"kind":          "proofkit.browser-visual-references",
		"references":    references,
		"schemaVersion": 1,
	}, stablejson.LayoutPretty)
}

func readRunFile(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("visual run file must be a regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maxBytes {
		return nil, fmt.Errorf("visual run file exceeds its size limit")
	}
	return content, nil
}

// admitRunObservedEnvironment requires the run's observed environment to equal
// the recorded reference environment in every compared field.
func admitRunObservedEnvironment(runDirectory string, environment visualEnvironment) error {
	raw, err := readRunFile(filepath.Join(runDirectory, visualObservedRunFile), 1<<20)
	if err != nil {
		return fmt.Errorf("read the run's observed environment: %w", err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return err
	}
	observed, ok := value.(map[string]any)
	if !ok || admit.KnownKeys(observed, append([]string{"cpu", "divergentFields"}, visualComparedEnvironmentFields...), "visual run observed environment") != nil ||
		len(observed) != len(visualComparedEnvironmentFields)+2 {
		return fmt.Errorf("visual run observed environment must record the CPU, every compared field and divergentFields")
	}
	if err := admitObservedTuple(observed, false); err != nil {
		return err
	}
	if err := admitObservedCPU(observed["cpu"]); err != nil {
		return err
	}
	divergent, err := visualEnvironmentDivergence(environment.Observed, observed)
	if err != nil {
		return err
	}
	if len(divergent) != 0 {
		return fmt.Errorf("visual run observed another environment (%s); only a reference-environment run can be admitted", strings.Join(divergent, ", "))
	}
	if !emptyArray(observed["divergentFields"]) {
		return fmt.Errorf("visual run observed environment lists divergent fields although every compared field equals the recorded environment; only a reference-environment run can be admitted")
	}
	return nil
}

// admitRunCaptureFiles requires exactly one regular PNG capture per expected
// ID below the capture directory and nothing else.
func admitRunCaptureFiles(captures string) error {
	expected := map[string]struct{}{}
	for _, reference := range expectedVisualReferences() {
		expected[reference.id()+".png"] = struct{}{}
	}
	found := map[string]struct{}{}
	err := filepath.WalkDir(captures, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("visual run captures must not contain symlinks")
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(captures, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if _, ok := expected[relative]; !ok || !entry.Type().IsRegular() {
			return fmt.Errorf("visual run captures contain an unexpected file %s", admit.RedactStructuralText(relative))
		}
		found[relative] = struct{}{}
		return nil
	})
	if err != nil {
		return fmt.Errorf("admit visual run captures: %w", err)
	}
	if len(found) != len(expected) {
		missing := []string{}
		for name := range expected {
			if _, ok := found[name]; !ok {
				missing = append(missing, strings.TrimSuffix(name, ".png"))
			}
		}
		slices.Sort(missing)
		return fmt.Errorf("visual run is missing %d of %d captures, first %s", len(missing), len(expected), firstOrNone(missing))
	}
	return nil
}

// recomputeCaptureDigests decodes every capture through the canonical digest
// owner in the visual harness and admits the result as a closed inventory.
func recomputeCaptureDigests(root, captures string) ([]visualReferenceDigest, error) {
	absolute, err := filepath.Abs(captures)
	if err != nil {
		return nil, err
	}
	command := exec.Command("node", filepath.FromSlash(visualCaptureDigestScript), absolute)
	command.Dir = root
	var stdout bytes.Buffer
	command.Stdout = &stdout
	stderr := diagnostic.NewStderrCapture()
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if childErr := stderr.Failure("visual capture digest stderr"); childErr != nil {
			return nil, fmt.Errorf("recompute visual capture digests: %w; %s", err, childErr)
		}
		return nil, fmt.Errorf("recompute visual capture digests: %w", err)
	}
	if stdout.Len() > visualMaxCaptureDigestBytes {
		return nil, fmt.Errorf("visual capture digest output exceeds its size limit")
	}
	value, err := admission.DecodeJSON(bytes.NewReader(stdout.Bytes()), visualMaxCaptureDigestBytes)
	if err != nil {
		return nil, err
	}
	return admitVisualReferenceEntries(value, "recomputed capture inventory")
}

// crossCheckCandidateInventory refuses a run whose own candidate inventory
// disagrees with the recomputed digests: a capture changed after the run.
func crossCheckCandidateInventory(runDirectory string, recomputed []visualReferenceDigest) error {
	raw, err := readRunFile(filepath.Join(runDirectory, visualCandidateRunFile), 4<<20)
	if err != nil {
		return fmt.Errorf("read the run's candidate inventory: %w", err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return err
	}
	record, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("visual run candidate inventory must be an object")
	}
	candidate, err := admitVisualReferenceEntries(record["references"], "visual run candidate inventory")
	if err != nil {
		return err
	}
	for index, entry := range recomputed {
		if candidate[index] != entry {
			return fmt.Errorf("visual run capture %s no longer matches the run's candidate inventory", entry.ID)
		}
	}
	return nil
}

func readRepositoryFile(root, path string, maxBytes int64) ([]byte, error) {
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer rootFS.Close()
	localPath := filepath.FromSlash(path)
	if err := admitRootedRegularFile(rootFS, localPath); err != nil {
		return nil, err
	}
	file, err := rootFS.Open(localPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	// One byte past the limit lets callers distinguish an oversized file.
	return io.ReadAll(io.LimitReader(file, maxBytes+1))
}

func readRepositoryJSON(root, path string, maxBytes int64) (any, error) {
	content, err := readRepositoryFile(root, path, maxBytes)
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds the %s-byte limit", path, strconv.FormatInt(maxBytes, 10))
	}
	return admission.DecodeJSON(bytes.NewReader(content), maxBytes)
}
