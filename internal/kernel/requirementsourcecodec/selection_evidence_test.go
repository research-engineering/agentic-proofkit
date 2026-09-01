package requirementsourcecodec

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

const (
	maxScreenArchiveBytes      = 8 << 20
	maxScreenFileBytes         = 4 << 20
	maxScreenFileCount         = 512
	maxScreenUncompressedBytes = 16 << 20
)

type boundFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type screenManifestEvidence struct {
	SchemaVersion    int         `json:"schemaVersion"`
	Kind             string      `json:"kind"`
	FixtureGenerator boundFile   `json:"fixtureGenerator"`
	Renderer         boundFile   `json:"renderer"`
	SelectionOpener  boundFile   `json:"selectionOpener"`
	MethodBindings   []boundFile `json:"methodBindings"`
	Review           struct {
		Assignment boundFile `json:"assignment"`
	} `json:"review"`
}

type fixtureIndexEvidence struct {
	SchemaVersion int    `json:"schemaVersion"`
	Kind          string `json:"kind"`
	Fixtures      []struct {
		Path           string `json:"path"`
		SemanticSHA256 string `json:"semanticSha256"`
	} `json:"fixtures"`
	Edits []struct {
		BeforePath   string `json:"beforePath"`
		BeforeSHA256 string `json:"beforeSha256"`
		AfterPath    string `json:"afterPath"`
		AfterSHA256  string `json:"afterSha256"`
	} `json:"edits"`
}

type tokenReportEvidence struct {
	Implementation string `json:"implementation"`
	Records        []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Tokens int    `json:"tokens"`
	} `json:"records"`
}

type screenDecisionEvidence struct {
	SchemaVersion       int               `json:"schemaVersion"`
	Kind                string            `json:"kind"`
	ManifestSHA256      string            `json:"manifestSha256"`
	ObservationSHA256   string            `json:"observationSha256"`
	OpeningSHA256       string            `json:"openingSha256"`
	ReviewResultsSHA256 string            `json:"reviewResultsSha256"`
	TokenReportSHA256   map[string]string `json:"tokenReportSha256"`
	ValidationSHA256    string            `json:"validationSha256"`
	State               string            `json:"state"`
	SelectedJSONLayout  string            `json:"selectedJsonLayout"`
	SelectedChallenger  *string           `json:"selectedChallenger"`
	Candidates          []struct {
		CandidateID             string `json:"candidateId"`
		WeightedCanonicalBytes  int    `json:"weightedCanonicalBytes"`
		WeightedTokensO200kBase int    `json:"weightedTokensO200kBase"`
		ChangedLines            int    `json:"changedLines"`
		ChangedBytes            int    `json:"changedBytes"`
		EditLocality            bool   `json:"editLocality"`
		JSONFieldClosure        string `json:"jsonFieldClosure"`
		Review                  *struct {
			AccuracyBasisPoints         int `json:"accuracyBasisPoints"`
			InvalidMutationFalseAccepts int `json:"invalidMutationFalseAccepts"`
		} `json:"review"`
		ProjectedProduction struct {
			LOC      int `json:"loc"`
			Branches int `json:"branches"`
		} `json:"projectedProduction"`
	} `json:"candidates"`
}

func TestSelectionEvidenceIsByteBoundAndProjectsDecision(t *testing.T) {
	record := readCodecSelection(t)
	root := readScreenArchive(t, record.ScreenEvidence)
	if err := verifyScreenTree(root, record.ScreenEvidence.ArtifactCount, record.ScreenEvidence.TreeSHA256); err != nil {
		t.Fatal(err)
	}
	artifacts := verifyScreenArtifacts(t, root, record.ScreenEvidence.Artifacts)
	manifest := readEvidence[screenManifestEvidence](t, root, artifacts["screen-manifest"].Path)
	if manifest.SchemaVersion != 3 || manifest.Kind != "proofkit.requirement-source-codec-formatter-screen" {
		t.Fatalf("screen manifest identity = %#v", manifest)
	}
	bound := []boundFile{manifest.FixtureGenerator, manifest.Renderer, manifest.SelectionOpener, manifest.Review.Assignment}
	bound = append(bound, manifest.MethodBindings...)
	for _, file := range bound {
		assertBoundFile(t, root, file)
	}

	fixtureIndex := readEvidence[fixtureIndexEvidence](t, root, artifacts["fixture-index"].Path)
	if fixtureIndex.SchemaVersion != 1 || fixtureIndex.Kind != "proofkit.requirement-source-codec-selection-fixtures" {
		t.Fatalf("fixture index identity = %#v", fixtureIndex)
	}
	for _, fixture := range fixtureIndex.Fixtures {
		assertBoundFile(t, root, boundFile{Path: path.Join("out-v3", fixture.Path), SHA256: fixture.SemanticSHA256})
	}
	for _, edit := range fixtureIndex.Edits {
		assertBoundFile(t, root, boundFile{Path: path.Join("out-v3", edit.BeforePath), SHA256: edit.BeforeSHA256})
		assertBoundFile(t, root, boundFile{Path: path.Join("out-v3", edit.AfterPath), SHA256: edit.AfterSHA256})
	}

	pythonTokens := readEvidence[tokenReportEvidence](t, root, artifacts["token-python"].Path)
	goTokens := readEvidence[tokenReportEvidence](t, root, artifacts["token-go"].Path)
	if pythonTokens.Implementation != "openai-tiktoken-0.14.0" || goTokens.Implementation != "tiktoken-go-0.8.1" || !reflect.DeepEqual(pythonTokens.Records, goTokens.Records) {
		t.Fatal("independent token reports are not exactly equal")
	}
	for _, token := range pythonTokens.Records {
		assertBoundFile(t, root, boundFile{Path: path.Join("out-v3", "rendered", token.Path), SHA256: token.SHA256})
		if token.Tokens <= 0 {
			t.Fatalf("nonpositive token count for %q", token.Path)
		}
	}

	decision := readEvidence[screenDecisionEvidence](t, root, artifacts["screen-decision"].Path)
	assertDecisionLinks(t, decision, artifacts)
	assertDecisionProjection(t, record, decision)
}

func TestScreenTreeDigestRejectsByteAndInventoryMutation(t *testing.T) {
	original := fstest.MapFS{"a": {Data: []byte("alpha")}, "nested/b": {Data: []byte("beta")}}
	digest, count, err := screenTreeDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyScreenTree(original, count, digest); err != nil {
		t.Fatal(err)
	}
	mutated := fstest.MapFS{"a": {Data: []byte("changed")}, "nested/b": {Data: []byte("beta")}}
	if err := verifyScreenTree(mutated, count, digest); err == nil {
		t.Fatal("screen evidence byte mutation retained the original identity")
	}
	deleted := fstest.MapFS{"a": {Data: []byte("alpha")}}
	if err := verifyScreenTree(deleted, count, digest); err == nil {
		t.Fatal("screen evidence inventory mutation retained the original identity")
	}
}

func TestScreenArchiveAdmissionRejectsUnsafeTopology(t *testing.T) {
	tests := []struct {
		name    string
		entries []tar.Header
		want    string
	}{
		{name: "traversal", entries: []tar.Header{{Name: "../escape", Mode: 0o444, Size: 1, Typeflag: tar.TypeReg}}, want: "unsafe screen archive entry"},
		{name: "symlink", entries: []tar.Header{{Name: "link", Linkname: "../escape", Mode: 0o777, Typeflag: tar.TypeSymlink}}, want: "unsupported screen archive entry type"},
		{name: "duplicate", entries: []tar.Header{{Name: "entry", Mode: 0o444, Size: 1, Typeflag: tar.TypeReg}, {Name: "entry", Mode: 0o444, Size: 1, Typeflag: tar.TypeReg}}, want: "duplicate screen archive entry"},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			_, err := decodeScreenArchive(screenArchiveFixture(t, item.entries))
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("decodeScreenArchive() error = %v, want %q", err, item.want)
			}
		})
	}
}

func verifyScreenArtifacts(t *testing.T, root fs.FS, values []screenArtifact) map[string]screenArtifact {
	t.Helper()
	result := make(map[string]screenArtifact, len(values))
	for _, artifact := range values {
		assertBoundFile(t, root, boundFile{Path: artifact.Path, SHA256: artifact.SHA256})
		if _, duplicate := result[artifact.Role]; duplicate {
			t.Fatalf("duplicate screen artifact role %q", artifact.Role)
		}
		result[artifact.Role] = artifact
	}
	return result
}

func assertDecisionLinks(t *testing.T, value screenDecisionEvidence, artifacts map[string]screenArtifact) {
	t.Helper()
	if value.SchemaVersion != 3 || value.Kind != "proofkit.requirement-source-codec-screen-decision" {
		t.Fatalf("screen decision identity = %#v", value)
	}
	want := map[string]string{
		"screen-manifest":        value.ManifestSHA256,
		"observations":           value.ObservationSHA256,
		"selection-opening":      value.OpeningSHA256,
		"review-results":         value.ReviewResultsSHA256,
		"independent-validation": value.ValidationSHA256,
		"token-python":           value.TokenReportSHA256["openai-tiktoken-0.14.0"],
		"token-go":               value.TokenReportSHA256["tiktoken-go-0.8.1"],
	}
	for role, digest := range want {
		if artifacts[role].SHA256 != digest {
			t.Fatalf("decision link %q = %q, want %q", role, digest, artifacts[role].SHA256)
		}
	}
}

func assertDecisionProjection(t *testing.T, record codecSelection, decision screenDecisionEvidence) {
	t.Helper()
	if decision.State != record.Decision.State || decision.SelectedJSONLayout != record.Decision.SelectedJSONLayout || !reflect.DeepEqual(decision.SelectedChallenger, record.Decision.SelectedChallenger) {
		t.Fatalf("screen decision projection mismatch: %#v", decision)
	}
	byID := make(map[string]screenObservation, len(record.ScreenObservations))
	for _, item := range record.ScreenObservations {
		byID[item.CandidateID] = item
	}
	seen := make(map[string]struct{}, len(decision.Candidates))
	for _, candidate := range decision.Candidates {
		if _, duplicate := seen[candidate.CandidateID]; duplicate {
			t.Fatalf("decision repeats candidate %q", candidate.CandidateID)
		}
		seen[candidate.CandidateID] = struct{}{}
		observation, exists := byID[candidate.CandidateID]
		if !exists {
			t.Fatalf("decision contains unknown candidate %q", candidate.CandidateID)
		}
		if observation.WeightedCanonicalBytes != candidate.WeightedCanonicalBytes || observation.WeightedTokensO200kBase != candidate.WeightedTokensO200kBase ||
			observation.ChangedLines != candidate.ChangedLines || observation.ChangedBytes != candidate.ChangedBytes || observation.EditLocality != candidate.EditLocality ||
			observation.ProjectedProductionLOC != candidate.ProjectedProduction.LOC || observation.ProjectedProductionBranches != candidate.ProjectedProduction.Branches {
			t.Fatalf("candidate %q observation drift", candidate.CandidateID)
		}
		if candidate.JSONFieldClosure != "" && observation.FieldClosure != candidate.JSONFieldClosure {
			t.Fatalf("candidate %q field closure drift", candidate.CandidateID)
		}
		if candidate.Review != nil && (observation.ReviewAccuracyBasisPoints == nil || observation.InvalidMutationFalseAccepts == nil ||
			*observation.ReviewAccuracyBasisPoints != candidate.Review.AccuracyBasisPoints || *observation.InvalidMutationFalseAccepts != candidate.Review.InvalidMutationFalseAccepts) {
			t.Fatalf("candidate %q review projection drift", candidate.CandidateID)
		}
		if candidate.Review == nil && (observation.ReviewAccuracyBasisPoints != nil || observation.InvalidMutationFalseAccepts != nil) {
			t.Fatalf("candidate %q unexpected review projection", candidate.CandidateID)
		}
	}
	if len(decision.Candidates) != len(record.ScreenObservations) {
		t.Fatalf("decision candidate count = %d, want %d", len(decision.Candidates), len(record.ScreenObservations))
	}
}

func assertBoundFile(t *testing.T, root fs.FS, value boundFile) {
	t.Helper()
	if value.Path == "" || path.IsAbs(value.Path) || path.Clean(value.Path) != value.Path || value.Path == ".." || len(value.Path) > 3 && value.Path[:3] == "../" {
		t.Fatalf("unsafe bound evidence path %q", value.Path)
	}
	payload, err := fs.ReadFile(root, value.Path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != value.SHA256 {
		t.Fatalf("evidence digest mismatch for %q", value.Path)
	}
}

func readEvidence[T any](t *testing.T, root fs.FS, filePath string) T {
	t.Helper()
	payload, err := fs.ReadFile(root, filePath)
	if err != nil {
		t.Fatal(err)
	}
	var result T
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func readScreenArchive(t *testing.T, evidence screenEvidence) fstest.MapFS {
	t.Helper()
	payload, err := os.ReadFile(evidence.ArchivePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > maxScreenArchiveBytes {
		t.Fatalf("screen archive bytes = %d, limit = %d", len(payload), maxScreenArchiveBytes)
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != evidence.ArchiveSHA256 {
		t.Fatal("screen archive digest mismatch")
	}
	result, err := decodeScreenArchive(payload)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func decodeScreenArchive(payload []byte) (fstest.MapFS, error) {
	compressed, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	compressed.Multistream(false)
	defer compressed.Close()

	result := fstest.MapFS{}
	totalBytes := int64(0)
	archive := tar.NewReader(compressed)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		clean := path.Clean(header.Name)
		if header.Name == "" || clean != header.Name || clean == "." || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
			return nil, fmt.Errorf("unsafe screen archive entry %q", header.Name)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("unsupported screen archive entry type %d for %q", header.Typeflag, header.Name)
		}
		if header.Size < 0 || header.Size > maxScreenFileBytes {
			return nil, fmt.Errorf("screen archive entry %q size = %d", header.Name, header.Size)
		}
		if _, duplicate := result[clean]; duplicate {
			return nil, fmt.Errorf("duplicate screen archive entry %q", clean)
		}
		if len(result) >= maxScreenFileCount || totalBytes+header.Size > maxScreenUncompressedBytes {
			return nil, fmt.Errorf("screen archive exceeds admitted expansion limits")
		}
		content, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
		if err != nil {
			return nil, err
		}
		if int64(len(content)) != header.Size {
			return nil, fmt.Errorf("screen archive entry %q size mismatch", header.Name)
		}
		totalBytes += header.Size
		result[clean] = &fstest.MapFile{Data: content, Mode: 0o444}
	}
	return result, nil
}

func screenArchiveFixture(t *testing.T, headers []tar.Header) []byte {
	t.Helper()
	var result bytes.Buffer
	compressed := gzip.NewWriter(&result)
	archive := tar.NewWriter(compressed)
	for index := range headers {
		header := headers[index]
		if err := archive.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := archive.Write(bytes.Repeat([]byte{'x'}, int(header.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}

func verifyScreenTree(root fs.FS, expectedCount int, expectedDigest string) error {
	digest, count, err := screenTreeDigest(root)
	if err != nil {
		return err
	}
	if count != expectedCount || digest != expectedDigest {
		return fmt.Errorf("screen evidence tree identity mismatch: got count=%d digest=%s, want count=%d digest=%s", count, digest, expectedCount, expectedDigest)
	}
	return nil
}

func screenTreeDigest(root fs.FS) (string, int, error) {
	paths := []string{}
	if err := fs.WalkDir(root, ".", func(filePath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			paths = append(paths, filePath)
		}
		return nil
	}); err != nil {
		return "", 0, err
	}
	sort.Strings(paths)
	tree := sha256.New()
	for _, filePath := range paths {
		payload, err := fs.ReadFile(root, filePath)
		if err != nil {
			return "", 0, err
		}
		fileDigest := sha256.Sum256(payload)
		tree.Write([]byte(filePath))
		tree.Write([]byte{0})
		tree.Write([]byte(hex.EncodeToString(fileDigest[:])))
		tree.Write([]byte{'\n'})
	}
	return hex.EncodeToString(tree.Sum(nil)), len(paths), nil
}

func TestScreenTreeDigestAlgorithmMatchesDeclaredBytes(t *testing.T) {
	record := readCodecSelection(t)
	if !bytes.Equal([]byte(record.ScreenEvidence.TreeDigestAlgorithm), []byte("sha256(sorted(relative-path NUL file-sha256 LF))")) {
		t.Fatal("screen tree digest algorithm drift")
	}
}
