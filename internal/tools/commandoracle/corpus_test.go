package commandoracle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCounterfeitCorpusClosesRequiredAxes(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ValidateCounterfeitCorpus(root)
	if err != nil {
		t.Fatalf("ValidateCounterfeitCorpus() error = %v", err)
	}
	if !isSHA256(digest) {
		t.Fatalf("ValidateCounterfeitCorpus() digest = %q, want SHA-256", digest)
	}
}

func TestEachCounterfeitCaseProducesItsCheckedInDecision(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(CounterfeitCorpusPath)))
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := admitCorpus(content)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range corpus.Cases {
		t.Run(item.CaseID, func(t *testing.T) {
			if got := evaluateCounterfeit(item); got != item.ExpectedDecision {
				t.Fatalf("evaluateCounterfeit() = %q, want checked-in %q", got, item.ExpectedDecision)
			}
		})
	}
}

func TestCounterfeitCorpusClosureRejectsMissingRequiredAxes(t *testing.T) {
	corpus := readCounterfeitCorpusFixture(t)
	for index, item := range corpus.Cases {
		if item.MutationID == "record-execution-command-drift" {
			corpus.Cases = append(corpus.Cases[:index], corpus.Cases[index+1:]...)
			break
		}
	}
	if err := validateCounterfeitCorpusClosure(corpus); DecisionID(err) != "corpus.policy_axis_missing" {
		t.Fatalf("validateCounterfeitCorpusClosure() error = %v", err)
	}
}

func readCounterfeitCorpusFixture(t *testing.T) counterfeitCorpus {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(CounterfeitCorpusPath)))
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := admitCorpus(content)
	if err != nil {
		t.Fatal(err)
	}
	return corpus
}
