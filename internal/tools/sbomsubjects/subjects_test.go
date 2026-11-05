package sbomsubjects_test

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/tools/sbomsubjects"
)

const subjectPath = "artifacts/package/proofkit.tgz"
const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const file = `{"type":"application","bom-ref":"file:artifacts/package/proofkit.tgz","name":"proofkit.tgz","version":"1.2.3",
	"properties":[{"name":"proofkit:path","value":"artifacts/package/proofkit.tgz"}],
	"hashes":[{"alg":"SHA-256","content":"` + digest + `"}]}`
const module = `{"type":"library","bom-ref":"go-module:example.test/module@v2.0.0","name":"example.test/module",
	"version":"v2.0.0","scope":"excluded","properties":[{"name":"proofkit:evidence-class","value":"source_build_inventory"}]}`

func TestAdmitChecksOnlyFileSubjectProjection(t *testing.T) {
	document := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[` + module + `,` + file + `],
		"metadata":{"component":{"type":"application","bom-ref":"pkg:generic/proofkit@1.2.3"}},
		"dependencies":[{"ref":"go-module:example.test/module@v2.0.0"}]}`
	if err := sbomsubjects.Admit([]byte(document), map[string]string{subjectPath: digest}, "1.2.3"); err != nil {
		t.Fatal(err)
	}
}

func TestAdmitRejectsAmbiguousOrUnboundFileClaims(t *testing.T) {
	const prefix = `{"bomFormat":"CycloneDX","specVersion":"1.6",`
	withComponents := func(components string) string { return prefix + `"components":[` + components + `]}` }
	for _, test := range []struct {
		name, content, diagnostic string
	}{
		{"empty document", `{}`, "CycloneDX format and version"},
		{"non-file only", withComponents(module), "missing file subject"},
		{"duplicate property", withComponents(strings.Replace(file, `"properties":[`, `"properties":[{"name":"proofkit:path","value":"artifacts/package/proofkit.tgz"},`, 1)), "incorrect path"},
		{"duplicate hash", withComponents(strings.Replace(file, `"hashes":[`, `"hashes":[{"alg":"SHA-256","content":"`+digest+`"},`, 1)), "expected SHA-256"},
		{"wrong hash algorithm", withComponents(strings.Replace(file, "SHA-256", "SHA-512", 1)), "expected SHA-256"},
		{"uppercase digest", withComponents(strings.Replace(file, digest, strings.ToUpper(digest), 1)), "expected SHA-256"},
		{"wrong version", withComponents(strings.Replace(file, "1.2.3", "1.2.2", 1)), "incorrect path"},
		{"wrong type", withComponents(strings.Replace(file, "application", "library", 1)), "incorrect path"},
		{"noncanonical ref", withComponents(strings.Replace(file, "file:artifacts", "file:./artifacts", 1)), "unexpected file subject"},
		{"type-only file claim", withComponents(file + `,{"type":"file"}`), "unexpected file subject"},
		{"path-only file claim", withComponents(file + `,{"type":"application","properties":[{"name":"proofkit:path","value":"extra"}]}`), "unexpected file subject"},
		{"nested file claim", withComponents(file + `,{"type":"library","components":[` + file + `]}`), "top-level components"},
		{"metadata file claim", prefix + `"components":[` + file + `],"metadata":{"component":` + file + `}}`, "top-level components"},
		{"duplicate JSON key", withComponents(strings.Replace(file, `"name":"proofkit.tgz"`, `"name":"other","name":"proofkit.tgz"`, 1)), "duplicate object key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := sbomsubjects.Admit([]byte(test.content), map[string]string{subjectPath: digest}, "1.2.3")
			if err == nil || !strings.Contains(err.Error(), test.diagnostic) {
				t.Fatalf("expected %q, got %v", test.diagnostic, err)
			}
		})
	}
}
