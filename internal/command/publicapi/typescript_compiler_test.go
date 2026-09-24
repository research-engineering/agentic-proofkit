package publicapi

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectExportsMatchesTypeScriptCompiler(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	compiler := filepath.Join(repoRoot, "node_modules", ".bin", "tsc")
	if _, err := os.Stat(compiler); err != nil {
		t.Skip("locked TypeScript compiler is not installed")
	}
	for _, test := range []struct {
		source          string
		typeDeclaration string
		typeName        string
	}{
		{"export const A = 1\nconst B = 2, C = 3;\nexport function public$() { return 1; }\nexport type Shape$ = { value: string };", "export type Shape$", "Shape$"},
		{"export const A = 1,\n B = 2;\nexport interface public$ { value: number }", "export interface public$", "public$"},
		{"export const A = true &&\nfunction () {}, B = 2;", "", ""},
		{"export const A = `x`\nconst B = 2, C = 3;", "", ""},
		{"let i = 0; export const A = i++\nconst B = 2, C = 3;", "", ""},
		{"let x = 1; export const A = x!\nconst B = 2, C = 3;", "", ""},
		{"const async = 2;\nexport const A = 1 |\nasync, B = 2;", "", ""},
		{"export const A = 1/*\r*/const B = 2, C = 3;", "", ""},
		{"export const A = 1 // comment\u2028const B = 2, C = 3;", "", ""},
		{"let C = 0;\nexport const A = 1\nC = 2, C = 3;", "", ""},
		{"export function\nasync() { return 1; }", "", ""},
		{"export const\nasync = 1;", "", ""},
	} {
		folder := t.TempDir()
		sourcePath := filepath.Join(folder, "index.ts")
		if err := os.WriteFile(sourcePath, []byte(test.source), 0o600); err != nil {
			t.Fatalf("write TypeScript fixture: %v", err)
		}
		command := exec.Command(compiler, "--target", "es2022", "--module", "commonjs", "--declaration", "--outDir", folder, sourcePath)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("TypeScript compiler error=%v: %s", err, output)
		}
		declaration, err := os.ReadFile(filepath.Join(folder, "index.d.ts"))
		if err != nil {
			t.Fatalf("read compiler declaration: %v", err)
		}
		if test.typeDeclaration != "" && !strings.Contains(string(declaration), test.typeDeclaration) {
			t.Fatalf("compiler declaration %q does not contain %q", declaration, test.typeDeclaration)
		}
		command = exec.Command("node", "-e", `process.stdout.write(JSON.stringify(Object.keys(require(process.argv[1])).sort()))`, filepath.Join(folder, "index.js"))
		output, err = command.CombinedOutput()
		if err != nil {
			t.Fatalf("compiled JavaScript import error=%v: %s", err, output)
		}
		var compiledExports []string
		if err := json.Unmarshal(output, &compiledExports); err != nil {
			t.Fatalf("decode compiled module exports: %v", err)
		}
		runtimeExports, typeExports, err := CollectExports(test.source)
		if err != nil {
			t.Fatalf("CollectExports() error=%v", err)
		}
		assertStringSlice(t, runtimeExports, compiledExports)
		if test.typeName == "" && len(typeExports) != 0 || test.typeName != "" && (len(typeExports) != 1 || typeExports[0] != test.typeName) {
			t.Fatalf("CollectExports() type exports=%v, compiler declaration=%q", typeExports, declaration)
		}
	}
}
