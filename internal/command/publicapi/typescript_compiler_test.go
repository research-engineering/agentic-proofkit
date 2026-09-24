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
		{"export\vconst A = 1;", "", ""},
		{"const privateValue = 1;", "", ""},
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
		{"export const values: Array<string> = [];", "", ""},
		{"export const enum$ = 1;", "", ""},
		{"const x = 1; export const A = typeof\nx, B = 2;", "", ""},
		{"class X {} export const A = new\nX(), B = 2;", "", ""},
		{"export const A = void\n0, B = 2;", "", ""},
		{"const tag = (parts: TemplateStringsArray) => parts[0]; export const A = tag\n`x`, B = 2;", "", ""},
		{"export const A = \"hello\\\nthere\", B = 2;", "", ""},
		{"let B = 0, i = 0; export const A = 1\n++i, B = 2;", "", ""},
		{"export type { Shape$ }\nfrom './other';", "export type { Shape$ }", "Shape$"},
		{"export { type\nShape$ as Public } from './other';", "export { type Shape$ as Public }", "Public"},
		{"export { type as as Public } from './other';", "export { type as as Public }", "Public"},
		{"export interface as { value: number }", "export interface as", "as"},
		{"export interface satisfies { value: number }; export const A = 1;", "export interface satisfies", "satisfies"},
		{"export function f() { interface as {} }", "", ""},
		{"export function f() { type as = number; }", "", ""},
		{"const obj = { interface: { value: 1 } }; export const a = obj.interface as { value: number };", "", ""},
		{"const obj = { interface: { value: 1 } }; export const a = obj.interface satisfies { value: number };", "", ""},
		{"export class C { #interface = { value: 1 }; get() { return this.#interface as { value: number }; } }", "", ""},
		{"export class C { #interface = { value: 1 }; get() { return this.#interface satisfies { value: number }; } }", "", ""},
		{"const obj = { enum: { value: 1 } }; export const A = obj.enum as { value: number };", "", ""},
		{"const obj = { namespace: { value: 1 } }; export const A = obj.namespace satisfies { value: number };", "", ""},
		{"const namespace = { value: 1 }; export const A = namespace satisfies { value: number };", "", ""},
		{"const namespace = { value: 1 }; export const A = namespace as { value: number };", "", ""},
	} {
		folder := t.TempDir()
		sourcePath := filepath.Join(folder, "index.ts")
		if err := os.WriteFile(sourcePath, []byte(test.source), 0o600); err != nil {
			t.Fatalf("write TypeScript fixture: %v", err)
		}
		if err := os.WriteFile(filepath.Join(folder, "other.ts"), []byte("export const A = 1; export type Shape$ = { value: string }; export type T = string; export type { T as as };"), 0o600); err != nil {
			t.Fatalf("write re-export fixture: %v", err)
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

func TestCommonJSSourceIsNotAnESMExportInventory(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(repoRoot, "node_modules", ".bin", "tsc")
	if _, err := os.Stat(compiler); err != nil {
		t.Skip("locked TypeScript compiler is not installed")
	}
	folder := t.TempDir()
	for _, source := range []string{
		"declare var exports: {Public: number}; exports.Public = 1;",
		"declare var exports: {Public: number}; exports.Public = 1; export type Shape = string;",
	} {
		path := filepath.Join(folder, "entry.cts")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(compiler, "--target", "es2022", "--module", "nodenext", "--moduleResolution", "nodenext", "--outDir", folder, path)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("TypeScript compiler error=%v: %s", err, output)
		}
		command = exec.Command("node", "-e", `process.stdout.write(JSON.stringify(Object.keys(require(process.argv[1])).sort()))`, filepath.Join(folder, "entry.cjs"))
		output, err := command.CombinedOutput()
		if err != nil || string(output) != `["Public"]` {
			t.Fatalf("CommonJS export names=%s, error=%v, want Public", output, err)
		}
		if _, _, err := CollectExports(source); err == nil || !strings.Contains(err.Error(), "CommonJS binding identifiers are not admitted") {
			t.Fatalf("CollectExports() error=%v, want CommonJS rejection", err)
		}
	}
}

func TestEmptyMTSModuleHasNoRuntimeExports(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(repoRoot, "node_modules", ".bin", "tsc")
	if _, err := os.Stat(compiler); err != nil {
		t.Skip("locked TypeScript compiler is not installed")
	}
	folder := t.TempDir()
	path := filepath.Join(folder, "entry.mts")
	if err := os.WriteFile(path, []byte("const privateValue = 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(compiler, "--target", "es2022", "--module", "nodenext", "--moduleResolution", "nodenext", "--outDir", folder, path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("TypeScript compiler error=%v: %s", err, output)
	}
	command = exec.Command("node", "-e", `import(process.argv[1]).then(module => process.stdout.write(JSON.stringify(Object.keys(module).sort())))`, filepath.Join(folder, "entry.mjs"))
	output, err := command.CombinedOutput()
	if err != nil || string(output) != "[]" {
		t.Fatalf("ESM export names=%s, error=%v, want empty", output, err)
	}
	runtimeExports, typeExports, err := CollectExports("const privateValue = 1;")
	if err != nil || len(runtimeExports) != 0 || len(typeExports) != 0 {
		t.Fatalf("CollectExports() runtime=%v type=%v error=%v, want empty", runtimeExports, typeExports, err)
	}
}

func TestInvalidContextualTypeAliasMatchesCompilerRejection(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(repoRoot, "node_modules", ".bin", "tsc")
	if _, err := os.Stat(compiler); err != nil {
		t.Skip("locked TypeScript compiler is not installed")
	}
	path := filepath.Join(t.TempDir(), "entry.ts")
	if err := os.WriteFile(path, []byte("export type as = number;"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(compiler, "--noEmit", path)
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "TS1005") {
		t.Fatalf("TypeScript compiler error=%v output=%s, want syntax rejection", err, output)
	}
	if _, _, err := CollectExports("export type as = number;"); err == nil || !strings.Contains(err.Error(), "type declaration name is not admitted") {
		t.Fatalf("CollectExports() error=%v, want syntax rejection", err)
	}
}

func TestTypeAliasKeywordAdmissionDoesNotExceedCompiler(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(repoRoot, "node_modules", ".bin", "tsc")
	if _, err := os.Stat(compiler); err != nil {
		t.Skip("locked TypeScript compiler is not installed")
	}
	path := filepath.Join(t.TempDir(), "entry.ts")
	for _, name := range []string{
		"as", "from", "type", "default", "interface", "enum", "namespace", "abstract", "readonly", "satisfies", "infer", "keyof", "await", "yield",
		"break", "case", "catch", "class", "const", "continue", "debugger", "delete", "do", "else", "export", "extends", "false", "finally",
		"for", "function", "if", "import", "in", "instanceof", "new", "null", "return", "super", "switch", "this", "throw", "true", "try",
		"typeof", "var", "void", "while", "with", "implements", "private", "protected", "public", "static", "let", "package", "arguments", "eval",
		"any", "unknown", "never", "string", "number", "boolean", "undefined", "object", "symbol", "bigint", "intrinsic",
	} {
		source := "export type " + name + " = number;"
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(compiler, "--noEmit", "--pretty", "false", path)
		output, compilerErr := command.CombinedOutput()
		_, _, admissionErr := CollectExports(source)
		if compilerErr != nil && admissionErr == nil {
			t.Errorf("CollectExports(%q) accepted compiler-invalid source: %s", source, output)
		}
	}
}

func TestInterfaceKeywordAdmissionDoesNotExceedCompiler(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(repoRoot, "node_modules", ".bin", "tsc")
	if _, err := os.Stat(compiler); err != nil {
		t.Skip("locked TypeScript compiler is not installed")
	}
	path := filepath.Join(t.TempDir(), "entry.ts")
	for _, name := range []string{
		"as", "satisfies", "from", "type", "interface", "await", "yield", "implements", "private", "protected", "public", "static", "let", "package",
		"any", "unknown", "never", "string", "number", "boolean", "undefined", "object", "symbol", "bigint", "intrinsic",
	} {
		source := "export interface " + name + " { value: number }"
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(compiler, "--noEmit", "--pretty", "false", path)
		output, compilerErr := command.CombinedOutput()
		_, _, admissionErr := CollectExports(source)
		if compilerErr != nil && admissionErr == nil {
			t.Errorf("CollectExports(%q) accepted compiler-invalid source: %s", source, output)
		}
	}
}

func TestStaticInventoryAdmitsCompilerValidGenericPositions(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(repoRoot, "node_modules", ".bin", "tsc")
	if _, err := os.Stat(compiler); err != nil {
		t.Skip("locked TypeScript compiler is not installed")
	}
	for _, test := range []struct{ extension, source string }{
		{".ts", "export const id = <T>(value: T) => value;"},
		{".mts", "export const id = <T,>(value: T) => value;"},
		{".mts", "export const id = <T = Array<string>,>(value: T) => value;"},
		{".mts", "export const id: <T>(value: T) => T = value => value;"},
		{".mts", "export const fn: (<T>(x: T) => T) = x => x;"},
		{".mts", "export type Fn = <T>(value: T) => T;"},
		{".mts", "export function id<T>(value: T) { return value; }"},
		{".mts", "export type Shape = { id: <T>(value: T) => T };"},
		{".mts", "export interface Shape { <T>(value: T): T; return<U>(value: U): U }"},
		{".mts", "export class Api { return<T>(x: T) { return x; } }"},
		{".mts", "function id<T>(x: T) { return x; } export const value = id<number>(1);"},
		{".ts", "export const xs: Array<string extends string ? string : never> = [];"},
	} {
		path := filepath.Join(t.TempDir(), "entry"+test.extension)
		if err := os.WriteFile(path, []byte(test.source), 0o600); err != nil {
			t.Fatal(err)
		}
		output, compilerErr := exec.Command(compiler, "--noEmit", "--pretty", "false", "--module", "nodenext", "--moduleResolution", "nodenext", path).CombinedOutput()
		_, _, admissionErr := collectExportsWithExtension(test.source, test.extension)
		if compilerErr != nil || admissionErr != nil {
			t.Fatalf("extension=%s source=%q compilerError=%v output=%s admissionError=%v", test.extension, test.source, compilerErr, output, admissionErr)
		}
	}
}

func TestDuplicateTypeOnlyModifierMatchesCompilerRejection(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(repoRoot, "node_modules", ".bin", "tsc")
	if _, err := os.Stat(compiler); err != nil {
		t.Skip("locked TypeScript compiler is not installed")
	}
	folder := t.TempDir()
	source := `export type { type Shape as Public } from "./other";`
	if err := os.WriteFile(filepath.Join(folder, "entry.ts"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "other.ts"), []byte("export type Shape = string;"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(compiler, "--noEmit", filepath.Join(folder, "entry.ts"))
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "TS2207") {
		t.Fatalf("TypeScript compiler error=%v output=%s, want TS2207", err, output)
	}
	if _, _, err := CollectExports(source); err == nil || !strings.Contains(err.Error(), "duplicate type-only re-export modifier") {
		t.Fatalf("CollectExports() error=%v, want duplicate modifier rejection", err)
	}
}

func TestTypeOnlyReexportAttributesMatchCompiler(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(repoRoot, "node_modules", ".bin", "tsc")
	if _, err := os.Stat(compiler); err != nil {
		t.Skip("locked TypeScript compiler is not installed")
	}
	folder := t.TempDir()
	if err := os.WriteFile(filepath.Join(folder, "other.ts"), []byte("export type T = number;"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		source string
		valid  bool
	}{
		{`export type { T } from "./other.js" with { type: "json" };`, false},
		{`export type { T } from "./other.js" /*trivia*/ with { type: "json" };`, false},
		{`export type { T } from "./other.js" assert { type: "json" };`, false},
		{"export type { T } from \"./other.js\"\nwith { \"resolution-mode\": \"import\" };", false},
		{"export type { T } from \"./other.js\" /*\n*/ with { \"resolution-mode\": \"import\" };", false},
		{"export type { T } from \"./other.js\" // comment\u2028with { type: \"json\" };", false},
		{`export type { T } from "./other.js" with { "resolution-mode": "import" };`, true},
		{`export type { T } from "./other.js" /*trivia*/ with { /*a*/ "resolution-mode" /*b*/ : /*c*/ "import" /*d*/ };`, true},
		{`export type { T } from "./other.js" with { "resolution-mode": "import", };`, true},
		{`export { type T } from "./other.js" with { "resolution-mode": "import" };`, false},
	} {
		path := filepath.Join(folder, "entry.ts")
		if err := os.WriteFile(path, []byte(test.source), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(compiler, "--noEmit", "--module", "nodenext", "--moduleResolution", "nodenext", path)
		output, compilerErr := command.CombinedOutput()
		_, _, admissionErr := CollectExports(test.source)
		if (compilerErr == nil) != test.valid || (admissionErr == nil) != test.valid {
			t.Fatalf("source=%q compilerError=%v output=%s admissionError=%v, valid=%t", test.source, compilerErr, output, admissionErr, test.valid)
		}
	}
}

func TestConfusingTypeScriptCastMatchesCompilerRejection(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(repoRoot, "node_modules", ".bin", "tsc")
	if _, err := os.Stat(compiler); err != nil {
		t.Skip("locked TypeScript compiler is not installed")
	}
	for _, test := range []struct {
		source string
		valid  bool
	}{
		{`export const A: Array<number> = [1 + 2 as number * 3];`, false},
		{`export const A: Array<number> = [(1 + 2 as number) * 3];`, true},
	} {
		path := filepath.Join(t.TempDir(), "entry.ts")
		if err := os.WriteFile(path, []byte(test.source), 0o600); err != nil {
			t.Fatal(err)
		}
		output, compilerErr := exec.Command(compiler, "--noEmit", "--pretty", "false", path).CombinedOutput()
		_, _, admissionErr := CollectExports(test.source)
		if (compilerErr == nil) != test.valid || (admissionErr == nil) != test.valid {
			t.Fatalf("source=%q compilerError=%v output=%s admissionError=%v valid=%t", test.source, compilerErr, output, admissionErr, test.valid)
		}
	}
}
