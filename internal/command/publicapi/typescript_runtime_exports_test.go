package publicapi

import (
	"fmt"
	"strings"
	"testing"
)

func TestRuntimeExportInventoryDoesNotAmplifyNestedWhitespace(t *testing.T) {
	const depth = 2000
	source := "export const A = " + strings.Repeat("[\n", depth) + "0" + strings.Repeat("\n]", depth) + ";"
	result := buildRuntimeExportInventory(source, ".ts")
	if len(result.Errors) != 0 || len(result.OutputFiles) != 1 {
		t.Fatalf("buildRuntimeExportInventory() errors=%v outputs=%d", result.Errors, len(result.OutputFiles))
	}
	if got := len(result.OutputFiles[0].Contents); got > 2*len(source) {
		t.Fatalf("generated JS length=%d exceeds twice source length=%d", got, len(source))
	}
	names, err := collectRuntimeExports(source, ".ts")
	if err != nil || len(names) != 1 || names[0] != "A" {
		t.Fatalf("collectRuntimeExports() names=%v error=%v", names, err)
	}
}

func TestExpandingDeclarationsFailBeforeRuntimeBuild(t *testing.T) {
	var source strings.Builder
	source.WriteString(`export enum E { A0 = "x"`)
	for index := 1; index <= 22; index++ {
		previous := index - 1
		fmt.Fprintf(&source, ", A%d = A%d + A%d", index, previous, previous)
	}
	source.WriteString(" }")
	if _, _, err := CollectExports(source.String()); err == nil || !strings.Contains(err.Error(), "enum declarations are not admitted") {
		t.Fatalf("CollectExports(computed enum) error=%v, want pre-build refusal", err)
	}
	var qualifiedNamespace strings.Builder
	qualifiedNamespace.WriteString("namespace Root." + strings.Repeat("N", 4096) + " {")
	for index := 0; index < 1024; index++ {
		fmt.Fprintf(&qualifiedNamespace, "export const v%d=1;", index)
	}
	qualifiedNamespace.WriteString("} export const api=Root;")
	for _, rejected := range []string{
		`export enum E { A, B, C }`,
		`export enum E { A = "x", B = "y" }`,
		`export enum E { A = 1, B = -2, C = 0x10 }`,
		`const enum E { A = 1 }; export const A = E.A;`,
		`export enum E { A = "` + strings.Repeat("x", 4096) + `" }; export const xs = [` + strings.Repeat("E.A,", 4096) + `];`,
		`namespace VeryLongName { export const A = 1; } export const id = VeryLongName.A;`,
		`namespace VeryLongName.Inner { export const A = 1; } export const id = VeryLongName.Inner.A;`,
		"const x = 1\nnamespace N { export const y = 1 } export const id = N.y;",
		qualifiedNamespace.String(),
	} {
		if _, _, err := CollectExports(rejected); err == nil || !strings.Contains(err.Error(), "declarations are not admitted") {
			t.Fatalf("CollectExports(expanding declaration) error=%v, want pre-build refusal", err)
		}
	}
	if runtime, _, err := CollectExports(`export const record = { enum: 1 };`); err != nil || len(runtime) != 1 || runtime[0] != "record" {
		t.Fatalf("CollectExports(object property) runtime=%v error=%v, want passed", runtime, err)
	}
	if runtime, _, err := CollectExports(`export class C { enum() { return 1; } }`); err != nil || len(runtime) != 1 || runtime[0] != "C" {
		t.Fatalf("CollectExports(class method) runtime=%v error=%v, want passed", runtime, err)
	}
	if runtime, _, err := CollectExports(`export const record = { namespace: 1 };`); err != nil || len(runtime) != 1 || runtime[0] != "record" {
		t.Fatalf("CollectExports(namespace property) runtime=%v error=%v, want passed", runtime, err)
	}
}

func TestStringFoldEstimateRejectsLongLiteralChainBeforeRuntimeBuild(t *testing.T) {
	source := "export const A = " + strings.Repeat("'xxxxxxxxxxxxxxxx'+", 8192) + "'';"
	if _, _, err := CollectExports(source); err == nil || !strings.Contains(err.Error(), "string-fold work estimate") {
		t.Fatalf("CollectExports(long literal chain) error=%v, want pre-build refusal", err)
	}
	for _, admitted := range []string{
		`export const A = 'x' + 'y';`,
		`export const A = '+'; // +++`,
	} {
		runtime, _, err := CollectExports(admitted)
		if err != nil || len(runtime) != 1 || runtime[0] != "A" {
			t.Fatalf("CollectExports(%q) runtime=%v error=%v, want static inventory", admitted, runtime, err)
		}
	}
	scan, err := scanTypeScriptSource("export const A = '+'; // +++")
	if err != nil || scan.plusTokens != 0 || scan.literalBytes != 3 {
		t.Fatalf("scanTypeScriptSource() plusTokens=%d literalBytes=%d error=%v, want only quoted literal bytes", scan.plusTokens, scan.literalBytes, err)
	}
}
