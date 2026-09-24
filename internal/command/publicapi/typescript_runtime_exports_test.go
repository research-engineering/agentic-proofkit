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
	for _, rejected := range []string{
		`export enum E { A, B, C }`,
		`export enum E { A = "x", B = "y" }`,
		`export enum E { A = 1, B = -2, C = 0x10 }`,
		`const enum E { A = 1 }; export const A = E.A;`,
		`export enum E { A = "` + strings.Repeat("x", 4096) + `" }; export const xs = [` + strings.Repeat("E.A,", 4096) + `];`,
		`namespace VeryLongName { export const A = 1; } export const id = VeryLongName.A;`,
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
