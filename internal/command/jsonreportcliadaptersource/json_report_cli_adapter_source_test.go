package jsonreportcliadaptersource

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

const expectedTypeScriptSourceSha256 = "sha256:2b2d3c84676dc513f521722a9abf8fea4b2cc942aa11fc03a9ceeeece780d812"

func TestBuildEmitsDeterministicTypeScriptSourceBundle(t *testing.T) {
	if !slices.IsSorted(exportedSymbols) {
		t.Fatalf("exported symbols must be sorted: %v", exportedSymbols)
	}
	for index := 1; index < len(exportedSymbols); index++ {
		if exportedSymbols[index] == exportedSymbols[index-1] {
			t.Fatalf("exported symbols must be unique: %v", exportedSymbols)
		}
	}
	first, err := Build(LanguageTypeScript, FormatJSON)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	second, err := Build(LanguageTypeScript, "")
	if err != nil {
		t.Fatalf("Build(default format) error = %v", err)
	}
	if first["source"] != second["source"] || first["sourceSha256"] != second["sourceSha256"] {
		t.Fatalf("source bundle is not deterministic")
	}
	source, ok := first["source"].(string)
	if !ok || source == "" {
		t.Fatalf("source must be a non-empty string: %#v", first["source"])
	}
	if actual := exportedDeclarations(source); !slices.Equal(actual, exportedSymbols) {
		t.Fatalf("exportedSymbols mismatch\nactual:  %v\nlisted: %v", actual, exportedSymbols)
	}
	if first["sourceSha256"] != digest.SHA256TextRef(source) {
		t.Fatalf("source hash mismatch: %v", first["sourceSha256"])
	}
	if first["sourceSha256"] != expectedTypeScriptSourceSha256 {
		t.Fatalf("source hash=%v, want owner-approved ABI hash %s", first["sourceSha256"], expectedTypeScriptSourceSha256)
	}
	for _, symbol := range exportedSymbols {
		if !strings.Contains(source, symbol) {
			t.Fatalf("generated source missing exported symbol %s", symbol)
		}
	}
}

func TestBuildRejectsUnsupportedLanguageAndFormat(t *testing.T) {
	if _, err := Build("javascript", FormatJSON); err == nil || !strings.Contains(err.Error(), "typescript") {
		t.Fatalf("Build accepted unsupported language: %v", err)
	}
	if _, err := Build(LanguageTypeScript, "markdown"); err == nil || !strings.Contains(err.Error(), "json") {
		t.Fatalf("Build accepted unsupported format: %v", err)
	}
}

func TestGeneratedSourcePreservesConsumerOwnedPackageResolution(t *testing.T) {
	source := TypeScriptSource()
	for _, forbidden := range []string{
		"node_modules",
		"package.json",
		"dist/agentic-proofkit",
		"import.meta.url",
		"process.cwd()",
		"existsSync",
		"readdir",
		"glob",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("generated source contains consumer-owned package resolution or scanning token %q", forbidden)
		}
	}
	for _, required := range []string{
		"readonly binaryPath: string;",
		"readonly cwd: string;",
		"spawnSync(options.binaryPath",
		"cwd: options.cwd",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("generated source missing explicit caller-owned runtime option %q", required)
		}
	}
}

func TestGeneratedSourceUsesHardBoundedInputReads(t *testing.T) {
	source := TypeScriptSource()
	for _, forbidden := range []string{
		"readFileSync",
		" statSync",
		"statSync(filePath)",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("generated source contains non-hard-bounded read token %q", forbidden)
		}
	}
	for _, required := range []string{
		"openSync(filePath, \"r\")",
		"fstatSync(fd)",
		"readSync(fd, chunk",
		"closeSync(fd)",
		"maxInputBytes + 1",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("generated source missing hard bounded read token %q", required)
		}
	}
}

func TestGeneratedSourcePreservesCLIExitCodeAsPublicContract(t *testing.T) {
	source := TypeScriptSource()
	for _, required := range []string{
		"export interface ProofkitProcessResult",
		"readonly status: number | null;",
		"readonly stdout: string;",
		"readonly stderr: string;",
		"export type ProofkitJsonCommandResult",
		"status: child.status",
		"stdout: child.stdout",
		"stderr: child.stderr",
		"value: parseProofkitJsonStrict(jsonText)",
		"const outputPath = outputPathFromArgs(command, args)",
		"function outputPathFromArgs(command: string, args: readonly string[])",
		"command !== \"requirement-spec-tree-view\"",
		"function resolveOutputPath",
		"if (child.status !== 0 && child.stdout.trim().length === 0) {",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("generated source does not preserve CLI process contract token %q", required)
		}
	}
}

func TestGeneratedSourceAvoidsGenericIndexedAssignmentDrift(t *testing.T) {
	source := TypeScriptSource()
	for _, forbidden := range []string{
		"Partial<Record<Key, string | null>>",
		"parsed: Partial<Record<Key",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("generated source contains consumer-unsafe generic indexed assignment token %q", forbidden)
		}
	}
	for _, required := range []string{
		"const parsed: Record<string, string | null> = { outputPath: null };",
		"return parsed as ProofkitJsonReportCliOptions<Key>;",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("generated source missing consumer typechecker guard token %q", required)
		}
	}
}

func TestGeneratedTypeScriptAdapterExecutesCoreSemantics(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is required to prove generated TypeScript semantics: %v", err)
	}
	tempDir := t.TempDir()
	adapterPath := filepath.Join(tempDir, "proofkit-json-report-cli-adapter.ts")
	harnessPath := filepath.Join(tempDir, "harness.mjs")
	fakeProofkitPath := filepath.Join(tempDir, "fake-proofkit.mjs")
	if err := os.WriteFile(adapterPath, []byte(TypeScriptSource()), 0o644); err != nil {
		t.Fatalf("write adapter: %v", err)
	}
	if err := os.WriteFile(fakeProofkitPath, []byte(fakeProofkitBinarySource), 0o755); err != nil {
		t.Fatalf("write fake proofkit: %v", err)
	}
	if err := os.WriteFile(harnessPath, []byte(generatedAdapterHarnessSource(fakeProofkitPath)), 0o644); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	command := exec.Command(nodePath, "--experimental-strip-types", harnessPath)
	command.Dir = tempDir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("generated TypeScript harness failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "generated adapter semantics ok") {
		t.Fatalf("generated TypeScript harness did not confirm semantics:\n%s", output)
	}
}

func exportedDeclarations(source string) []string {
	pattern := regexp.MustCompile(`(?m)^export (?:type|interface|function) ([A-Za-z][A-Za-z0-9_]*)`)
	matches := pattern.FindAllStringSubmatch(source, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		out = append(out, match[1])
	}
	slices.Sort(out)
	return out
}

const fakeProofkitBinarySource = `#!/usr/bin/env node
import { writeFileSync } from "node:fs";

const command = process.argv[2];
let input = "";
process.stdin.on("data", (chunk) => {
  input += chunk;
});
process.stdin.on("end", () => {
  if (command === "json-pass") {
    const parsed = JSON.parse(input);
    process.stdout.write(JSON.stringify({schemaVersion: 1, state: "passed", received: parsed}) + "\n");
    process.exit(0);
  }
  if (command === "json-fail") {
    process.stderr.write("diagnostic\n");
    process.stdout.write(JSON.stringify({schemaVersion: 1, state: "failed"}) + "\n");
    process.exit(1);
  }
  if (command === "json-process-fail") {
    process.stderr.write("process failure\n");
    process.exit(2);
  }
  if (command === "json-secret-process-fail") {
    process.stderr.write("Bearer abcdefghijklmnopqrstuvwxyz\n");
    process.exit(2);
  }
  if (command === "json-openai-secret-process-fail") {
    process.stderr.write("sk-proj-abcdefghijklmnop\n");
    process.exit(2);
  }
  if (command === "requirement-spec-tree-view") {
    const outputIndex = process.argv.indexOf("--output");
    if (outputIndex === -1 || process.argv[outputIndex + 1] === undefined) {
      process.stderr.write("missing output flag");
      process.exit(2);
    }
    writeFileSync(process.argv[outputIndex + 1], JSON.stringify({schemaVersion: 1, state: "passed", outputFile: true}) + "\n");
    process.exit(0);
  }
  if (command === "text-pass") {
    process.stdout.write("text result");
    process.exit(0);
  }
  if (command === "json-no-input") {
    if (process.argv.includes("--input")) {
      process.stderr.write("unexpected input flag");
      process.exit(2);
    }
    process.stdout.write(JSON.stringify({schemaVersion: 1, state: "passed", inputless: true}) + "\n");
    process.exit(0);
  }
  process.stderr.write("unknown command");
  process.exit(2);
});
`

func generatedAdapterHarnessSource(fakeProofkitPath string) string {
	return `import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import {
  formatProofkitCliError,
  parseProofkitJsonReportCli,
  parseProofkitJsonStrict,
  proofkitStableJsonString,
  proofkitStableJsonValue,
  readProofkitJsonReportInput,
  runProofkitJsonCommand,
  runProofkitJsonReportCliMain,
  runProofkitNoInputJsonCommand,
  runProofkitTextCommand,
  writeProofkitJsonReportOutput,
} from "./proofkit-json-report-cli-adapter.ts";

const fakeProofkitPath = ` + quoteJavaScriptString(fakeProofkitPath) + `;

const parsed = parseProofkitJsonReportCli(["--input", "in.json", "--output", "out.json"], {
  flags: [{flag: "--input", key: "inputPath", required: true}],
});
assert.equal(parsed.inputPath, "in.json");
assert.equal(parsed.outputPath, "out.json");
assert.throws(() => parseProofkitJsonReportCli(["--unknown"], {flags: []}), /unknown argument/);
assert.throws(() => parseProofkitJsonReportCli([], {flags: [{flag: "--input", key: "inputPath", required: true}]}), /missing required/);
let helpText = "";
assert.throws(
  () => parseProofkitJsonReportCli(["--help"], {
    flags: [],
    helpText: "help text",
    writeHelp: (value) => { helpText = value; },
    exitHelp: () => { throw new Error("help-exit"); },
  }),
  /help-exit/,
);
assert.equal(helpText, "help text");

assert.equal(proofkitStableJsonString({z: 1, a: true}), "{\n  \"a\": true,\n  \"z\": 1\n}\n");
assert.throws(() => proofkitStableJsonValue(Number.POSITIVE_INFINITY), /non-finite/);
assert.throws(() => proofkitStableJsonValue(9007199254740993), /unsafe integer/);
let stdout = "";
writeProofkitJsonReportOutput({z: 1, a: true}, null, {writeStdout: (value) => { stdout += value; }});
assert.equal(stdout, "{\n  \"a\": true,\n  \"z\": 1\n}\n");

assert.deepEqual(parseProofkitJsonStrict("{\"a\":1,\"b\":[true,null]}"), {a: 1, b: [true, null]});
assert.deepEqual(parseProofkitJsonStrict("{\"a\":1.25,\"b\":1e-3}"), {a: 1.25, b: 0.001});
assert.throws(() => parseProofkitJsonStrict("{\"a\":1,\"a\":2}"), /duplicate object key/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":9007199254740993}"), /unsafe integer number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":9007199254740993e0}"), /unsafe integer number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":9007199254740993.0}"), /unsafe integer number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":9007199254740991.1}"), /lossy number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":9007199254740990.9}"), /lossy number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":9007199254740991.1e0}"), /lossy number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":1e-100000}"), /lossy number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":1e309}"), /non-finite number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":01}"), /invalid number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":1.}"), /invalid number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":1e}"), /invalid number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":1e+}"), /invalid number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":-}"), /invalid number/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":+1}"), /unexpected token/);
assert.throws(() => parseProofkitJsonStrict("{\"a\":1} {\"b\":2}"), /multiple JSON values/);
writeFileSync("secret-duplicate.json", "{\"Bearer abcdefghijklmnopqrstuvwxyz\":1,\"Bearer abcdefghijklmnopqrstuvwxyz\":2}");
assert.throws(
  () => readProofkitJsonReportInput("secret-duplicate.json"),
  (error) => error instanceof Error && /duplicate object key/.test(error.message) && !/abcdefghijklmnopqrstuvwxyz/.test(error.message),
);
writeFileSync("oversize.json", "{\"ok\":true}");
assert.throws(() => readProofkitJsonReportInput("oversize.json", {maxInputBytes: 4}), /exceeds maxInputBytes/);
assert.throws(
  () => readProofkitJsonReportInput("missing\napi_key=abc123456789.json"),
  (error) =>
    error instanceof Error &&
    /<redacted-control-rune>/.test(error.message) &&
    /\[REDACTED\]/.test(error.message) &&
    !/abc123456789/.test(error.message) &&
    !/\n/.test(error.message),
);

const pass = runProofkitJsonCommand("json-pass", {z: 1, a: true}, [], {binaryPath: fakeProofkitPath, cwd: "."});
assert.equal(pass.status, 0);
assert.equal(pass.value.state, "passed");
assert.deepEqual(pass.value.received, {a: true, z: 1});

const fail = runProofkitJsonCommand("json-fail", {ok: false}, [], {binaryPath: fakeProofkitPath, cwd: "."});
assert.equal(fail.status, 1);
assert.equal(fail.value.state, "failed");
assert.equal(fail.stderr, "diagnostic\n");
assert.throws(
  () => runProofkitJsonCommand("json-process-fail", {}, [], {binaryPath: fakeProofkitPath, cwd: "."}),
  /process failure/,
);
assert.throws(
  () => runProofkitJsonCommand("json-secret-process-fail", {}, [], {binaryPath: fakeProofkitPath, cwd: "."}),
  /\[REDACTED\]/,
);
assert.throws(
  () => runProofkitJsonCommand("json-openai-secret-process-fail", {}, [], {binaryPath: fakeProofkitPath, cwd: "."}),
  /\[REDACTED\]/,
);
const outputPass = runProofkitJsonCommand("requirement-spec-tree-view", {ok: true}, ["--output", "proofkit-output.json"], {binaryPath: fakeProofkitPath, cwd: "."});
assert.equal(outputPass.status, 0);
assert.equal(outputPass.stdout, "");
assert.equal(outputPass.value.outputFile, true);

const text = runProofkitTextCommand("text-pass", {}, [], {binaryPath: fakeProofkitPath, cwd: "."});
assert.equal(text.status, 0);
assert.equal(text.text, "text result");
const noInput = runProofkitNoInputJsonCommand("json-no-input", [], {binaryPath: fakeProofkitPath, cwd: "."});
assert.equal(noInput.status, 0);
assert.equal(noInput.value.inputless, true);

process.exitCode = undefined;
runProofkitJsonReportCliMain({argv: [], run: () => 7});
assert.equal(process.exitCode, 7);
let errorText = "";
process.exitCode = undefined;
runProofkitJsonReportCliMain({
  argv: [],
  run: () => { throw new Error("ghp_123456789012345678901234567890123456"); },
  writeError: (value) => { errorText += value; },
});
	assert.equal(process.exitCode, 1);
	assert.match(errorText, /\[REDACTED\]/);
	process.exitCode = 0;
	assert.equal(formatProofkitCliError("Bearer abcdefghijklmnopqrstuvwxyz"), "Bearer [REDACTED]");
	assert.equal(formatProofkitCliError("Bearer abcdefgh"), "Bearer [REDACTED]");
	assert.equal(formatProofkitCliError("api_key=abc123456789"), "[REDACTED]");
	assert.equal(formatProofkitCliError("ghp_short"), "[REDACTED]");
	const authorizationHeader = formatProofkitCliError("request failed: Authorization: Basic YWxpY2U6c2VjcmV0");
	assert.match(authorizationHeader, /\[REDACTED\]/);
	assert.doesNotMatch(authorizationHeader, /YWxpY2U6c2VjcmV0|Basic/);
	const controlRunes = formatProofkitCliError("line one\nline two\t\u007fend");
	assert.equal(controlRunes, "line one<redacted-control-rune>line two<redacted-control-rune>end");
	const truncated = formatProofkitCliError("x".repeat(520));
	assert.equal(truncated.length, 512 + "...<truncated-diagnostic>".length);
	assert.match(truncated, /\.\.\.<truncated-diagnostic>$/);

console.log("generated adapter semantics ok");
`
}

func quoteJavaScriptString(value string) string {
	quoted := strings.ReplaceAll(value, `\`, `\\`)
	quoted = strings.ReplaceAll(quoted, `"`, `\"`)
	return `"` + quoted + `"`
}
