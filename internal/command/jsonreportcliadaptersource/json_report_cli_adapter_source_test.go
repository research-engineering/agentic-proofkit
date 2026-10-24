package jsonreportcliadaptersource

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/commandroute"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

const expectedTypeScriptSourceSha256 = "sha256:e782b2cb6e17f1671a43418cf224a566365a4ebe90730a40699adbffbd1b0ac4"

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

// The generated adapter runs the CLI synchronously without a timeout, so its
// child must never read standard input from the socket of spawnSync's input
// option: on macOS such a reader is sometimes not woken when the parent shuts
// down writing, and the call then never returns. Except on Windows, the input
// file and its directory are removed by path before the child starts.
func TestGeneratedSourceGivesTheCLIItsInputAsARegularFile(t *testing.T) {
	source := TypeScriptSource()
	if count := strings.Count(source, "node:child_process"); count != 1 || !strings.Contains(source, "import { spawnSync } from \"node:child_process\";\n") {
		t.Fatalf("generated source must import only spawnSync from node:child_process, found %d imports", count)
	}
	if count := strings.Count(source, "spawnSync("); count != 1 {
		t.Fatalf("generated source must call spawnSync exactly once, found %d calls", count)
	}
	start := strings.Index(source, "spawnSync(options.binaryPath, childArgs, {\n")
	if start < 0 {
		t.Fatal("generated source lost its single spawnSync call")
	}
	end := strings.Index(source[start:], "\n  });\n")
	if end < 0 {
		t.Fatal("generated spawnSync options are not closed")
	}
	const wantOptions = "spawnSync(options.binaryPath, childArgs, {\n" +
		"    cwd: options.cwd,\n" +
		"    env: options.env,\n" +
		"    maxBuffer: options.maxBuffer ?? defaultMaxBuffer,\n" +
		"    stdio: [stdin, \"pipe\", \"pipe\"],"
	if options := source[start : start+end]; options != wantOptions {
		t.Fatalf("generated spawnSync options must be exactly cwd, env, maxBuffer and a stdin descriptor:\n%s", options)
	}
	for _, required := range []string{
		"const inputText = options.inputMode === \"none\" ? null : proofkitStableJsonString(input);",
		"spawnProofkitWithStdin(options, childArgs, \"ignore\")",
		"const directory = mkdtempSync(join(tmpdir(), \"proofkit-cli-stdin-\"));",
		"const writeFd = openSync(inputPath, \"wx\", 0o600);",
		"writeFileSync(writeFd, inputText, {encoding: \"utf8\"});",
		"    inputFd = openSync(inputPath, \"r\");\n" +
			"    if (process.platform !== \"win32\") {\n" +
			"      removeProofkitInputFile(inputPath, directory);\n" +
			"      removed = true;\n" +
			"    }\n" +
			"    return spawnProofkitWithStdin(options, childArgs, inputFd);\n",
		"if (inputFd !== null) closeSync(inputFd);",
		"if (!removed) removeProofkitInputFile(inputPath, directory);",
		"  rmSync(inputPath, {force: true});\n  rmdirSync(directory);\n",
		"throw new Error(formatProofkitCliError(error));",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("generated source missing regular-file stdin transport token %q", required)
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
		"const {child, outputFile} = runProofkitCommand(commandRoute, input, args, options)",
		"function outputPathFromArgs(args: readonly string[])",
		"function admitWritableOutputTarget",
		"prepared = prepareOutputArgs(options.cwd, args)",
		"if (child.status !== 0 && child.stdout.trim().length === 0) {",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("generated source does not preserve CLI process contract token %q", required)
		}
	}
}

func TestGeneratedSourceAdmitsBoundedCanonicalCommandRoutes(t *testing.T) {
	source := TypeScriptSource()
	for _, required := range []string{
		"function admitCommandRoute(commandRoute: string): readonly string[]",
		"commandRoute.split(" + strconv.Quote(commandroute.Separator) + ")",
		fmt.Sprintf("tokens.length < %d", commandroute.MinimumTokens),
		fmt.Sprintf("tokens.length > %d", commandroute.MaximumTokens),
		strconv.Quote(fmt.Sprintf("agentic-proofkit command route must contain %d to %d canonical tokens", commandroute.MinimumTokens, commandroute.MaximumTokens)),
		"...routeTokens, \"--input\", \"-\"",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("generated source missing command-route guard %q", required)
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
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.091236415555979919321510491623647940156692204483402355271747696953075393053294")
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
	if err := os.WriteFile(harnessPath, []byte(generatedAdapterHarnessSource(t, fakeProofkitPath)), 0o644); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	command := exec.Command(nodePath, "--experimental-strip-types", harnessPath)
	command.Dir = tempDir
	// A pipe, not the null device, so that a child which inherited the
	// harness's standard input would show it.
	command.Stdin = strings.NewReader("harness standard input\n")
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
import { createHash } from "node:crypto";
import { fstatSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const commandIndex = process.argv[2] === "--json-layout" ? 4 : 2;
const command = process.argv[commandIndex];
let commandRoute = command;
let commandRouteLength = 1;
if (command === "adopt" && process.argv[commandIndex + 1] === "plan") {
  commandRoute = "adopt plan";
  commandRouteLength = 2;
} else if (command === "three" && process.argv.slice(commandIndex, commandIndex + 3).join(" ") === "three route tokens") {
  commandRoute = "three route tokens";
  commandRouteLength = 3;
} else if (command === "four" && process.argv.slice(commandIndex, commandIndex + 4).join(" ") === "four route tokens exactly") {
  commandRoute = "four route tokens exactly";
  commandRouteLength = 4;
}
if (command === "early-refusal") {
  process.stderr.write("early refusal\n");
  process.exit(2);
}
let input = "";
process.stdin.on("data", (chunk) => {
  input += chunk;
});
process.stdin.on("end", () => {
  if (["adopt plan", "three route tokens", "four route tokens exactly"].includes(commandRoute)) {
    if (process.argv.includes("--input")) {
      process.stderr.write("unexpected input flag");
      process.exit(2);
    }
    process.stdout.write(JSON.stringify({schemaVersion: 1, state: "passed", route: process.argv.slice(commandIndex, commandIndex + commandRouteLength), args: process.argv.slice(commandIndex + commandRouteLength)}) + "\n");
    process.exit(0);
  }
  if (commandRoute === "json-pass") {
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
    const outputIndex = process.argv.indexOf("--output");
    if (outputIndex !== -1 && process.argv[outputIndex + 1] !== undefined) {
      writeFileSync(process.argv[outputIndex + 1], "text output file");
      process.exit(0);
    }
    process.stdout.write("text result");
    process.exit(0);
  }
  if (command === "text-fail") {
    process.stderr.write("text process failure");
    process.exit(2);
  }
  if (command === "json-no-input") {
    if (process.argv.includes("--input")) {
      process.stderr.write("unexpected input flag");
      process.exit(2);
    }
    process.stdout.write(JSON.stringify({schemaVersion: 1, state: "passed", inputless: true}) + "\n");
    process.exit(0);
  }
  if (command === "stdin-probe") {
    const info = fstatSync(0);
    const temporaryRoot = process.env.PROOFKIT_PROBE_TMP_ROOT;
    const directories = temporaryRoot === undefined ? [] : readdirSync(temporaryRoot).sort()
      .filter((name) => name.startsWith("proofkit-cli-stdin-"))
      .map((name) => ({
        entries: readdirSync(join(temporaryRoot, name)).sort().map((entry) => ({mode: statSync(join(temporaryRoot, name, entry)).mode & 0o777, name: entry})),
        mode: statSync(join(temporaryRoot, name)).mode & 0o777,
      }));
    process.stdout.write(JSON.stringify({schemaVersion: 1, state: "passed", directories, stdin: {
      bytesRead: Buffer.byteLength(input),
      inputFlag: process.argv.includes("--input"),
      isFIFO: info.isFIFO(),
      isFile: info.isFile(),
      isNullDevice: info.isCharacterDevice() && info.rdev === statSync("/dev/null").rdev,
      isSocket: info.isSocket(),
      mode: info.mode & 0o777,
      nlink: info.nlink,
      sha256: createHash("sha256").update(input).digest("hex"),
      size: info.size,
    }}) + "\n");
    process.exit(0);
  }
  if (command === "large-stdout") {
    process.stdout.write("x".repeat(4096));
    process.exit(0);
  }
  if (command === "json-invalid-utf8") {
    process.stdout.write(Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff, 0x7d]));
    process.exit(0);
  }
  process.stderr.write("unknown command");
  process.exit(2);
});
`

func generatedAdapterHarnessSource(t *testing.T, fakeProofkitPath string) string {
	t.Helper()
	return `import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs, { existsSync, fstatSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { join, resolve, sep } from "node:path";
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
const redactionFixtures = ` + redactionFixturesLiteral() + `;
const repositoryRoot = "repository";
const outsideRoot = "outside";
mkdirSync(repositoryRoot);
mkdirSync(outsideRoot);
// Every adapter call of this harness creates its input directory here.
const adapterTemporaryRoot = resolve("adapter-tmp");
mkdirSync(adapterTemporaryRoot);
process.env.TMPDIR = adapterTemporaryRoot;

const parsed = parseProofkitJsonReportCli(["--input", "in.json", "--output", "out.json"], {
  flags: [{flag: "--input", key: "inputPath", required: true}],
});
assert.equal(parsed.inputPath, "in.json");
assert.equal(parsed.outputPath, "out.json");
assert.throws(
  () => parseProofkitJsonReportCli(["--output", "first.json", "--output", "second.json"], {flags: []}),
  /at most once/,
);
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
assert.equal(proofkitStableJsonString({z: 1, a: true}, "compact"), "{\"a\":true,\"z\":1}\n");
assert.equal(
  proofkitStableJsonString({value: "\u007f\u0085\u200b\u2028\u2029\u{e0001}", "\u{10000}": "supplementary", "\ue000": "bmp"}, "compact"),
  "{\"value\":\"\\u007f\\u0085\\u200b\\u2028\\u2029\\udb40\\udc01\",\"\ue000\":\"bmp\",\"\u{10000}\":\"supplementary\"}\n",
);
for (const [value, expected] of [
  ["alpha", "{\"value\":\"alpha\"}\n"],
  ["<&>", "{\"value\":\"<&>\"}\n"],
  ["\u{1f600}", "{\"value\":\"\u{1f600}\"}\n"],
  ["e\u0301", "{\"value\":\"e\u0301\"}\n"],
  ["\b\t\n\f\r", "{\"value\":\"\\b\\t\\n\\f\\r\"}\n"],
  ["\0", "{\"value\":\"\\u0000\"}\n"],
  ["\u007f", "{\"value\":\"\\u007f\"}\n"],
  ["\u0085", "{\"value\":\"\\u0085\"}\n"],
  ["\u200b", "{\"value\":\"\\u200b\"}\n"],
  ["\u{e0001}", "{\"value\":\"\\udb40\\udc01\"}\n"],
  ["\u2028", "{\"value\":\"\\u2028\"}\n"],
  ["\u2029", "{\"value\":\"\\u2029\"}\n"],
]) {
  const encoded = proofkitStableJsonString({value}, "compact");
  assert.equal(encoded, expected);
  assert.equal(parseProofkitJsonStrict(encoded).value, value);
}
const unsafeScalarRangesForTest = ` + unsafeScalarRangesLiteral(t) + `;
const unsafeScalarsForTest = new Set();
for (const [start, end, step] of unsafeScalarRangesForTest) {
  for (let value = start; value <= end; value += step) unsafeScalarsForTest.add(value);
}
function expectedScalarEncodingForTest(value) {
  if (value === 0x08) return "\\b";
  if (value === 0x09) return "\\t";
  if (value === 0x0a) return "\\n";
  if (value === 0x0c) return "\\f";
  if (value === 0x0d) return "\\r";
  if (unsafeScalarsForTest.has(value)) {
    if (value <= 0xffff) return "\\u" + value.toString(16).padStart(4, "0");
    const adjusted = value - 0x10000;
    return "\\u" + (0xd800 + (adjusted >> 10)).toString(16) + "\\u" + (0xdc00 + (adjusted & 0x3ff)).toString(16);
  }
  if (value === 0x22) return "\\\"";
  if (value === 0x5c) return "\\\\";
  return String.fromCodePoint(value);
}
for (let value = 0; value <= 0x10ffff; value += 1) {
  if (value >= 0xd800 && value <= 0xdfff) continue;
  const scalar = String.fromCodePoint(value);
  assert.equal(
    proofkitStableJsonString({value: scalar}, "compact"),
    "{\"value\":\"" + expectedScalarEncodingForTest(value) + "\"}\n",
    "U+" + value.toString(16).padStart(4, "0"),
  );
}
for (const invalidScalar of ["\ud800", "\udc00", "\ud800a"]) {
  assert.throws(() => proofkitStableJsonValue({value: invalidScalar}), /Unicode scalar values/);
  assert.throws(() => proofkitStableJsonValue({[invalidScalar]: "key"}), /Unicode scalar values/);
}
for (let unit = 0xd800; unit <= 0xdfff; unit += 1) {
  const invalidScalar = String.fromCharCode(unit);
  assert.throws(() => proofkitStableJsonValue({value: invalidScalar}), /Unicode scalar values/);
  assert.throws(() => proofkitStableJsonValue({[invalidScalar]: "key"}), /Unicode scalar values/);
}
for (let high = 0xd800; high <= 0xdbff; high += 1) {
  for (let low = 0xdc00; low <= 0xdfff; low += 1) {
    const scalar = String.fromCharCode(high, low);
    proofkitStableJsonValue({value: scalar});
    proofkitStableJsonValue({[scalar]: "key"});
  }
}
assert.throws(() => parseProofkitJsonStrict('{"value":"\\ud800"}'), /Unicode scalar values/);
const prototypeKey = JSON.parse('{"__proto__":{"polluted":true}}');
assert.equal(proofkitStableJsonString(prototypeKey), '{\n  "__proto__": {\n    "polluted": true\n  }\n}\n');
assert.equal(({}).polluted, undefined);
assert.throws(() => proofkitStableJsonValue(Number.POSITIVE_INFINITY), /non-finite/);
assert.throws(() => proofkitStableJsonValue(9007199254740993), /unsafe integer/);
const cyclic = {};
cyclic["self"] = cyclic;
assert.throws(() => proofkitStableJsonValue(cyclic), /cycles/);

function nestedJson(kind, wrappers) {
  let value = "0";
  for (let index = 0; index < wrappers; index += 1) {
    value = kind === "array" || (kind === "mixed" && index % 2 === 0) ? "[" + value + "]" : "{\"value\":" + value + "}";
  }
  return value;
}

function nestedStableValue(kind, wrappers) {
  let value = 0;
  for (let index = 0; index < wrappers; index += 1) {
    value = kind === "array" || (kind === "mixed" && index % 2 === 0) ? [value] : {value};
  }
  return value;
}

for (const kind of ["array", "object", "mixed"]) {
  assert.doesNotThrow(() => parseProofkitJsonStrict(nestedJson(kind, 511)), kind + " JSON must pass exactly at depth 512");
  assert.throws(() => parseProofkitJsonStrict(nestedJson(kind, 512)), /nesting depth limit/, kind + " JSON must fail at depth 513");
  assert.doesNotThrow(() => proofkitStableJsonValue(nestedStableValue(kind, 511)), kind + " value must pass exactly at depth 512");
  assert.throws(() => proofkitStableJsonValue(nestedStableValue(kind, 512)), /nesting depth limit/, kind + " value must fail at depth 513");
}

assert.throws(() => proofkitStableJsonValue(new Date()), /plain or null prototype/);
const customPrototype = Object.create({inherited: true});
customPrototype.value = 1;
assert.throws(() => proofkitStableJsonValue(customPrototype), /plain or null prototype/);
const sparseArray = new Array(1);
assert.throws(() => proofkitStableJsonValue(sparseArray), /dense/);
const customPropertyArray = [1];
customPropertyArray.extra = 2;
assert.throws(() => proofkitStableJsonValue(customPropertyArray), /custom properties/);
const customNumericPropertyArray = [1];
customNumericPropertyArray["4294967295"] = 2;
assert.throws(() => proofkitStableJsonValue(customNumericPropertyArray), /custom properties/);
const symbolArray = [1];
symbolArray[Symbol("secret")] = 2;
assert.throws(() => proofkitStableJsonValue(symbolArray), /custom properties/);
const symbolObject = {value: 1};
symbolObject[Symbol("secret")] = 2;
assert.throws(() => proofkitStableJsonValue(symbolObject), /symbol keys/);
const hiddenObject = {value: 1};
Object.defineProperty(hiddenObject, "hidden", {enumerable: false, value: 2});
assert.throws(() => proofkitStableJsonValue(hiddenObject), /own data properties/);
let accessorExecutions = 0;
const accessorObject = {};
Object.defineProperty(accessorObject, "value", {enumerable: true, get: () => { accessorExecutions += 1; return 1; }});
assert.throws(() => proofkitStableJsonValue(accessorObject), /own data properties/);
const accessorArray = [0];
Object.defineProperty(accessorArray, "0", {enumerable: true, get: () => { accessorExecutions += 1; return 1; }});
assert.throws(() => proofkitStableJsonValue(accessorArray), /own data elements/);
assert.equal(accessorExecutions, 0, "stable JSON must never execute accessors");
let stdout = "";
writeProofkitJsonReportOutput({z: 1, a: true}, null, {writeStdout: (value) => { stdout += value; }});
assert.equal(stdout, "{\n  \"a\": true,\n  \"z\": 1\n}\n");
assert.throws(() => writeProofkitJsonReportOutput({ok: true}, "missing-cwd.json"), /cwd is required/);
writeFileSync(repositoryRoot + "/atomic.json", "old");
writeProofkitJsonReportOutput({z: 1, a: true}, "atomic.json", {cwd: repositoryRoot});
assert.equal(readFileSync(repositoryRoot + "/atomic.json", "utf8"), "{\n  \"a\": true,\n  \"z\": 1\n}\n");
assert.deepEqual(readdirSync(repositoryRoot).filter((name) => name.includes(".tmp-")), []);

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
writeFileSync("malformed-utf8.json", Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff, 0x7d]));
assert.throws(
  () => readProofkitJsonReportInput("malformed-utf8.json"),
  (error) => error instanceof Error && /input file is not valid UTF-8/.test(error.message) && !error.message.includes("ff"),
);
assert.throws(
  () => readProofkitJsonReportInput("missing\napi_key=abc123456789.json"),
  (error) => error instanceof Error && error.message === "<redacted-diagnostic-value>",
);
assert.throws(
  () => readProofkitJsonReportInput("missing-prefix.json", {failureMessagePrefix: "Bearer prefixsecret123456789"}),
  (error) => error instanceof Error && error.message === "<redacted-diagnostic-value>",
);

const pass = runProofkitJsonCommand("json-pass", {z: 1, a: true}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot});
assert.equal(pass.status, 0);
assert.equal(pass.value.state, "passed");
assert.deepEqual(pass.value.received, {a: true, z: 1});
const routedPass = runProofkitNoInputJsonCommand("adopt plan", ["--mode", "fresh", "--repo-root", "."], {binaryPath: fakeProofkitPath, cwd: repositoryRoot});
assert.equal(routedPass.status, 0);
assert.deepEqual(routedPass.value.route, ["adopt", "plan"]);
assert.deepEqual(routedPass.value.args, ["--mode", "fresh", "--repo-root", "."]);
const maxMinusOneRoute = runProofkitNoInputJsonCommand("three route tokens", [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot});
assert.deepEqual(maxMinusOneRoute.value.route, ["three", "route", "tokens"]);
const maximumRoute = runProofkitNoInputJsonCommand("four route tokens exactly", [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot});
assert.deepEqual(maximumRoute.value.route, ["four", "route", "tokens", "exactly"]);
for (const invalidRoute of ["", "adopt  plan", "adopt plan now extra later", "Adopt plan", "--help"]) {
  assert.throws(
    () => runProofkitJsonCommand(invalidRoute, {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
		/1 to 4 canonical tokens/,
  );
}
const compactPass = runProofkitJsonCommand("json-pass", {z: 1, a: true}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot, jsonLayout: "compact"});
assert.equal(compactPass.status, 0);
assert.deepEqual(compactPass.value.received, {a: true, z: 1});

const fail = runProofkitJsonCommand("json-fail", {ok: false}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot});
assert.equal(fail.status, 1);
assert.equal(fail.value.state, "failed");
assert.equal(fail.stderr, "diagnostic\n");
assert.throws(
  () => runProofkitJsonCommand("json-process-fail", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  /process failure/,
);
assert.throws(
  () => runProofkitJsonCommand("json-secret-process-fail", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  (error) => error instanceof Error && error.message === "<redacted-diagnostic-value>",
);
assert.throws(
  () => runProofkitJsonCommand("json-openai-secret-process-fail", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  (error) => error instanceof Error && error.message === "<redacted-diagnostic-value>",
);
assert.throws(
  () => runProofkitJsonCommand("json-invalid-utf8", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  (error) => error instanceof Error && error.message === "Proofkit stdout is not valid UTF-8",
);
const outputPass = runProofkitJsonCommand("requirement-spec-tree-view", {ok: true}, ["--output", "proofkit-output.json"], {binaryPath: fakeProofkitPath, cwd: repositoryRoot});
assert.equal(outputPass.status, 0);
assert.equal(outputPass.stdout, "");
assert.equal(outputPass.value.outputFile, true);
assert.throws(
  () => runProofkitJsonCommand("requirement-spec-tree-view", {ok: true}, ["--output", "-"], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  /other than -/,
);
assert.throws(
  () => runProofkitJsonCommand("requirement-spec-tree-view", {ok: true}, ["--output", "first.json", "--output", "second.json"], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  /at most once/,
);
assert.equal(existsSync(repositoryRoot + "/first.json"), false);
assert.equal(existsSync(repositoryRoot + "/second.json"), false);
assert.throws(
  () => runProofkitJsonCommand("requirement-spec-tree-view", {ok: true}, ["--output", resolve(outsideRoot, "absolute.json")], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  /repository-relative/,
);
assert.throws(
  () => runProofkitJsonCommand("requirement-spec-tree-view", {ok: true}, ["--output", "../outside/traversal.json"], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  /inside the repository/,
);
assert.equal(existsSync(outsideRoot + "/absolute.json"), false);
assert.equal(existsSync(outsideRoot + "/traversal.json"), false);

mkdirSync(repositoryRoot + "/canonical-parent");
symlinkSync("canonical-parent", repositoryRoot + "/inside-parent-link", "dir");
assert.throws(
  () => runProofkitJsonCommand(
    "requirement-spec-tree-view",
    {ok: true},
    ["--output", "inside-parent-link/canonical.json"],
    {binaryPath: fakeProofkitPath, cwd: repositoryRoot},
  ),
  /non-symlink directories/,
);
assert.equal(existsSync(repositoryRoot + "/canonical-parent/canonical.json"), false);

symlinkSync("../outside", repositoryRoot + "/outside-parent-link", "dir");
assert.throws(
  () => runProofkitJsonCommand("requirement-spec-tree-view", {ok: true}, ["--output", "outside-parent-link/escaped.json"], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  /non-symlink directories/,
);
assert.equal(existsSync(outsideRoot + "/escaped.json"), false);
writeFileSync(outsideRoot + "/symlink-target.json", "unchanged");
symlinkSync("../outside/symlink-target.json", repositoryRoot + "/symlink-output.json");
assert.throws(
  () => runProofkitJsonCommand("requirement-spec-tree-view", {ok: true}, ["--output", "symlink-output.json"], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  /regular non-symlink file/,
);
assert.throws(
  () => writeProofkitJsonReportOutput({ok: true}, "symlink-output.json", {cwd: repositoryRoot}),
  /regular non-symlink file/,
);
assert.equal(readFileSync(outsideRoot + "/symlink-target.json", "utf8"), "unchanged");
mkdirSync(repositoryRoot + "/nonregular-output");
assert.throws(
  () => runProofkitJsonCommand("requirement-spec-tree-view", {ok: true}, ["--output", "nonregular-output"], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  /regular non-symlink file/,
);

const text = runProofkitTextCommand("text-pass", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot});
assert.equal(text.status, 0);
assert.equal(text.text, "text result");
assert.throws(() => runProofkitTextCommand("text-pass", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot, jsonLayout: "compact"}), /only for JSON/);
const textOutput = runProofkitTextCommand("text-pass", {}, ["--output", "proofkit-output.txt"], {binaryPath: fakeProofkitPath, cwd: repositoryRoot});
assert.equal(textOutput.status, 0);
assert.equal(textOutput.stdout, "");
assert.equal(textOutput.text, "text output file");
const nestedTextOutput = runProofkitTextCommand("text-pass", {}, ["--output", "new-parent/nested-output.txt"], {binaryPath: fakeProofkitPath, cwd: repositoryRoot});
assert.equal(nestedTextOutput.status, 0);
assert.equal(nestedTextOutput.text, "text output file");
assert.equal(readFileSync(repositoryRoot + "/new-parent/nested-output.txt", "utf8"), "text output file");
assert.throws(
  () => runProofkitTextCommand("text-fail", {}, ["--output", "proofkit-output.txt"], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  /text process failure/,
);
assert.throws(
  () => runProofkitTextCommand("text-pass", {}, ["--output", "../outside.txt"], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  /repository-relative|inside the repository/,
);
const noInput = runProofkitNoInputJsonCommand("json-no-input", [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot});
assert.equal(noInput.status, 0);
assert.equal(noInput.value.inputless, true);

const probeEnv = {...process.env, PROOFKIT_PROBE_TMP_ROOT: adapterTemporaryRoot};
const probeInput = {a: true, payload: "x".repeat(1 << 20), z: 1};
const probeText = proofkitStableJsonString(probeInput);
const probeStdin = (nlink) => ({
  bytesRead: Buffer.byteLength(probeText),
  inputFlag: true,
  isFIFO: false,
  isFile: true,
  isNullDevice: false,
  isSocket: false,
  mode: 0o600,
  nlink,
  sha256: createHash("sha256").update(probeText).digest("hex"),
  size: Buffer.byteLength(probeText),
});
const inputDirectories = [{entries: [{mode: 0o600, name: "stdin"}], mode: 0o700}];
const listInputDirectories = () => readdirSync(adapterTemporaryRoot).sort().map((name) => {
  const directory = join(adapterTemporaryRoot, name);
  return {
    entries: readdirSync(directory).sort().map((entry) => ({mode: statSync(join(directory, entry)).mode & 0o777, name: entry})),
    mode: statSync(directory).mode & 0o777,
  };
});
const inAdapterTemporaryRoot = (path) => typeof path === "string" && path.startsWith(adapterTemporaryRoot + sep);
const simulatedFailure = (code) => Object.assign(new Error("simulated " + code), {code});
const openDescriptorCount = () => readdirSync("/dev/fd").length;
// Replaces node:fs functions, as the adapter sees them, for one run.
const withAdapterFs = (replacements, run) => {
  const saved = {};
  for (const [name, replace] of Object.entries(replacements)) {
    saved[name] = fs[name];
    fs[name] = replace(saved[name]);
  }
  syncBuiltinESMExports();
  try {
    return run();
  } finally {
    Object.assign(fs, saved);
    syncBuiltinESMExports();
  }
};
// The Windows branch of the adapter is exercised here by reporting win32 as the
// platform; Windows itself is not.
const platformDescriptor = Object.getOwnPropertyDescriptor(process, "platform");
const asWindows = (run) => {
  Object.defineProperty(process, "platform", {...platformDescriptor, value: "win32"});
  try {
    return run();
  } finally {
    Object.defineProperty(process, "platform", platformDescriptor);
  }
};
// Records the input directory when the adapter opens the input file for the child.
const runProbe = () => {
  const atOpen = [];
  const result = withAdapterFs({openSync: (open) => (path, flags, mode) => {
    const descriptor = open(path, flags, mode);
    if (inAdapterTemporaryRoot(path) && flags === "r") atOpen.push(...listInputDirectories());
    return descriptor;
  }}, () => runProofkitJsonCommand("stdin-probe", probeInput, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot, env: probeEnv}));
  return {atOpen, result};
};

const probe = runProbe();
assert.deepEqual(probe.atOpen, inputDirectories, "the input file is alone in a fresh mode 0700 directory when it is opened for the child");
assert.deepEqual(probe.result.value.stdin, probeStdin(0), "the child reads the stable JSON input to the end of a regular file that no longer has a name");
assert.deepEqual(probe.result.value.directories, [], "no input directory remains while the child runs");
assert.deepEqual(readdirSync(adapterTemporaryRoot), []);
const windowsProbe = asWindows(runProbe);
assert.deepEqual(windowsProbe.atOpen, inputDirectories);
assert.deepEqual(windowsProbe.result.value.stdin, probeStdin(1), "on Windows the child reads the input file under its name");
assert.deepEqual(windowsProbe.result.value.directories, inputDirectories, "on Windows the input directory remains while the child runs");
assert.deepEqual(readdirSync(adapterTemporaryRoot), [], "on Windows the input directory is removed when the call returns");
assert.equal(fstatSync(0).isFIFO(), true, "the harness's own standard input is a pipe");
const noInputProbe = runProofkitNoInputJsonCommand("stdin-probe", [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot, env: probeEnv});
assert.equal(noInputProbe.value.stdin.inputFlag, false);
assert.equal(noInputProbe.value.stdin.isNullDevice, true, "a call without input gives the child the null device, not an inherited standard input");
assert.equal(noInputProbe.value.stdin.isFIFO, false);
assert.equal(noInputProbe.value.stdin.isSocket, false);
assert.equal(noInputProbe.value.stdin.bytesRead, 0);
assert.deepEqual(noInputProbe.value.directories, [], "a call without input writes no input file");
assert.throws(
  () => runProofkitJsonCommand("early-refusal", {payload: "y".repeat(2 << 20)}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}),
  (error) => error instanceof Error && error.message === "early refusal",
  "a child that exits without reading its input reports its own refusal, not a write error",
);
assert.throws(
  () => runProofkitJsonCommand("large-stdout", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot, maxBuffer: 1024}),
  /ENOBUFS/,
);
assert.throws(() => runProofkitJsonCommand("json-pass", {}, [], {binaryPath: resolve("missing-proofkit"), cwd: repositoryRoot}), /ENOENT/);
// spawnSync's own argument errors are thrown with the adapter's redacted and
// bounded diagnostic, as plain errors without Node's class or code.
assert.throws(
  () => runProofkitJsonCommand("json-pass", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot, maxBuffer: -1}),
  (error) => error.constructor === Error && error.code === undefined && /options\.maxBuffer/.test(error.message),
);
assert.throws(
  () => runProofkitJsonCommand("json-pass", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot, env: {PROOFKIT_PROBE_VALUE: "ghp_123456789012345678901234567890123456\u0000"}}),
  (error) => error.constructor === Error && error.code === undefined && error.message === "<redacted-diagnostic-value>",
  "a secret-shaped environment value in spawnSync's argument error is redacted",
);
assert.deepEqual(readdirSync(adapterTemporaryRoot), [], "a throw from spawnSync leaves no input directory");
assert.throws(() => runProofkitJsonCommand("json-pass", cyclic, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}), /cycles/);
process.env.TMPDIR = resolve("missing-temporary-root");
assert.throws(() => runProofkitJsonCommand("json-pass", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}), /ENOENT/);
process.env.TMPDIR = adapterTemporaryRoot;

// A throw inside the transport closes the input descriptor and leaves no input
// directory; a failed removal before the child starts fails the call and is
// retried once when the call ends.
const descriptorsBeforeTransportFailures = openDescriptorCount();
let reopenFailures = 0;
assert.throws(
  () => withAdapterFs({openSync: (open) => (path, flags, mode) => {
    if (inAdapterTemporaryRoot(path) && flags === "r" && reopenFailures++ === 0) throw simulatedFailure("EIO");
    return open(path, flags, mode);
  }}, () => runProofkitJsonCommand("json-pass", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot})),
  /simulated EIO/,
);
assert.equal(reopenFailures, 1);
assert.deepEqual(readdirSync(adapterTemporaryRoot), [], "a failed open for the child leaves no input directory");
for (const name of ["rmSync", "rmdirSync"]) {
  let removals = 0;
  assert.throws(
    () => withAdapterFs({[name]: (remove) => (path, ...rest) => {
      if (inAdapterTemporaryRoot(path) && removals++ === 0) throw simulatedFailure("EBUSY");
      return remove(path, ...rest);
    }}, () => runProofkitJsonCommand("json-pass", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot})),
    /simulated EBUSY/,
    name + ": a failed removal before the child starts fails the call",
  );
  assert.equal(removals, 2, name + ": the removal is retried once when the call ends");
  assert.deepEqual(readdirSync(adapterTemporaryRoot), [], name + ": the retried removal leaves no input directory");
}
let windowsRemovals = 0;
assert.throws(
  () => asWindows(() => withAdapterFs({rmSync: (remove) => (path, ...rest) => {
    if (inAdapterTemporaryRoot(path) && windowsRemovals++ === 0) throw simulatedFailure("EBUSY");
    return remove(path, ...rest);
  }}, () => runProofkitJsonCommand("json-pass", {}, [], {binaryPath: fakeProofkitPath, cwd: repositoryRoot}))),
  /simulated EBUSY/,
  "on Windows a failed removal when the call ends fails the call",
);
assert.equal(windowsRemovals, 1);
assert.equal(listInputDirectories().length, 1, "on Windows a failed removal leaves the input directory");
for (const name of readdirSync(adapterTemporaryRoot)) rmSync(join(adapterTemporaryRoot, name), {force: true, recursive: true});
assert.equal(openDescriptorCount(), descriptorsBeforeTransportFailures, "no input descriptor stays open after a transport failure");

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
	assert.equal(errorText, "<redacted-diagnostic-value>\n");
	process.exitCode = 0;
	const fixedDiagnostic = "<redacted-diagnostic-value>";
	assert.equal(formatProofkitCliError("Bearer abcdefghijklmnopqrstuvwxyz"), fixedDiagnostic);
	assert.equal(formatProofkitCliError("Bearer abcdefgh"), fixedDiagnostic);
	assert.equal(formatProofkitCliError("api_key=abc123456789"), fixedDiagnostic);
	assert.equal(formatProofkitCliError("ghp_short"), fixedDiagnostic);
	const authorizationHeader = formatProofkitCliError("request failed: Authorization: Basic YWxpY2U6c2VjcmV0");
	assert.equal(authorizationHeader, fixedDiagnostic);
	const controlRunes = formatProofkitCliError("line one\nline two\t\u007fend");
	assert.equal(controlRunes, fixedDiagnostic);
	const truncated = formatProofkitCliError("x".repeat(520));
	assert.equal(truncated.length, 512 + "...<truncated-diagnostic>".length);
	assert.match(truncated, /\.\.\.<truncated-diagnostic>$/);
	for (const fixture of redactionFixtures) {
	  assert.equal(formatProofkitCliError("prefix " + fixture.input + " suffix"), fixedDiagnostic, fixture.name + " contiguous");
	  const wrapped = "prefix " + fixture.input + " suffix";
	  for (const separator of ["\0", "\u007f", "\u0085", "\u200b", "\u{e0001}", "\u2028", "\u2029"]) {
	    for (const offset of [Math.floor(wrapped.length / 3), Math.floor(wrapped.length / 2), Math.floor(wrapped.length * 2 / 3)]) {
	      assert.equal(formatProofkitCliError(wrapped.slice(0, offset) + separator + wrapped.slice(offset)), fixedDiagnostic, fixture.name + " split");
	    }
	  }
	}
	assert.equal(formatProofkitCliError("\ud800"), fixedDiagnostic);
	const slashRunStart = performance.now();
	assert.equal(formatProofkitCliError("\\".repeat(65536)), "\\".repeat(512) + "...<truncated-diagnostic>");
	assert(performance.now() - slashRunStart < 2000, "generated diagnostic escaping must remain linear");
	const beyondDecodeBudget = "passw\\u005c" + "u005c".repeat(17) + "u006frd=synthetic-fixture-value";
	assert.equal(formatProofkitCliError(beyondDecodeBudget), fixedDiagnostic);
	let nestedJSON = JSON.stringify('{"passw\\u006frd":"synthetic-fixture-value"}').replace("u006f", "\\u0075006f");
	for (let depth = 0; depth <= 4; depth++) {
		assert.equal(formatProofkitCliError(nestedJSON), fixedDiagnostic);
		nestedJSON = JSON.stringify(nestedJSON);
	}
	const regexStart = performance.now();
	assert.equal(formatProofkitCliError("a".repeat(8192) + beyondDecodeBudget), fixedDiagnostic);
	assert(performance.now() - regexStart < 2000, "generated repeated decoding must not amplify URL matching cost");
	const guardedURLStart = performance.now();
	assert.equal(formatProofkitCliError("a".repeat(8192) + "://safe " + beyondDecodeBudget), fixedDiagnostic);
	assert(performance.now() - guardedURLStart < 2000, "generated URL candidate scanning must remain bounded");
	assert.equal(formatProofkitCliError("123https://user:password@example.test"), fixedDiagnostic);

assert.deepEqual(readdirSync(adapterTemporaryRoot), [], "every adapter call removes its input directory");

console.log("generated adapter semantics ok");
`
}

func unsafeScalarRangesLiteral(t *testing.T) string {
	t.Helper()
	type corpusRange struct {
		Start int `json:"start"`
		End   int `json:"end"`
		Step  int `json:"step"`
	}
	type corpus struct {
		SchemaVersion int           `json:"schemaVersion"`
		Ranges        []corpusRange `json:"ranges"`
	}
	path := filepath.Join("..", "..", "kernel", "unicodepolicy", "testdata", "unsafe-scalar-ranges.v1.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var owner corpus
	if err := json.Unmarshal(content, &owner); err != nil {
		t.Fatal(err)
	}
	if owner.SchemaVersion != 1 || len(owner.Ranges) == 0 {
		t.Fatal("Unicode owner corpus identity is invalid")
	}
	projection := make([][3]int, 0, len(owner.Ranges))
	for _, item := range owner.Ranges {
		projection = append(projection, [3]int{item.Start, item.End, item.Step})
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func redactionFixturesLiteral() string {
	type fixture struct {
		Input            string   `json:"input"`
		Name             string   `json:"name"`
		SensitiveNeedles []string `json:"sensitiveNeedles"`
	}
	fixtures := []fixture{}
	for _, item := range admit.ReportVisibleRedactionFixtures() {
		fixtures = append(fixtures, fixture{Name: item.Name, Input: item.Input, SensitiveNeedles: item.SensitiveNeedles})
	}
	encoded, err := json.Marshal(fixtures)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func quoteJavaScriptString(value string) string {
	quoted := strings.ReplaceAll(value, `\`, `\\`)
	quoted = strings.ReplaceAll(quoted, `"`, `\"`)
	return `"` + quoted + `"`
}
