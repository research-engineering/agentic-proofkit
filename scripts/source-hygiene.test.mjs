import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {fileURLToPath} from "node:url";
import test from "node:test";

const scanner = fileURLToPath(new URL("source-hygiene.mjs", import.meta.url));

test("source hygiene scans large staged blobs without truncation and preserves both source views", () => {
  const root = mkdtempSync(join(tmpdir(), "proofkit-source-hygiene-"));
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")));
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  env.GIT_CONFIG_SYSTEM = "/dev/null";
  const git = (...args) => execFileSync("git", args, {cwd: root, env, timeout: 10_000, stdio: "ignore"});
  const run = () => {
    const result = spawnSync(process.execPath, [scanner], {cwd: root, env, timeout: 20_000, encoding: "utf8", maxBuffer: 1 << 20});
    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.stdout, "");
    return result;
  };
  try {
    git("-c", "init.defaultBranch=main", "init");
    const path = join(root, "source.json");
    const prefix = " ".repeat(2 << 20);
    const forbidden = ["auto", "fleet"].join("");
    writeFileSync(path, prefix + "{}\n");
    git("add", "source.json");
    assert.equal(run().status, 0, "large clean staged blob rejected");

    writeFileSync(path, prefix + forbidden);
    git("add", "source.json");
    writeFileSync(path, "{}\n");
    let result = run();
    assert.equal(result.status, 1, "staged suffix beyond old buffer omitted");
    assert.match(result.stderr, /organization-specific text leaked.*source\.json/);

    git("add", "source.json");
    writeFileSync(path, prefix + forbidden);
    result = run();
    assert.equal(result.status, 1, "worktree source was replaced by index-only scanning");
    assert.match(result.stderr, /organization-specific text leaked.*source\.json/);

    writeFileSync(path, " ".repeat((16 << 20) + 1));
    git("add", "source.json");
    result = run();
    assert.equal(result.status, 1, "oversized index blob must fail, not truncate");
    assert.match(result.stderr, /ENOBUFS/);
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});
