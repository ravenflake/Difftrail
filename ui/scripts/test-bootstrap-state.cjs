const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const uiRoot = path.resolve(__dirname, "..");
const compiler = path.join(uiRoot, "node_modules", "typescript", "bin", "tsc");
const outputDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "difftrail-bootstrap-state-"));

try {
  execFileSync(
    process.execPath,
    [compiler, "src/bootstrap-state.ts", "--target", "ES2022", "--module", "CommonJS", "--outDir", outputDirectory, "--skipLibCheck"],
    { cwd: uiRoot, stdio: "inherit" },
  );

  const { createBootstrapReadGate } = require(path.join(outputDirectory, "bootstrap-state.js"));
  const gate = createBootstrapReadGate();
  const pollStartedBeforeSave = gate.begin();

  gate.invalidate();
  assert.equal(gate.isCurrent(pollStartedBeforeSave), false, "a pre-save poll must stay stale");

  const firstRefresh = gate.begin();
  const newerRefresh = gate.begin();
  assert.equal(gate.isCurrent(firstRefresh), false, "an older refresh must not win");
  assert.equal(gate.isCurrent(newerRefresh), true, "the newest refresh may update the UI");
} finally {
  fs.rmSync(outputDirectory, { recursive: true, force: true });
}
