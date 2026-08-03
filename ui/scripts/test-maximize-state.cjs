const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const uiRoot = path.resolve(__dirname, "..");
const compiler = path.join(uiRoot, "node_modules", "typescript", "bin", "tsc");
const outputDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "difftrail-maximize-state-"));

try {
  execFileSync(
    process.execPath,
    [compiler, "src/maximize-state.ts", "--target", "ES2022", "--module", "CommonJS", "--outDir", outputDirectory, "--skipLibCheck"],
    { cwd: uiRoot, stdio: "inherit" },
  );

  const { createMaximizeReadGate } = require(path.join(outputDirectory, "maximize-state.js"));
  const gate = createMaximizeReadGate();
  const initialRead = gate.begin();
  const toggleRead = gate.begin();

  assert.equal(gate.isCurrent(initialRead), false);
  assert.equal(gate.isCurrent(toggleRead), true);

  const resizeRead = gate.begin();
  assert.equal(gate.isCurrent(toggleRead), false);
  assert.equal(gate.isCurrent(resizeRead), true);

  gate.invalidate();
  assert.equal(gate.isCurrent(resizeRead), false);
} finally {
  fs.rmSync(outputDirectory, { recursive: true, force: true });
}
