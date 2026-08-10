const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const vite = path.join(root, "node_modules", "vite", "bin", "vite.js");
const output = fs.mkdtempSync(path.join(os.tmpdir(), "difftrail-production-build-"));
const token = "difftrail-production-token-must-not-be-bundled";
const endpoint = "http://127.0.0.1:59999/api";

function filesIn(folder) {
  return fs.readdirSync(folder, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(folder, entry.name);
    return entry.isDirectory() ? filesIn(target) : [target];
  });
}

try {
  execFileSync(process.execPath, [vite, "build", "--outDir", output, "--emptyOutDir"], {
    cwd: root,
    env: {
      ...process.env,
      VITE_DIFFTRAIL_API_TOKEN: token,
      VITE_DIFFTRAIL_API_URL: endpoint,
    },
    stdio: "inherit",
  });
  const bundle = Buffer.concat(filesIn(output).map((file) => fs.readFileSync(file))).toString("utf8");
  assert.equal(bundle.includes(token), false, "production bundle contains the API token override");
  assert.equal(bundle.includes(endpoint), false, "production bundle contains the API endpoint override");
} finally {
  fs.rmSync(output, { recursive: true, force: true });
}
