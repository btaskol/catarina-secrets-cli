// csec scan: rules, false positives, redaction, files + git history, exit codes.
// Fake keys are assembled at runtime so this file itself never looks like it holds a secret.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanLine, redact } from "../scan.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "csec.js");
const rnd = (n, abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") =>
  Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => abc[b % abc.length]).join("");
const UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", HEX = "0123456789abcdef";

const FAKE = {
  "aws-access-key": "AKIA" + rnd(16, UP),
  "github-token": "ghp" + "_" + rnd(36),
  "stripe-key": "sk" + "_live_" + rnd(24),
  "anthropic-key": "sk-" + "ant-api03-" + rnd(90),
  "openai-key": "sk-" + "proj-" + rnd(30) + "T3Blbk" + "FJ" + rnd(30),
  "google-api-key": "AI" + "za" + rnd(35),
  "slack-token": "xo" + "xb-" + rnd(12, "0123456789") + "-" + rnd(24),
  "sendgrid-key": "SG" + "." + rnd(22) + "." + rnd(43),
  "npm-token": "npm" + "_" + rnd(36),
  "huggingface-token": "hf" + "_" + rnd(34),
  "digitalocean-token": "dop" + "_v1_" + rnd(64, HEX),
  "private-key": "-----BEGIN " + "RSA PRIVATE KEY-----",
};

test("provider formats are found with high confidence", () => {
  for (const [rule, value] of Object.entries(FAKE)) {
    const f = scanLine(`const key = "${value}";`, "src/app.js");
    assert.equal(f.length, 1, `${rule}: ${JSON.stringify(f)}`);
    assert.equal(f[0].rule, rule);
    assert.equal(f[0].confidence, "high");
  }
  const pw = rnd(14);
  const db = scanLine(`DATABASE_URL=postgres://app:${pw}@db.example.com:5432/prod`, ".env");
  assert.equal(db[0].rule, "database-url");
  assert.equal(db[0].value, pw, "only the password counts as the secret");
});

test("no false positives on code, placeholders and examples", () => {
  const clean = [
    ["const token = await getToken(userId);", "a.js"],
    ["const apiKey = config.stripe.apiKey;", "a.js"],
    ["const secret = process.env.STRIPE_SECRET_KEY;", "a.js"],
    ["password: '${DB_PASSWORD}',", "a.js"],
    ['API_KEY="your_api_key_here"', ".env"],
    ["SECRET_KEY=changeme", ".env"],
    ["DATABASE_URL=postgres://user:${PASSWORD}@localhost/db", ".env"],
    ["token = makeToken(rand(32))", "a.py"],
    ["password_reset_url: https://example.com/reset", "config.yml"],
    ["STRIPE_KEY=sk_live_xxxxxxxxxxxxxxxx", ".env.example"],
    [`OPENAI_API_KEY=${rnd(40)}`, ".env.example"],
    ["const tokenName = 'access_token_for_admins';", "a.js"],
  ];
  for (const [line, file] of clean) assert.deepEqual(scanLine(line, file), [], `${file}: ${line}`);
  assert.deepEqual(scanLine(`const k = "${FAKE["stripe-key"]}"; // csec:ignore`, "a.js"), [], "csec:ignore");
});

test("random-looking values under secret names: .env is high, code is possible", () => {
  const v = rnd(32) + "!x";
  assert.equal(scanLine(`MY_SERVICE_SECRET=${v}`, ".env")[0].confidence, "high");
  assert.equal(scanLine(`MY_SERVICE_SECRET=${v}`, ".env.local")[0].confidence, "high");
  assert.equal(scanLine(`MY_SERVICE_SECRET=${v}`, ".dev.vars")[0].confidence, "high", "Cloudflare local secrets");
  const code = scanLine(`const clientSecret = "${v}";`, "src/x.ts");
  assert.equal(code[0].confidence, "medium");
  assert.deepEqual(scanLine(`const clientSecret = ${v};`, "src/x.ts"), [], "unquoted in code = an identifier, not a literal");
});

test("redaction never shows the full value", () => {
  const v = FAKE["stripe-key"];
  const r = redact(v);
  assert.ok(!r.includes(v.slice(4, -2)));
  assert.match(r, /^sk_l…/);
  assert.equal(redact("short"), "•••••");
});

test("csec scan: files, .env, git history, JSON, exit codes, no account needed", () => {
  const dir = mkdtempSync(join(tmpdir(), "csec-scan-"));
  const HOME = mkdtempSync(join(tmpdir(), "csec-scan-home-"));
  try {
    const git = (...a) => execFileSync("git", ["-C", dir, "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { stdio: "ignore" });
    const run = (...a) => spawnSync(process.execPath, [CLI, "scan", dir, ...a], { encoding: "utf8", env: { ...process.env, HOME, CATARINA_URL: "http://127.0.0.1:9" } });
    git("init", "-q");
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "src", "app.js"), "export const hello = () => 'hi';\n");
    git("add", "."); git("commit", "-qm", "init");
    let r = run();
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stderr, /No secrets found in 1 files/);

    // a key committed, then "removed": still in history
    writeFileSync(join(dir, "src", "pay.js"), `const stripe = "${FAKE["stripe-key"]}";\n`);
    git("add", "."); git("commit", "-qm", "add payments");
    writeFileSync(join(dir, "src", "pay.js"), "const stripe = process.env.STRIPE_KEY;\n");
    git("add", "."); git("commit", "-qm", "use env");
    // a git-ignored .env with a real-looking key
    writeFileSync(join(dir, ".gitignore"), ".env\n");
    writeFileSync(join(dir, ".env"), `OPENAI_API_KEY=${FAKE["openai-key"]}\n`);

    r = run();
    assert.equal(r.status, 1, "high-confidence finding → exit 1");
    assert.match(r.stderr, /OpenAI API key/);
    assert.match(r.stderr, /\.env:1/);
    assert.match(r.stderr, /Early access: https:\/\/secret\.getcatarina\.com\/\?utm_source=csec-scan/, "non-users get one line about the product");
    assert.doesNotMatch(r.stderr, /csec import/, "no vault commands for people without a vault");
    assert.doesNotMatch(r.stderr, /Stripe/, "history is opt-in");
    for (const v of Object.values(FAKE)) assert.ok(!r.stderr.includes(v) && !r.stdout.includes(v), "never prints a full secret");

    r = run("--history");
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Stripe secret key/);
    assert.match(r.stderr, /history: src\/pay\.js \(commit [0-9a-f]{12}\)/);
    assert.match(r.stderr, /Rotate keys found in git history/);
    assert.ok(!r.stderr.includes(FAKE["stripe-key"]));

    r = run("--history", "--json");
    const j = JSON.parse(r.stdout);
    assert.ok(!r.stdout.includes("utm_source"), "JSON output stays clean");
    assert.equal(j.commits, 3);
    assert.deepEqual(j.secrets.map((s) => s.rule).sort(), ["openai-key", "stripe-key"]);
    assert.ok(!r.stdout.includes(FAKE["openai-key"]) && !r.stdout.includes(FAKE["stripe-key"]));

    rmSync(join(dir, ".git"), { recursive: true, force: true });
    assert.match(run("--history").stderr, /--history needs a git repository/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(HOME, { recursive: true, force: true });
  }
});

test("pre-commit hook: blocks a staged secret, allows clean commits, never overwrites a foreign hook", () => {
  const dir = mkdtempSync(join(tmpdir(), "csec-hook-"));
  const HOME = mkdtempSync(join(tmpdir(), "csec-hook-home-"));
  try {
    const env = { ...process.env, HOME, CATARINA_URL: "http://127.0.0.1:9" };
    const git = (...a) => spawnSync("git", ["-C", dir, "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { encoding: "utf8", env });
    const csec = (...a) => spawnSync(process.execPath, [CLI, "scan", dir, ...a], { encoding: "utf8", env });
    git("init", "-q");
    const r0 = csec("--install-hook");
    assert.equal(r0.status, 0, r0.stderr);
    assert.match(r0.stderr, /Installed the pre-commit hook/);

    writeFileSync(join(dir, "a.js"), "export const a = 1;\n");
    git("add", ".");
    assert.equal(git("commit", "-qm", "clean").status, 0, "clean commit passes");

    writeFileSync(join(dir, "b.js"), `const k = "${FAKE["github-token"]}";\n`);
    git("add", ".");
    const blocked = git("commit", "-qm", "leak");
    assert.notEqual(blocked.status, 0, "secret commit is blocked");
    assert.match(blocked.stderr, /GitHub token/);
    assert.match(blocked.stderr, /b\.js:1/);
    assert.match(blocked.stderr, /Commit blocked by csec/);
    assert.ok(!blocked.stderr.includes(FAKE["github-token"]), "hook output is redacted too");

    const j = JSON.parse(csec("--staged", "--json").stdout);
    assert.deepEqual(j.secrets.map((x) => x.rule), ["github-token"]);

    assert.equal(git("commit", "-qm", "leak anyway", "--no-verify").status, 0, "--no-verify still works");

    writeFileSync(join(dir, "c.js"), `const x = 1; // const k = "${FAKE["npm-token"]}"; csec:ignore\n`);
    git("add", ".");
    assert.equal(git("commit", "-qm", "ignored line").status, 0, "csec:ignore lines pass");

    assert.match(csec("--uninstall-hook").stderr, /Removed/);
    writeFileSync(join(dir, ".git", "hooks", "pre-commit"), "#!/bin/sh\necho mine\n", { mode: 0o755 });
    const clash = csec("--install-hook");
    assert.notEqual(clash.status, 0);
    assert.match(clash.stderr, /isn't csec's/);
    assert.match(csec("--uninstall-hook").stderr, /left it alone/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(HOME, { recursive: true, force: true });
  }
});
