// csec scan — find secrets in a project: working files (including git-ignored .env files) and,
// with --history, every line ever added in git. Runs offline; never prints a full secret.

import { readdirSync, statSync, openSync, readSync, closeSync, readFileSync } from "node:fs";
import { join, relative, basename } from "node:path";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";

const SKIP_DIRS = new Set([
  ".git", "node_modules", "vendor", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit", ".turbo",
  ".wrangler", ".vercel", ".cache", "coverage", "venv", ".venv", "__pycache__", ".tox", "target", "Pods", ".gradle", ".idea",
]);
const SKIP_EXT = /\.d\.ts$|\.(png|jpe?g|gif|webp|ico|icns|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|so|dylib|dll|exe|bin|wasm|woff2?|ttf|otf|eot|mp[34]|mov|avi|webm|wav|ogg|sqlite3?|db|lock|min\.js|map)$/i;
const MAX_FILE = 1_000_000;
const MAX_FILES = 50_000;
const MAX_LINE = 4000;

// High confidence: the format alone identifies the provider.
export const RULES = [
  { id: "aws-access-key", name: "AWS access key ID", re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/ },
  { id: "github-token", name: "GitHub token", re: /\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/ },
  { id: "stripe-key", name: "Stripe secret key", re: /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\b/ },
  { id: "anthropic-key", name: "Anthropic API key", re: /\b(sk-ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{40,})/ },
  { id: "openai-key", name: "OpenAI API key", re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}T3BlbkFJ[A-Za-z0-9_-]{16,}|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,})/ },
  { id: "google-api-key", name: "Google API key", re: /\b(AIza[0-9A-Za-z_-]{35})\b/ },
  { id: "slack-token", name: "Slack token", re: /\b(xox[abposr]-[A-Za-z0-9-]{10,})\b/ },
  { id: "slack-webhook", name: "Slack webhook URL", re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{16,})/ },
  { id: "sendgrid-key", name: "SendGrid API key", re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/ },
  { id: "npm-token", name: "npm token", re: /\b(npm_[A-Za-z0-9]{36})\b/ },
  { id: "huggingface-token", name: "Hugging Face token", re: /\b(hf_[A-Za-z0-9]{34,})\b/ },
  { id: "groq-key", name: "Groq API key", re: /\b(gsk_[A-Za-z0-9]{48,})\b/ },
  { id: "digitalocean-token", name: "DigitalOcean token", re: /\b(do[op]_v1_[a-f0-9]{64})\b/ },
  { id: "shopify-token", name: "Shopify access token", re: /\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b/ },
  { id: "twilio-key", name: "Twilio API key", re: /\b(SK[0-9a-f]{32})\b/ },
  { id: "private-key", name: "Private key", re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)/ },
  { id: "database-url", name: "Database URL with password", re: /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^:\s/@"'`]+:([^@\s/"'`]{6,})@[^\s"'`]+)/, secretGroup: 2 },
];

// Medium confidence: a secret-sounding name assigned a random-looking value.
const NAME_RE = /(?:secret|token|api[_-]?key|apikey|password|passwd|pwd|private[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?key|signing[_-]?key|webhook[_-]?secret|credentials?)/i;
const ASSIGN_RE = /([A-Za-z_][A-Za-z0-9_.-]{1,80})["']?\s*(?::|=|:=|=>)\s*(["'`]?)([^\s"'`,;#]{12,256})/g;
// Files where values are written bare (KEY=value). In code, only quoted string literals count.
const CONFIG_FILE = /(?:^|\.)env(?:\..+)?$|^\.dev\.vars(?:\..+)?$|\.(?:ya?ml|toml|ini|cfg|conf|properties|tfvars)$/i;
const JWT_RE = /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/;

const PLACEHOLDER = /^(?:x+|\*+|\.+|-+|_+|0+|1234\d*|changeme|change[_-]?me|todo|tbd|none|null|undefined|true|false|example|sample|dummy|test|placeholder|redacted|secret|password|your[_-].*|my[_-].*|<.*>|\$\{.*\}|\$[A-Z_]+|%.*%|\{\{.*\}\})$/i;
const CODE_REF = /^(?:process\.env|import\.meta\.env|os\.environ|os\.getenv|env\(|getenv|ENV\[|System\.getenv|config\.|settings\.|this\.|self\.|args\.|params\.|props\.|req\.|request\.|options\.|opts\.|input\.|data\.|new |function|await |require\(|[a-zA-Z_]+\()/;

export function entropy(s) {
  const n = new Map();
  for (const ch of s) n.set(ch, (n.get(ch) || 0) + 1);
  let h = 0;
  for (const c of n.values()) { const p = c / s.length; h -= p * Math.log2(p); }
  return h;
}

const looksRandom = (v) => {
  if (PLACEHOLDER.test(v) || CODE_REF.test(v)) return false;
  if (/[(){}[\]<>$\\]/.test(v)) return false; // an expression or a template, not a literal
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(v)) return false; // member access: config.apiKey
  if (/^[a-z]+(?:[_-][a-z]+)*$/i.test(v)) return false; // plain words: "my_database_password"
  if (/^https?:\/\//.test(v) && !/:[^/@]+@/.test(v)) return false; // a URL without credentials
  if (/^[./~]|\.(?:js|ts|json|pem|key|txt|ya?ml)$/i.test(v)) return false; // a path
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(v)).length;
  return entropy(v) >= 3.5 && classes >= 2;
};

// .env files and Cloudflare's .dev.vars hold real values by convention.
export const isEnvFile = (name) => /^\.env(?:\..+)?$|\.env$|^\.dev\.vars(?:\..+)?$/.test(name) && !/\.(example|sample|template|dist|defaults?)$/i.test(name);
const isExampleFile = (name) => /\.(example|sample|template)(\.|$)/i.test(name);

export const redact = (v) => (v.length <= 8 ? "•".repeat(v.length) : `${v.slice(0, 4)}…${v.slice(-2)} (${v.length} chars)`);
const fingerprint = (v) => createHash("sha256").update(v).digest("hex").slice(0, 12);

/** Findings in one line of text. `file` is used for .env / example heuristics. */
export function scanLine(line, file) {
  if (!line || line.includes("csec:ignore")) return [];
  const text = line.length > MAX_LINE ? line.slice(0, MAX_LINE) : line;
  const name = basename(file || "");
  const out = [];
  const seen = new Set();
  const add = (rule, value, confidence) => {
    if (seen.has(value)) return;
    seen.add(value);
    out.push({ rule: rule.id, name: rule.name, confidence, value });
  };
  for (const r of RULES) {
    const m = text.match(r.re);
    if (!m) continue;
    const value = m[r.secretGroup || 1];
    if (r.id === "database-url" && (PLACEHOLDER.test(value) || /^\$|^\{|^</.test(value))) continue;
    add(r, value, "high");
  }
  if (out.length) return out;
  if (isExampleFile(name)) return out; // example files: only provider formats count
  const jwt = text.match(JWT_RE);
  if (jwt) add({ id: "jwt", name: "JSON Web Token" }, jwt[1], "medium");
  for (const m of text.matchAll(ASSIGN_RE)) {
    const [, key, quote, value] = m;
    if (!quote && !CONFIG_FILE.test(name)) continue;
    if (!NAME_RE.test(key) || /(?:_?(?:name|file|path|url|uri|endpoint|length|len|type|id|header|field|env|key_?name)$)/i.test(key)) continue;
    if (!looksRandom(value)) continue;
    add({ id: isEnvFile(name) ? "env-secret" : "generic-secret", name: `Secret in ${key}` }, value, isEnvFile(name) ? "high" : "medium");
  }
  return out;
}

function* walk(root) {
  const stack = [root];
  let count = 0;
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(p); continue; }
      if (!e.isFile() || SKIP_EXT.test(e.name)) continue;
      if (++count > MAX_FILES) return;
      yield p;
    }
  }
}

function readText(p) {
  let st;
  try { st = statSync(p); } catch { return null; }
  if (st.size > MAX_FILE || st.size === 0) return null;
  const fd = openSync(p, "r");
  try {
    const head = Buffer.alloc(Math.min(8000, st.size));
    readSync(fd, head, 0, head.length, 0);
    if (head.includes(0)) return null; // binary
  } finally { closeSync(fd); }
  return readFileSync(p, "utf8");
}

export function scanFiles(root) {
  const findings = [];
  let files = 0;
  for (const p of walk(root)) {
    const text = readText(p);
    if (text == null) continue;
    files++;
    const rel = relative(root, p) || basename(p);
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      for (const f of scanLine(lines[i], rel)) findings.push({ ...f, where: "file", file: rel, line: i + 1 });
    }
  }
  return { findings, files };
}

/** Every line ever added in git history (all branches). Resolves with findings + commit count. */
export const scanHistory = (root) =>
  scanDiff(root, ["log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=commit %H"], "history");

/** Only what is staged for the next commit (the pre-commit hook). */
export const scanStaged = (root) =>
  scanDiff(root, ["diff", "--cached", "-U0", "--no-color", "--no-ext-diff"], "staged");

function scanDiff(root, gitArgs, where) {
  return new Promise((resolve, reject) => {
    const git = spawn("git", ["-C", root, ...gitArgs], { stdio: ["ignore", "pipe", "pipe"] });
    const findings = [];
    let commit = null, file = null, commits = 0, buf = "", err = "", newLine = 0;
    const handle = (line) => {
      if (line.startsWith("commit ")) { commit = line.slice(7, 19); commits++; return; }
      if (line.startsWith("+++ ")) { file = line.startsWith("+++ b/") ? line.slice(6) : null; return; }
      const hunk = line.match(/^@@ -\S+ \+(\d+)/);
      if (hunk) { newLine = Number(hunk[1]); return; }
      if (!file || !line.startsWith("+") || line.startsWith("+++")) return;
      const at = newLine++;
      if (SKIP_EXT.test(file) || file.split("/").some((part) => SKIP_DIRS.has(part))) return;
      for (const f of scanLine(line.slice(1), file)) findings.push({ ...f, where, file, commit, line: at });
    };
    git.stdout.setEncoding("utf8");
    git.stdout.on("data", (d) => { buf += d; const parts = buf.split("\n"); buf = parts.pop(); for (const l of parts) handle(l); });
    git.stderr.on("data", (d) => (err += d));
    git.on("error", reject);
    git.on("close", (code) => {
      if (buf) handle(buf);
      if (code !== 0) return reject(new Error(err.trim().split("\n")[0] || `git exited ${code}`));
      resolve({ findings, commits });
    });
  });
}

/** Group findings by secret value so one key found in 5 places is one row. Values are dropped here. */
export function summarize(findings) {
  const groups = new Map();
  for (const f of findings) {
    const fp = fingerprint(f.value);
    let g = groups.get(fp);
    if (!g) { g = { fingerprint: fp, rule: f.rule, name: f.name, confidence: f.confidence, preview: redact(f.value), places: [] }; groups.set(fp, g); }
    if (f.confidence === "high") g.confidence = "high";
    const place = f.where === "history" ? { where: "history", file: f.file, commit: f.commit } : { where: f.where, file: f.file, line: f.line };
    if (!g.places.some((p) => p.where === place.where && p.file === place.file && p.line === place.line && p.commit === place.commit)) g.places.push(place);
  }
  return [...groups.values()].sort((a, b) => (a.confidence === b.confidence ? 0 : a.confidence === "high" ? -1 : 1));
}
