#!/usr/bin/env node
// csec — Catarina Secrets CLI. No dependencies; Node 22+.
// Device keys live in the macOS Keychain (or a 0600 file elsewhere). Secrets are decrypted
// in memory for each command and never written to disk.

import { spawn, execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { hostname, homedir, platform, constants as osConstants } from "node:os";
import { mkdirSync, readFileSync, writeFileSync, rmSync, existsSync, realpathSync } from "node:fs";
import { join, relative, basename } from "node:path";
import * as C from "./crypto.js";
import { scanFiles, scanHistory, scanStaged, summarize, isEnvFile } from "./scan.js";

const BASE = (process.env.CATARINA_URL || "https://secret.getcatarina.com").replace(/\/$/, "");
const HOST = new URL(BASE).host;
const SERVICE = "catarina-secrets";
const ACCOUNT = `device@${HOST}`;
const te = new TextEncoder();

const out = (s = "") => process.stderr.write(s + "\n"); // status → stderr, data → stdout
let MCP_MODE = false; // in `csec mcp`, errors become tool errors instead of exiting the server
class CliError extends Error {}
const die = (s, code = 1) => { if (MCP_MODE) throw new CliError(s); out(`✗ ${s}`); process.exit(code); };

// ---------- key storage ----------
const isMac = platform() === "darwin";
const fileStore = join(homedir(), ".config", "catarina", `${HOST.replace(/[^\w.-]/g, "_")}.json`);

// Tests only: CSEC_TEST_FILE_STORE=1 keeps keys in $HOME/.config/catarina instead of the Keychain,
// and is honoured only for a localhost server, so it can't weaken a real installation.
const FILE_STORE = !isMac || (process.env.CSEC_TEST_FILE_STORE === "1" && /^(localhost|127\.0\.0\.1)(:\d+)?$/.test(HOST));

const ACCESS_ACCOUNT = `access@${HOST}`;
const fileFor = (account) => (account === ACCOUNT ? fileStore : fileStore.replace(/\.json$/, ".access.json"));

function storeSave(account, label, obj) {
  const data = JSON.stringify(obj);
  if (!FILE_STORE) {
    // `security -i` reads the command from stdin, so the value never appears in the process list.
    const hex = Buffer.from(data, "utf8").toString("hex");
    execFileSync("security", ["-i"], { input: `add-generic-password -U -s ${SERVICE} -a ${account} -l "${label}" -X ${hex}\n`, stdio: ["pipe", "ignore", "pipe"] });
  } else {
    mkdirSync(join(homedir(), ".config", "catarina"), { recursive: true, mode: 0o700 });
    writeFileSync(fileFor(account), data, { mode: 0o600 });
  }
}
function storeLoad(account) {
  try {
    const raw = !FILE_STORE
      ? execFileSync("security", ["find-generic-password", "-s", SERVICE, "-a", account, "-w"], { stdio: ["ignore", "pipe", "ignore"] }).toString().trim()
      : existsSync(fileFor(account)) ? readFileSync(fileFor(account), "utf8") : "";
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
function storeDelete(account) {
  if (!FILE_STORE) { try { execFileSync("security", ["delete-generic-password", "-s", SERVICE, "-a", account], { stdio: "ignore" }); } catch {} }
  else rmSync(fileFor(account), { force: true });
}
const saveDevice = (obj) => storeSave(ACCOUNT, "Catarina Secrets device key", obj);
const loadDevice = () => storeLoad(ACCOUNT);
const deleteDevice = () => storeDelete(ACCOUNT);

// ---------- Touch ID (Secure Enclave) protection for device keys ----------
// The device's private keys are encrypted to a P-256 key that lives inside the Secure Enclave and
// can only be used after Touch ID / the Mac password. Sealing needs no prompt (ECDH with the public
// key); unsealing needs the Secure Enclave, so a process that copies the Keychain item gets nothing.

const SE_SOURCE = new URL("./se-helper.swift", import.meta.url);
const SE_WRAP = "catarina/v1/se-wrap";

async function seHelper() {
  if (!isMac) return null;
  const src = readFileSync(SE_SOURCE);
  const tag = Buffer.from(await crypto.subtle.digest("SHA-256", src)).toString("hex").slice(0, 12);
  const dir = join(homedir(), ".config", "catarina", "bin");
  const bin = join(dir, `csec-se-${tag}`);
  if (!existsSync(bin)) {
    out("… Building the Touch ID helper (one time, ~30 s)");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    try { execFileSync("swiftc", ["-O", SE_SOURCE.pathname, "-o", bin], { stdio: ["ignore", "ignore", "pipe"] }); }
    catch (e) { out(`! Could not build the Touch ID helper (${String(e.stderr || e.message).split("\n")[0]}). Install Xcode Command Line Tools: xcode-select --install`); return null; }
  }
  return bin;
}

async function seWrapKey(shared, ephPub, deviceId) {
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: ephPub, info: te.encode(`${SE_WRAP}/${deviceId}`) },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

/** Encrypt the device's private keys to a new Secure Enclave key. Returns the sealed record, or null. */
async function sealDevice(dev) {
  const bin = await seHelper();
  if (!bin) return null;
  let se;
  try { se = JSON.parse(execFileSync(bin, ["create"], { stdio: ["ignore", "pipe", "pipe"] }).toString()); }
  catch (e) { out(`! Secure Enclave unavailable (${String(e.stderr || e.message).trim()}).`); return null; }
  const sePub = await crypto.subtle.importKey("raw", Buffer.from(se.pub, "base64"), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: sePub }, eph.privateKey, 256));
  const ephPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey)); // X9.63 uncompressed
  const key = await seWrapKey(shared, ephPub, dev.device_id);
  shared.fill(0);
  const iv = C.rand(12);
  const secret = te.encode(JSON.stringify({ sign_priv: dev.sign_priv, enc_priv: dev.enc_priv }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(`${SE_WRAP}/${dev.device_id}`) }, key, secret));
  const { sign_priv, enc_priv, ...pub } = dev;
  return { ...pub, v: 2, sealed: true, se_blob: se.blob, eph_pub: Buffer.from(ephPub).toString("base64"), iv: C.toB64u(iv), ct: C.toB64u(ct) };
}

/** Return the device with usable private keys. Shows Touch ID if the keys are sealed. */
async function unlockDevice(rec, reason) {
  if (!rec.sealed) return rec;
  const bin = await seHelper();
  if (!bin) die("The Touch ID helper is missing and couldn't be built.");
  let shared;
  try {
    const outp = execFileSync(bin, ["derive", "--reason", reason], { input: JSON.stringify({ blob: rec.se_blob, peer: rec.eph_pub }), stdio: ["pipe", "pipe", "pipe"] });
    shared = new Uint8Array(Buffer.from(JSON.parse(outp.toString()).shared, "base64"));
  } catch (e) {
    if (e.status === 3) die("Touch ID was cancelled.");
    die(`Touch ID check failed (${String(e.stderr || e.message).trim()}).`);
  }
  const key = await seWrapKey(shared, new Uint8Array(Buffer.from(rec.eph_pub, "base64")), rec.device_id);
  shared.fill(0);
  let pt;
  try {
    pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: C.fromB64u(rec.iv), additionalData: te.encode(`${SE_WRAP}/${rec.device_id}`) }, key, C.fromB64u(rec.ct));
  } catch {
    die("Couldn't unseal this device's keys (the Keychain item was modified or belongs to another Secure Enclave key). Re-link: csec logout && csec login");
  }
  return { ...rec, ...JSON.parse(new TextDecoder().decode(pt)) };
}

async function touchid(args) {
  const sub = args[0] || "status";
  const rec = loadDevice();
  if (!rec) die("Not linked. Run: csec login");
  if (sub === "status") return out(rec.sealed ? "✓ Touch ID required: device keys are sealed by the Secure Enclave." : "! Touch ID is OFF: device keys are readable by any process running as you. Turn on: csec touchid on");
  if (sub === "on") {
    if (rec.sealed) return out("Already on.");
    const sealed = await sealDevice(rec);
    if (!sealed) die("Could not turn on Touch ID protection.");
    saveDevice(sealed);
    out("✓ Touch ID is on. csec will ask for your fingerprint before using secrets.");
    out("  Your old keys were stored unprotected until now. To be sure no copy survives, re-link: csec logout && csec login");
    return;
  }
  if (sub === "off") {
    if (!rec.sealed) return out("Already off.");
    const dev = await unlockDevice(rec, "turn off Touch ID protection for csec");
    const { v, sealed, se_blob, eph_pub, iv, ct, ...plain } = dev;
    saveDevice(plain);
    return out("✓ Touch ID protection turned off.");
  }
  die("Usage: csec touchid [status|on|off]");
}

// ---------- Cloudflare Access service token ----------
// Access protects /api/device with a service token (in addition to device signatures).
// Stored once with `csec access-token`; env vars override it.
function accessHeaders() {
  const saved = storeLoad(ACCESS_ACCOUNT) || {};
  const id = process.env.CATARINA_ACCESS_CLIENT_ID || saved.id;
  const secret = process.env.CATARINA_ACCESS_CLIENT_SECRET || saved.secret;
  return id && secret ? { "CF-Access-Client-Id": id, "CF-Access-Client-Secret": secret } : {};
}
const ACCESS_BLOCKED = "Blocked by Cloudflare Access. Save the service token first: csec access-token";

// ---------- signed HTTP ----------
async function sha256Hex(text) {
  const d = await crypto.subtle.digest("SHA-256", te.encode(text));
  return Buffer.from(d).toString("hex");
}
async function signedFetch(dev, path, method = "GET", body) {
  const bodyText = body ? JSON.stringify(body) : "";
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = C.toB64u(C.rand(16));
  const canonical = ["catarina-v1", method, path, ts, nonce, await sha256Hex(bodyText)].join("\n");
  const key = await crypto.subtle.importKey("pkcs8", C.fromB64u(dev.sign_priv), { name: "Ed25519" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, te.encode(canonical)));
  const res = await fetch(BASE + path, {
    method,
    redirect: "manual",
    headers: {
      ...accessHeaders(),
      "X-Catarina-Device": dev.device_id, "X-Catarina-Ts": ts, "X-Catarina-Nonce": nonce, "X-Catarina-Sig": C.toB64u(sig),
      ...(bodyText ? { "Content-Type": "application/json" } : {}),
    },
    body: bodyText || undefined,
  });
  if ((res.status >= 300 && res.status < 400) || res.status === 403 && !res.headers.get("content-type")?.includes("json")) die(ACCESS_BLOCKED);
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

// ---------- rollback / tamper detection ----------
// This computer remembers the highest signed-manifest number it has seen (see crypto.js), so the
// server can't hand it an older copy of the vault, or drop or swap items, without a warning.
const seenFile = fileStore.replace(/\.json$/, ".seen.json");
function seenGet(deviceId) {
  try { return Number(JSON.parse(readFileSync(seenFile, "utf8"))[deviceId]) || 0; } catch { return 0; }
}
function seenSet(deviceId, n) {
  if (n <= seenGet(deviceId)) return;
  try {
    mkdirSync(join(homedir(), ".config", "catarina"), { recursive: true, mode: 0o700 });
    writeFileSync(seenFile, JSON.stringify({ [deviceId]: n }), { mode: 0o600 });
  } catch { /* read-only home: no memory, no crash */ }
}
const INTEGRITY_TEXT = {
  rollback: "the server sent an older copy of your vault than this computer has already seen",
  mismatch: "the vault's contents don't match the signature your own devices wrote",
  missing: "the server dropped the signature your devices keep on this vault",
};

/** Write that changes items: signs the item rows as they will be after it, then sends it. */
async function signedItemWrite(ctx, path, body, rows) {
  const manifest = await C.signManifest(ctx.manKey, (ctx.raw.manifest ? ctx.raw.manifest.n : 0) + 1, rows);
  const r = await signedFetch(ctx.dev, path, "POST", { ...body, manifest });
  if (r.status === 200) {
    ctx.raw.manifest = manifest;
    ctx.raw.items = rows;
    seenSet(ctx.dev.device_id, manifest.n);
  }
  return r;
}

// ---------- vault access ----------
async function openVault(reason, unlocked) {
  const rec = unlocked || loadDevice();
  if (!rec) die("This computer isn't linked. Run: csec login");
  const dev = unlocked || (await unlockDevice(rec, reason || "use your Catarina secrets"));
  const { status, data } = await signedFetch(dev, "/api/device/vault");
  if (status === 401) die(`Access denied (${data.error}). The device may have been revoked. Run: csec login`);
  if (status !== 200) die(`Server error (${status} ${data.error || ""})`);
  const encPriv = await crypto.subtle.importKey("pkcs8", C.fromB64u(dev.enc_priv), { name: "X25519" }, false, ["deriveBits"]);
  const vkRaw = await C.unwrapVaultKeyForDevice(encPriv, dev.enc_pub, data.wrap, dev.device_id);
  const vk = await C.importVaultKey(vkRaw);
  const macKey = await C.backupMacKey(vkRaw);
  const manKey = await C.manifestKey(vkRaw);
  vkRaw.fill(0);
  const check = await C.checkManifest(manKey, data.manifest || null, data.items, seenGet(dev.device_id));
  if (INTEGRITY_TEXT[check]) {
    out(`! Warning: ${INTEGRITY_TEXT[check]}. Secrets may be out of date or changed.`);
    out("  Check them in the vault page before relying on them, and report it to security@getcatarina.com.");
  } else if (data.manifest) seenSet(dev.device_id, data.manifest.n);
  const items = [];
  for (const it of data.items) {
    try { items.push({ ...(await C.decryptItem(vk, it.id, it.blob)), id: it.id, version: it.version }); }
    catch { out(`! Skipped item ${it.id.slice(0, 8)}: decryption failed (tampered?)`); }
  }
  const trash = [];
  for (const it of data.trash || []) {
    try { trash.push({ ...(await C.decryptItem(vk, it.id, it.blob)), id: it.id, version: it.version, deleted_at: it.deleted_at, deleted_by: it.deleted_by }); }
    catch { /* unreadable trash entry: ignore */ }
  }
  return { dev, vk, macKey, manKey, items, trash, raw: data };
}

/** Encrypt on this device and upload. entries: [{ existing?: item, data: {name, value, notes, project, env} }] */
/** A decrypted item minus what openVault adds, so fields this CLI doesn't know (tags from the vault page) survive. */
function keepFields(existing) {
  if (!existing) return {};
  const { id, version, ...data } = existing;
  return data;
}
async function putItems(ctx, entries) {
  const payload = [];
  for (const e of entries) {
    const id = e.existing ? e.existing.id : crypto.randomUUID();
    payload.push({ id, expected_version: e.existing ? e.existing.version : 0, blob: await C.encryptItem(ctx.vk, id, e.data) });
  }
  for (let i = 0; i < payload.length; i += 100) {
    const chunk = payload.slice(i, i + 100);
    const rows = C.itemsAfter(ctx.raw.items, { put: chunk.map((p) => ({ id: p.id, version: p.expected_version + 1, blob: p.blob })) });
    const { status, data } = await signedItemWrite(ctx, "/api/device/items", { items: chunk }, rows);
    if (status === 409) die("A secret changed on another device while saving. Run the command again.");
    if (status !== 200) die(`Save failed (${status} ${data.error || ""}).`);
  }
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SLUG = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const CONFIG_FILE = ".csec.json";

// ---------- project / environment scope ----------
function takeFlag(args, names, isBool = false) {
  const i = args.findIndex((a) => names.includes(a));
  if (i < 0) return isBool ? false : undefined;
  if (isBool) { args.splice(i, 1); return true; }
  const v = args[i + 1];
  if (v === undefined || v.startsWith("-")) die(`${names[0]} needs a value`);
  args.splice(i, 2);
  return v;
}
function findConfig(dir = process.cwd()) {
  for (let d = dir; ; d = join(d, "..")) {
    const f = join(d, CONFIG_FILE);
    if (existsSync(f)) {
      try { return { path: f, ...JSON.parse(readFileSync(f, "utf8")) }; } catch { die(`${f} is not valid JSON.`); }
    }
    if (d === join(d, "..")) return null;
  }
}
/** Resolve which project/env a command uses: flags > env vars > .csec.json > defaults. */
function resolveScope(args) {
  const cfg = findConfig();
  const project = (takeFlag(args, ["--project", "-p"]) ?? (process.env.CSEC_PROJECT || undefined) ?? (cfg && cfg.project) ?? "").toLowerCase();
  const env = (takeFlag(args, ["--env", "-e"]) ?? (process.env.CSEC_ENV || undefined) ?? (cfg && cfg.env) ?? "dev").toLowerCase();
  if (project && !SLUG.test(project)) die(`Invalid project name "${project}" (use a-z, 0-9, - and _).`);
  if (!SLUG.test(env)) die(`Invalid environment "${env}".`);
  return { project, env, label: `${project || "(no project)"} / ${env}`, cfg };
}
const projOf = (it) => it.project || "";
const envOf = (it) => it.env || "";
/** Secrets for a project+env. Items with no env apply to every env; an env-specific item wins over them. */
function inScope(items, scope) {
  const byName = new Map();
  for (const it of items) {
    if (projOf(it) !== scope.project || (envOf(it) && envOf(it) !== scope.env)) continue;
    const prev = byName.get(it.name);
    if (!prev || (!envOf(prev) && envOf(it))) byName.set(it.name, it);
  }
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

// ---------- input helpers ----------
async function readStdinAll() {
  let s = "";
  for await (const c of process.stdin) s += c;
  return s;
}
async function readHidden(prompt) {
  if (!process.stdin.isTTY) return (await readStdinAll()).replace(/\r?\n$/, "");
  process.stderr.write(prompt);
  return new Promise((resolve) => {
    const stdin = process.stdin;
    let v = "";
    const onData = (chunk) => {
      for (const c of chunk) {
        if (c === "\r" || c === "\n") { stdin.setRawMode(false); stdin.pause(); stdin.off("data", onData); process.stderr.write("\n"); return resolve(v); }
        if (c === "\u0003") { stdin.setRawMode(false); process.stderr.write("\n"); process.exit(130); }
        if (c === "\u007f" || c === "\b") v = v.slice(0, -1);
        else v += c;
      }
    };
    stdin.setRawMode(true);
    stdin.setEncoding("utf8");
    stdin.resume();
    stdin.on("data", onData);
  });
}
async function confirm(question) {
  if (!process.stdin.isTTY) return false;
  const rl = (await import("node:readline/promises")).createInterface({ input: process.stdin, output: process.stderr });
  const a = await rl.question(`${question} [y/N] `);
  rl.close();
  return /^y(es)?$/i.test(a.trim());
}

/** Minimal .env parser: KEY=value, export prefix, # comments, single/double quotes, multi-line double quotes. */
function parseDotenv(text) {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const entries = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.replace(/^export\s+/, "").match(/^([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/);
    if (!m) { out(`! Line ${i + 1} skipped (not KEY=value)`); continue; }
    let [, key, val] = m;
    if (val.startsWith('"')) {
      let buf = val.slice(1);
      while (!/(^|[^\\])"\s*(#.*)?$/.test(buf) && i + 1 < lines.length) buf += "\n" + lines[++i];
      val = buf.replace(/"\s*(#.*)?$/, "").replace(/\\n/g, "\n").replace(/\\"/g, '"').replace(/\\\\/g, "\\");
    } else if (val.startsWith("'")) {
      val = val.replace(/^'([^']*)'.*$/, "$1");
    } else {
      val = val.replace(/\s+#.*$/, "").trim();
    }
    entries.push({ key, value: val });
  }
  return entries;
}

// ---------- commands ----------
async function login(args) {
  const noTouch = takeFlag(args, ["--no-touchid"], true);
  const nameIdx = args.indexOf("--name");
  const name = (nameIdx >= 0 ? args[nameIdx + 1] : `${hostname().replace(/\.local$/, "")} (CLI)`).slice(0, 64);
  if (loadDevice()) out("! This computer is already linked. Linking again replaces its keys.");

  const sign = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const enc = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const sign_pub = C.toB64u(new Uint8Array(await crypto.subtle.exportKey("raw", sign.publicKey)));
  const enc_pub = C.toB64u(new Uint8Array(await crypto.subtle.exportKey("raw", enc.publicKey)));
  const sign_priv = C.toB64u(new Uint8Array(await crypto.subtle.exportKey("pkcs8", sign.privateKey)));
  const enc_priv = C.toB64u(new Uint8Array(await crypto.subtle.exportKey("pkcs8", enc.privateKey)));

  const res = await fetch(`${BASE}/api/device/enroll`, {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/json", ...accessHeaders() },
    body: JSON.stringify({ name, sign_pub, enc_pub }),
  });
  if ((res.status >= 300 && res.status < 400) || res.status === 403) die(ACCESS_BLOCKED);
  if (res.status !== 200) die(`Could not start login (${res.status}).`);
  const { id, code, expires_in } = await res.json();
  const fp = await C.deviceFingerprint(sign_pub, enc_pub);

  out("");
  out(`  Open ${BASE}/vault/ → Devices → Approve a device`);
  out("");
  out(`  Pairing code:  ${code}`);
  out(`  Fingerprint:   ${fp}`);
  out(`  Device name:   ${name}`);
  out("");
  out("  Approve only if the fingerprint in the browser matches this one.");
  out(`  Waiting for approval (expires in ${Math.round(expires_in / 60)} min)…`);

  const pending = { device_id: id, sign_priv, sign_pub, enc_priv, enc_pub, name };
  const deadline = Date.now() + expires_in * 1000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 2500));
    const { status, data } = await signedFetch(pending, `/api/device/enroll/${id}`);
    if (status === 200 && data.status === "approved") {
      const full = { ...pending, server: BASE, linked_at: new Date().toISOString() };
      const { items } = await openVault(null, full); // proves the wrapped key decrypts on this device
      const sealed = !noTouch && isMac ? await sealDevice(full) : null;
      saveDevice(sealed || full);
      out(`✓ Linked. ${items.length} secret(s) available. Keys stored in ${FILE_STORE ? fileStore : "the macOS Keychain"}.`);
      out(sealed ? "✓ Touch ID required: keys are sealed by the Secure Enclave." : "! Touch ID protection is off (any process running as you can use these keys).");
      return;
    }
    if (status === 200 && data.status === "expired") break;
    if (status !== 200 && status !== 429) die(`Login failed (${status} ${data.error || ""}).`);
  }
  die("Pairing code expired. Run csec login again.");
}

async function list(args) {
  const all = takeFlag(args, ["--all", "-a"], true);
  const scope = resolveScope(args);
  const { items } = await openVault("list your secrets");
  if (all) {
    if (!items.length) return out("No secrets in the vault.");
    const rows = items.map((it) => [projOf(it) || "-", envOf(it) || "(all)", it.name + tagText(it)])
      .sort((a, b) => a.join("\0").localeCompare(b.join("\0")));
    const w0 = Math.max(7, ...rows.map((r) => r[0].length)), w1 = Math.max(3, ...rows.map((r) => r[1].length));
    process.stdout.write(`${"PROJECT".padEnd(w0)}  ${"ENV".padEnd(w1)}  NAME\n`);
    for (const r of rows) process.stdout.write(`${r[0].padEnd(w0)}  ${r[1].padEnd(w1)}  ${r[2]}\n`);
    return;
  }
  const scoped = inScope(items, scope);
  out(`${scope.label}: ${scoped.length} secret(s)${scope.project ? "" : "  (tip: csec init <project>, or csec list --all)"}`);
  for (const it of scoped) process.stdout.write(`${it.name}${envOf(it) ? "" : "   (all envs)"}${ENV_NAME.test(it.name) ? "" : "   (not a valid env var name)"}${tagText(it)}\n`);
}
/** Tags set in the vault page, shown as "   #billing #stripe". */
function tagText(it) {
  const tags = Array.isArray(it.tags) ? it.tags.filter((t) => typeof t === "string" && /^[a-z0-9][a-z0-9_-]{0,23}$/.test(t)) : [];
  return tags.length ? "   " + tags.map((t) => "#" + t).join(" ") : "";
}

async function get(args) {
  const scope = resolveScope(args);
  const name = args[0];
  if (!name) die("Usage: csec get NAME [-p project] [-e env]");
  const it = inScope((await openVault(`read ${name} (${scope.label})`)).items, scope).find((x) => x.name === name);
  if (!it) die(`No secret named ${name} in ${scope.label}.`);
  process.stdout.write(it.value + (process.stdout.isTTY ? "\n" : ""));
}

async function run(args) {
  const sep = args.indexOf("--");
  const own = sep >= 0 ? args.slice(0, sep) : [];
  const cmd = sep >= 0 ? args.slice(sep + 1) : args;
  const scope = resolveScope(own);
  if (!cmd.length) die("Usage: csec run [-p project] [-e env] -- <command> [args…]");
  const scoped = inScope((await openVault(`run "${cmd.join(" ").slice(0, 60)}" with ${scope.label} secrets`)).items, scope);
  const env = { ...process.env };
  let n = 0;
  for (const it of scoped) {
    if (!ENV_NAME.test(it.name)) continue;
    env[it.name] = it.value;
    n++;
  }
  out(`✓ ${n} secret(s) from ${scope.label} injected into the process (nothing written to disk)`);
  const child = spawn(cmd[0], cmd.slice(1), { stdio: "inherit", env });
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, () => child.kill(sig));
  child.on("error", (e) => die(`Could not start ${cmd[0]}: ${e.message}`, 127));
  child.on("exit", (code, signal) => process.exit(signal ? 128 + (osConstants.signals[signal] || 1) : code ?? 0));
}

/** Parse --type/--length (shared by `gen` and `set --generate`). */
function genOptions(args) {
  const type = takeFlag(args, ["--type", "-t"]) ?? "password";
  const length = Number(takeFlag(args, ["--length", "-l"]) ?? C.SECRET_LEN.default);
  if (!C.SECRET_TYPES[type]) die(`--type must be one of: ${Object.keys(C.SECRET_TYPES).join(", ")}`);
  if (!Number.isInteger(length) || length < C.SECRET_LEN.min || length > C.SECRET_LEN.max) die(`--length must be ${C.SECRET_LEN.min}-${C.SECRET_LEN.max}`);
  return { type, length };
}

async function gen(args) {
  const { type, length } = genOptions(args);
  if (args.length) die("Usage: csec gen [--type password|alnum|hex|b64u] [--length 32]");
  process.stdout.write(C.generateSecret(type, length) + (process.stdout.isTTY ? "\n" : ""));
  if (process.stdout.isTTY) process.stderr.write(`(${C.secretBits(type, length)} bits. To store one without ever showing it: csec set NAME --generate)\n`);
}

async function set(args) {
  const allEnvs = takeFlag(args, ["--all-envs"], true);
  const generate = takeFlag(args, ["--generate", "-g"], true);
  const genOpts = generate ? genOptions(args) : null;
  const scope = resolveScope(args);
  const name = args[0];
  if (!name || !ENV_NAME.test(name) || args.length > 1) die("Usage: csec set NAME [-p project] [-e env] [--all-envs] [--generate [--type T] [--length N]]   (value is read from stdin or a hidden prompt)");
  const env = allEnvs ? "" : scope.env;
  const value = generate
    ? C.generateSecret(genOpts.type, genOpts.length)
    : await readHidden(`Value for ${name} (${scope.project || "(no project)"} / ${env || "all envs"}, input hidden): `);
  if (!value) die("Empty value, nothing saved.");
  const ctx = await openVault(`save ${name} (${scope.project || "no project"} / ${env || "all envs"})`);
  const existing = ctx.items.find((it) => it.name === name && projOf(it) === scope.project && envOf(it) === env);
  await putItems(ctx, [{ existing, data: { ...keepFields(existing), name, value, notes: existing ? existing.notes || "" : "", project: scope.project, env } }]);
  out(`✓ ${existing ? "Updated" : "Saved"} ${name} in ${scope.project || "(no project)"} / ${env || "all envs"}.${generate ? ` Generated ${genOpts.length}-char ${genOpts.type} (≈${C.secretBits(genOpts.type, genOpts.length)} bits), not shown.` : ""}`);
}

// ---------- backup ----------
async function backup(args) {
  const outFlag = takeFlag(args, ["--out", "-o"]);
  if (args.length) die("Usage: csec backup [-o file]   (writes one encrypted file; restore it in the vault page)");
  const ctx = await openVault("create an encrypted backup");
  const { unlockers, items, trash } = ctx.raw;
  if (!unlockers || !unlockers.some((u) => u.kind === "recovery")) die("The server didn't return the vault's unlock methods. Update the server, then try again.");
  const file = outFlag || `catarina-backup-${new Date().toISOString().slice(0, 10)}.json`;
  if (existsSync(file) && !outFlag) die(`${file} already exists. Choose another name with -o.`);
  const b = await C.makeBackup(ctx.macKey, { source: BASE, unlockers, items, trash: trash || [] });
  writeFileSync(file, JSON.stringify(b, null, 1) + "\n", { mode: 0o600 });
  const r = await signedFetch(ctx.dev, "/api/device/backup-event", "POST", { items: items.length });
  if (r.status !== 200) out(`! Backup written, but recording it on the server failed (${r.status}).`);
  out(`✓ Encrypted backup: ${file} (${items.length} secret(s), ${(trash || []).length} in the trash)`);
  out("  Restore it in the vault page with the recovery key that is current today. After a vault key");
  out("  rotation this file needs the OLD recovery key, so make a new backup after rotating.");
  out("  Keep it somewhere other than this computer.");
}

// ---------- delete / trash / restore ----------
const TRASH_DAYS = 30;
const scopeName = (it) => `${projOf(it) || "(no project)"} / ${envOf(it) || "all envs"}`;
const daysLeft = (iso) => Math.max(0, Math.ceil((Date.parse(iso) + TRASH_DAYS * 86400_000 - Date.now()) / 86400_000));

/** Find one entry by exact scope (like `set`): NAME [-p] [-e] [--all-envs]. */
function exactMatches(list, name, scope, allEnvs) {
  const env = allEnvs ? "" : scope.env;
  return list.filter((it) => it.name === name && projOf(it) === scope.project && envOf(it) === env);
}

async function del(args) {
  const allEnvs = takeFlag(args, ["--all-envs"], true);
  const scope = resolveScope(args);
  const name = args[0];
  if (!name || args.length > 1) die("Usage: csec delete NAME [-p project] [-e env] [--all-envs]   (moves it to the trash for 30 days)");
  const ctx = await openVault(`delete ${name}`);
  const [it] = exactMatches(ctx.items, name, scope, allEnvs);
  if (!it) {
    const hint = !allEnvs && exactMatches(ctx.items, name, scope, true).length ? ` It exists for all envs: add --all-envs.` : "";
    die(`No secret named ${name} in ${scope.project || "(no project)"} / ${allEnvs ? "all envs" : scope.env}.${hint}`);
  }
  const { status, data } = await signedItemWrite(ctx, "/api/device/items/delete", { items: [{ id: it.id, expected_version: it.version }] },
    C.itemsAfter(ctx.raw.items, { remove: [it.id] }));
  if (status === 409) die("That secret changed on another device. Run the command again.");
  if (status !== 200) die(`Delete failed (${status} ${data.error || ""}).`);
  out(`✓ Moved ${name} (${scopeName(it)}) to the trash. Restore within ${TRASH_DAYS} days: csec restore ${name}${allEnvs ? " --all-envs" : ""}`);
}

async function trash() {
  const ctx = await openVault("list the trash");
  if (!ctx.trash.length) return out("Trash is empty.");
  out(`${ctx.trash.length} item(s) in the trash (deleted items are kept ${TRASH_DAYS} days):`);
  for (const t of ctx.trash) {
    const when = new Date(t.deleted_at).toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
    process.stdout.write(`${t.id.slice(0, 8)}  ${t.name.padEnd(24)} ${scopeName(t).padEnd(28)} deleted ${when}, ${daysLeft(t.deleted_at)} day(s) left\n`);
  }
}

/** Pick a trashed entry by id prefix, or by name (+ scope flags); the most recently deleted wins. */
function pickTrashed(ctx, args, allEnvs, scope) {
  const key = args[0];
  if (/^[0-9a-f]{8,36}$/.test(key) && !ctx.trash.some((t) => t.name === key)) {
    const m = ctx.trash.filter((t) => t.id.startsWith(key));
    if (m.length !== 1) die(m.length ? "That ID prefix matches several items; use more characters." : "Nothing in the trash with that ID.");
    return m[0];
  }
  let m = exactMatches(ctx.trash, key, scope, allEnvs);
  if (!m.length) {
    const any = ctx.trash.filter((t) => t.name === key);
    if (any.length === 1) m = any; // unambiguous: restore it wherever it was
    else if (any.length > 1) die(`${key} is in the trash in several places. Pick one by ID:\n` + any.map((t) => `  ${t.id.slice(0, 8)}  ${scopeName(t)}`).join("\n"));
    else die(`No ${key} in the trash. See: csec trash`);
  }
  return m[0]; // newest first
}

async function restore(args) {
  const allEnvs = takeFlag(args, ["--all-envs"], true);
  const replace = takeFlag(args, ["--replace"], true);
  const scope = resolveScope(args);
  if (args.length !== 1) die("Usage: csec restore NAME|ID [-p project] [-e env] [--all-envs] [--replace]");
  const ctx = await openVault(`restore ${args[0]}`);
  const t = pickTrashed(ctx, args, allEnvs, scope);
  const live = ctx.items.find((it) => it.name === t.name && projOf(it) === projOf(t) && envOf(it) === envOf(t));
  if (live && !replace) die(`${t.name} already exists in ${scopeName(t)}. Use --replace to move the current one to the trash and restore this one.`);
  if (live) {
    const r = await signedItemWrite(ctx, "/api/device/items/delete", { items: [{ id: live.id, expected_version: live.version }] },
      C.itemsAfter(ctx.raw.items, { remove: [live.id] }));
    if (r.status !== 200) die(`Could not move the current ${t.name} to the trash (${r.status} ${r.data.error || ""}).`);
  }
  const raw = (ctx.raw.trash || []).find((x) => x.id === t.id);
  const { status, data } = await signedItemWrite(ctx, "/api/device/trash/restore", { id: t.id },
    C.itemsAfter(ctx.raw.items, { put: [{ id: t.id, version: raw.version + 1, blob: raw.blob }] }));
  if (status === 409) die("The vault changed on another device. Run the command again.");
  if (status !== 200) die(`Restore failed (${status} ${data.error || ""}).`);
  out(`✓ Restored ${t.name} in ${scopeName(t)}.${live ? " The previous value is now in the trash." : ""}`);
}

async function purge(args) {
  const allEnvs = takeFlag(args, ["--all-envs"], true);
  const yes = takeFlag(args, ["--yes", "-y"], true);
  const scope = resolveScope(args);
  if (args.length !== 1) die("Usage: csec purge NAME|ID [--yes]   (deletes a trashed item forever)");
  const ctx = await openVault(`permanently delete ${args[0]}`);
  const t = pickTrashed(ctx, args, allEnvs, scope);
  if (!yes && !(await confirm(`Permanently delete ${t.name} (${scopeName(t)})? This can't be undone.`)))
    die("Not deleted. (Pass --yes to skip this question.)");
  const { status, data } = await signedFetch(ctx.dev, "/api/device/trash/purge", "POST", { id: t.id });
  if (status !== 200) die(`Purge failed (${status} ${data.error || ""}).`);
  out(`✓ ${t.name} (${scopeName(t)}) is permanently deleted.`);
}

async function importEnv(args) {
  const overwrite = takeFlag(args, ["--overwrite"], true);
  const del = takeFlag(args, ["--delete"], true);
  const scope = resolveScope(args);
  const file = args[0] || ".env";
  if (!existsSync(file)) die(`File not found: ${file}`);
  if (!scope.project) die("Choose a project first: csec init <project>  (or pass -p <project>)");
  const entries = parseDotenv(readFileSync(file, "utf8"));
  if (!entries.length) die(`No KEY=value lines found in ${file}.`);

  const ctx = await openVault(`import ${file} into ${scope.label}`);
  const toSave = [];
  const report = { created: [], updated: [], same: [], skipped: [] };
  for (const { key, value } of entries) {
    const existing = ctx.items.find((it) => it.name === key && projOf(it) === scope.project && envOf(it) === scope.env);
    if (existing && existing.value === value) { report.same.push(key); continue; }
    if (existing && !overwrite) { report.skipped.push(key); continue; }
    toSave.push({ existing, data: { ...keepFields(existing), name: key, value, notes: existing ? existing.notes || "" : `imported from ${file}`, project: scope.project, env: scope.env } });
    (existing ? report.updated : report.created).push(key);
  }
  if (toSave.length) await putItems(ctx, toSave);

  out(`✓ ${file} → ${scope.label}`);
  if (report.created.length) out(`  added:     ${report.created.join(", ")}`);
  if (report.updated.length) out(`  updated:   ${report.updated.join(", ")}`);
  if (report.same.length) out(`  unchanged: ${report.same.join(", ")}`);
  if (report.skipped.length) out(`  skipped (different value already in vault; use --overwrite): ${report.skipped.join(", ")}`);
  const bad = entries.map((e) => e.key).filter((k) => !ENV_NAME.test(k));
  if (bad.length) out(`  ! not injectable as env vars by csec run: ${bad.join(", ")}`);

  const safeToDelete = report.skipped.length === 0;
  if (!safeToDelete) return out(`  ${file} was kept because some values were skipped.`);
  if (del || (await confirm(`Delete the plaintext ${file} now? Your app can use: csec run -- <command>`))) {
    rmSync(file);
    out(`✓ Deleted ${file}. (If it was ever committed to git, rotate those keys: they're still in the history.)`);
  } else {
    out(`  Kept ${file}. Delete it when you're ready.`);
  }
}

async function init(args) {
  const env = (takeFlag(args, ["--env", "-e"]) || "dev").toLowerCase();
  const project = (args[0] || "").toLowerCase();
  if (!SLUG.test(project)) die("Usage: csec init <project> [--env dev]   (a-z, 0-9, - and _)");
  if (!SLUG.test(env)) die(`Invalid environment "${env}".`);
  const f = join(process.cwd(), CONFIG_FILE);
  writeFileSync(f, JSON.stringify({ project, env }, null, 2) + "\n");
  out(`✓ Wrote ${CONFIG_FILE}: project "${project}", default env "${env}". It contains no secrets, so it's safe to commit.`);
  if (existsSync(".env")) out("  Found a .env here. Move it into the vault with: csec import .env");
}

// ---------- broker grants (AI agents) ----------
function parseDuration(text) {
  const m = String(text).match(/^(\d+)(s|m|h)$/);
  if (!m) die(`Invalid duration "${text}" (use e.g. 90s, 15m, 2h).`);
  const secs = Number(m[1]) * { s: 1, m: 60, h: 3600 }[m[2]];
  if (secs < 60 || secs > 86400) die("Duration must be between 1m and 24h.");
  return secs;
}
const fmtTime = (unix) => new Date(unix * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

/** Decrypt one secret on this device and register a split-key broker grant for it. Shows Touch ID. */
async function createGrant({ scope, name, host, ttl, header, label, maxUses = null, ctx = null }) {
  const hm = String(header).match(/^([A-Za-z0-9-]{1,64}):\s*(.+)$/);
  if (!hm || !hm[2].includes("{secret}")) die('The auth header must look like "Header-Name: ...{secret}..."');
  host = String(host || "").toLowerCase();
  ctx = ctx || (await openVault(`let "${label}" use ${name} on ${host} for ${Math.round(ttl / 60)} min`));
  const it = inScope(ctx.items, scope).find((x) => x.name === name);
  if (!it) die(`No secret named ${name} in ${scope.label}.`);
  const id = crypto.randomUUID();
  const sealed = await C.sealGrant(it.value, id);
  const meta = await C.encryptItem(ctx.vk, id, { label, secret: name, project: scope.project, env: envOf(it) || scope.env });
  const { status, data } = await signedFetch(ctx.dev, "/api/device/grants", "POST", {
    id, meta, host, header_name: hm[1], header_template: hm[2],
    key_hash: sealed.keyHash, iv: sealed.iv, ct: sealed.ct, ttl, max_uses: maxUses,
  });
  if (status !== 200) die(`Could not create grant (${status} ${data.error || ""}).${data.error === "invalid_grant" ? " Check the host (a public hostname) and the auth header." : ""}`);
  return { id, token: sealed.token, expires_at: data.expires_at, host, value: it.value };
}

/** Build a broker URL for a grant and refuse anything that would escape /api/broker/<grant>/. */
function brokerTarget(gid, path) {
  const p = path || "/";
  if (!p.startsWith("/") || /(^|\/)(\.|%2e){1,2}(\/|\?|#|$)/i.test(p) || /\\|%5c/i.test(p)) return null;
  const target = new URL(`${BASE}/api/broker/${gid}${p}`);
  if (target.origin !== new URL(BASE).origin || !target.pathname.startsWith(`/api/broker/${gid}/`)) return null;
  return target;
}

async function grant(args) {
  const host = takeFlag(args, ["--host"]);
  const ttl = parseDuration(takeFlag(args, ["--for"]) || "15m");
  const header = takeFlag(args, ["--header"]) || "Authorization: Bearer {secret}";
  const usesFlag = takeFlag(args, ["--uses"]);
  const label = (takeFlag(args, ["--label"]) || "agent").slice(0, 64);
  const quiet = takeFlag(args, ["--json"], true);
  const scope = resolveScope(args);
  const name = args[0];
  if (!name || !host) die('Usage: csec grant NAME --host api.example.com [--for 15m] [--uses N] [--header "Authorization: Bearer {secret}"] [--label claude-code]');
  const maxUses = usesFlag === undefined ? null : Number(usesFlag);
  if (maxUses !== null && (!Number.isInteger(maxUses) || maxUses < 1)) die("--uses must be a positive number.");
  const { id, token, expires_at } = await createGrant({ scope, name, host, ttl, header, label, maxUses });
  const sealed = { token };
  const data = { expires_at };

  const brokerUrl = `${BASE}/api/broker/${id}`;
  const localUrl = `http://127.0.0.1:7777/${id}`;
  if (quiet) {
    process.stdout.write(JSON.stringify({ grant_id: id, token: sealed.token, broker_url: brokerUrl, local_proxy_url: localUrl, host: host.toLowerCase(), expires_at: data.expires_at }) + "\n");
    return;
  }
  out(`✓ Grant ${id.slice(0, 8)}: ${name} (${scope.label}) → https://${host.toLowerCase()} until ${fmtTime(data.expires_at)}${maxUses ? `, max ${maxUses} uses` : ""}`);
  out("");
  out("  Give the agent these two values (the token is shown once):");
  process.stdout.write(`  CATARINA_BASE_URL=${localUrl}\n  CATARINA_GRANT_TOKEN=${sealed.token}\n`);
  out("");
  out("  Start the local proxy in another terminal:  csec proxy");
  out(`  The agent calls the API through the proxy, for example:`);
  out(`    curl ${localUrl}/<api-path> -H "Authorization: Bearer $CATARINA_GRANT_TOKEN"`);
  out("  The broker swaps the grant token for the real key, and only sends it to " + host.toLowerCase() + ".");
  out(`  Revoke early: csec revoke ${id.slice(0, 8)}`);
}

async function grants() {
  const ctx = await openVault("list agent grants");
  const { status, data } = await signedFetch(ctx.dev, "/api/device/vault");
  if (status !== 200) die(`Server error (${status}).`);
  const now = Math.floor(Date.now() / 1000);
  const list = data.grants || [];
  if (!list.length) return out("No grants.");
  for (const g of list) {
    let meta = {};
    try { meta = await C.decryptItem(ctx.vk, g.id, g.meta); } catch {}
    const state = g.revoked_at ? "revoked" : g.expires_at <= now ? "expired" : `active until ${fmtTime(g.expires_at)}`;
    process.stdout.write(`${g.id.slice(0, 8)}  ${(meta.secret || "?").padEnd(20)} → ${g.host.padEnd(24)} ${String(g.uses).padStart(4)} use(s)  ${state}  ${meta.label || ""}\n`);
  }
}

async function revoke(args) {
  const prefix = (args[0] || "").toLowerCase();
  if (!/^[0-9a-f-]{4,36}$/.test(prefix)) die("Usage: csec revoke <grant-id or first characters>");
  const ctx = await openVault("revoke an agent grant");
  const { data } = await signedFetch(ctx.dev, "/api/device/vault");
  const matches = (data.grants || []).filter((g) => g.id.startsWith(prefix));
  if (matches.length !== 1) die(matches.length ? "That prefix matches several grants; use more characters." : "No grant with that ID.");
  const { status, data: r } = await signedFetch(ctx.dev, "/api/device/grants/revoke", "POST", { id: matches[0].id });
  if (status !== 200) die(`Revoke failed (${status} ${r.error || ""}).`);
  out(`✓ Revoked grant ${matches[0].id.slice(0, 8)}.`);
}

/** Local proxy for agents on this machine: adds the Access service token, maps PUT/PATCH/DELETE for the WAF.
 *  Responses are streamed, so server-sent events (streamed AI replies) arrive as they come. */
function startProxyServer(port, log = out) {
  const access = accessHeaders();
  const server = createServer(async (req, res) => {
    const reject = (code, error) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify({ ok: false, error })); };
    const m = req.url.match(/^\/([0-9a-f-]{36})(\/.*)?$/);
    if (!m) return reject(404, "use /<grant-id>/<path>");
    // Never let a request escape /api/broker/<grant>/ (e.g. "/<id>/../../vault/state" or %2e%2e).
    const target = brokerTarget(m[1], m[2] || "/");
    if (!target) return reject(400, "invalid_path");
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const headers = { ...access };
    for (const [k, v] of Object.entries(req.headers)) {
      if (["host", "connection", "content-length", "transfer-encoding"].includes(k)) continue;
      headers[k] = Array.isArray(v) ? v.join(", ") : v;
    }
    let method = req.method;
    if (["PUT", "PATCH", "DELETE"].includes(method)) { headers["X-Catarina-Method"] = method; method = "POST"; }
    try {
      const up = await fetch(target, {
        method, headers, redirect: "manual",
        body: ["GET", "HEAD"].includes(method) ? undefined : Buffer.concat(chunks),
      });
      const outHeaders = {};
      up.headers.forEach((v, k) => { if (!["content-encoding", "content-length", "transfer-encoding"].includes(k)) outHeaders[k] = v; });
      res.writeHead(up.status, outHeaders);
      if (up.body) for await (const chunk of up.body) res.write(chunk);
      res.end();
      log(`${new Date().toLocaleTimeString()}  ${req.method} ${m[1].slice(0, 8)}${(m[2] || "/").split("?")[0]} → ${up.status}`);
    } catch (e) {
      if (res.headersSent) return res.destroy();
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "proxy_error", detail: String(e.message) }));
    }
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server));
  });
}

async function proxy(args) {
  const port = Number(takeFlag(args, ["--port"]) || 7777);
  await startProxyServer(port).catch((e) => die(`Could not start the proxy on port ${port}: ${e.code || e.message}`));
  out(`✓ Broker proxy on http://127.0.0.1:${port}  →  ${BASE}/api/broker`);
  out("  Only reachable from this computer. Agents still need a grant token for each request. Ctrl+C to stop.");
}

// ---------- csec connect: run any app or agent with grant tokens instead of real keys ----------
// Each SDK gets a base URL pointing at a local proxy and a grant token where it expects its API key.
// The real key is added by the broker, only for the host of that preset. Nothing in the child holds it.
// auto: the official SDK reads urlVar by itself. Otherwise the app passes it as its client's base URL (one line).
const bearer = "Authorization: Bearer {secret}";
const CONNECT_PRESETS = {
  openai: { host: "api.openai.com", header: bearer, keyVar: "OPENAI_API_KEY", urlVar: "OPENAI_BASE_URL", path: "/v1", auto: "OpenAI SDKs" },
  anthropic: { host: "api.anthropic.com", header: "x-api-key: {secret}", keyVar: "ANTHROPIC_API_KEY", urlVar: "ANTHROPIC_BASE_URL", path: "", auto: "Anthropic SDKs" },
  gemini: { host: "generativelanguage.googleapis.com", header: "x-goog-api-key: {secret}", keyVar: "GEMINI_API_KEY", urlVar: "GOOGLE_GEMINI_BASE_URL", path: "", auto: "Google Gen AI SDK for JavaScript and Go", unset: ["GOOGLE_API_KEY"] },
  groq: { host: "api.groq.com", header: bearer, keyVar: "GROQ_API_KEY", urlVar: "GROQ_BASE_URL", path: "", auto: "Groq SDK for JavaScript" },
  mistral: { host: "api.mistral.ai", header: bearer, keyVar: "MISTRAL_API_KEY", urlVar: "MISTRAL_BASE_URL", path: "" },
  xai: { host: "api.x.ai", header: bearer, keyVar: "XAI_API_KEY", urlVar: "XAI_BASE_URL", path: "/v1" },
  deepseek: { host: "api.deepseek.com", header: bearer, keyVar: "DEEPSEEK_API_KEY", urlVar: "DEEPSEEK_BASE_URL", path: "" },
  openrouter: { host: "openrouter.ai", header: bearer, keyVar: "OPENROUTER_API_KEY", urlVar: "OPENROUTER_BASE_URL", path: "/api/v1" },
  github: { host: "api.github.com", header: bearer, keyVar: "GITHUB_TOKEN", urlVar: "GITHUB_API_URL", path: "", auto: "GitHub Actions toolkit" },
};
for (const p of Object.values(CONNECT_PRESETS)) p.secret = p.keyVar;
const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** "openai", "openai:MY_KEY", "anthropic:CLAUDE_KEY" or "STRIPE_KEY@api.stripe.com". */
function parseConnectSpec(spec, header) {
  const custom = spec.match(/^([A-Za-z_][A-Za-z0-9_]*)@([A-Za-z0-9.-]+)$/);
  if (custom) {
    const host = custom[2].toLowerCase();
    if (!HOST_RE.test(host)) die(`"${custom[2]}" isn't a public hostname.`);
    return { secret: custom[1], host, header: header || "Authorization: Bearer {secret}", keyVar: custom[1], urlVar: `${custom[1]}_BASE_URL`, path: "" };
  }
  const [preset, name] = spec.split(":");
  const p = CONNECT_PRESETS[preset.toLowerCase()];
  if (!p) die(`Unknown API "${spec}". Presets: ${Object.keys(CONNECT_PRESETS).join(", ")} (optionally :SECRET_NAME), or SECRET_NAME@api.example.com.`);
  if (name !== undefined && !ENV_NAME.test(name)) die(`"${name}" isn't a valid secret name.`);
  return { ...p, secret: name || p.secret };
}

async function connectCmd(args) {
  const sep = args.indexOf("--");
  const own = sep >= 0 ? args.slice(0, sep) : args;
  const cmd = sep >= 0 ? args.slice(sep + 1) : [];
  const ttl = parseDuration(takeFlag(own, ["--for"]) || "1h");
  const header = takeFlag(own, ["--header"]);
  const label = (takeFlag(own, ["--label"]) || (cmd[0] ? basename(cmd[0]) : "connect")).slice(0, 64);
  const port = Number(takeFlag(own, ["--port"]) || 0);
  const scope = resolveScope(own);
  const usage = "Usage: csec connect <api>[:SECRET] | SECRET@host … [--for 1h] -- <command> [args…]   (APIs: csec connect --list)";
  if (takeFlag(own, ["--list"], true)) {
    for (const [name, p] of Object.entries(CONNECT_PRESETS)) {
      process.stdout.write(`${name.padEnd(11)} ${p.host.padEnd(34)} ${p.keyVar} + ${p.urlVar}${p.auto ? `  (read automatically by the ${p.auto})` : ""}\n`);
    }
    out("  Use another secret name with preset:NAME, any other API with NAME@host.");
    return;
  }
  if (!own.length || !cmd.length) die(usage);
  const specs = own.map((x) => parseConnectSpec(x, header));
  if (new Set(specs.map((x) => x.keyVar)).size !== specs.length) die("Each API can be connected once.");

  const ctx = await openVault(`let "${label}" use ${specs.map((x) => `${x.secret} on ${x.host}`).join(", ")} for ${Math.round(ttl / 60)} min`);
  const have = new Set(inScope(ctx.items, scope).map((it) => it.name));
  const missing = specs.filter((x) => !have.has(x.secret)).map((x) => x.secret);
  if (missing.length) die(`No secret named ${missing.join(", ")} in ${scope.label}. Pick one with openai:NAME, or see csec list.`);
  const server = await startProxyServer(port, () => {}).catch((e) => die(`Could not start the local proxy: ${e.code || e.message}`));
  const local = `http://127.0.0.1:${server.address().port}`;
  const env = { ...process.env };
  const made = [];
  for (const x of specs) {
    const g = await createGrant({ scope, name: x.secret, host: x.host, ttl, header: x.header, label, ctx });
    made.push(g.id);
    for (const v of x.unset || []) delete env[v]; // an SDK would prefer it over keyVar
    env[x.keyVar] = g.token;
    env[x.urlVar] = `${local}/${g.id}${x.path}`;
    out(`✓ ${x.secret} → https://${x.host} until ${fmtTime(g.expires_at)}  (${x.keyVar} = grant token, ${x.urlVar} = local proxy)`);
    if (!x.auto) out(`  Pass ${x.urlVar} to your client as its base URL; its SDK doesn't read it by itself.`);
  }
  out("  The app gets grant tokens, never the real keys. They stop working when it exits.");

  const revokeAll = async () => {
    for (const id of made) await signedFetch(ctx.dev, "/api/device/grants/revoke", "POST", { id }).catch(() => {});
  };
  const child = spawn(cmd[0], cmd.slice(1), { stdio: "inherit", env });
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, () => child.kill(sig));
  child.on("error", async (e) => { await revokeAll(); die(`Could not start ${cmd[0]}: ${e.message}`, 127); });
  child.on("exit", async (code, signal) => {
    server.close();
    await revokeAll();
    process.exit(signal ? 128 + (osConstants.signals[signal] || 1) : code ?? 0);
  });
}

// ---------- MCP server (AI agents) ----------
// `csec mcp` speaks the Model Context Protocol over stdio. Agents get two tools:
//   list_secrets — names only;  call_api — call an API through the broker using a secret by name.
// The agent never receives a secret value. Each new (secret, host) needs Touch ID approval;
// the resulting 15-minute grant is reused for later calls.

const MCP_GRANT_TTL = 15 * 60;
const MCP_MAX_BODY = 100_000;

const MCP_TOOLS = [
  {
    name: "list_secrets",
    description: "List the NAMES of secrets available for a project/environment in Catarina Secrets. Values are never returned. Defaults to the project in .csec.json of the current folder.",
    inputSchema: {
      type: "object",
      properties: {
        project: { type: "string", description: "Project name (optional; defaults to .csec.json)" },
        env: { type: "string", description: "Environment, e.g. dev or prod (optional)" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "call_api",
    description: "Call an HTTPS API using a secret from Catarina Secrets WITHOUT seeing it. The broker adds the secret as an auth header and sends the request only to `host`. The first use of a secret on a host asks the user for Touch ID approval (valid 15 min). Returns the HTTP status, content type and body (secret values are redacted).",
    inputSchema: {
      type: "object",
      properties: {
        secret: { type: "string", description: "Secret name, e.g. STRIPE_KEY" },
        host: { type: "string", description: "API hostname, e.g. api.stripe.com" },
        method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"], default: "GET" },
        path: { type: "string", description: "Path starting with /, may include a query string, e.g. /v1/balance" },
        headers: { type: "object", additionalProperties: { type: "string" }, description: "Extra request headers (no auth header needed)" },
        body: { type: "string", description: "Request body (e.g. JSON or form-encoded text)" },
        auth_header: { type: "string", description: 'How to send the secret. Default "Authorization: Bearer {secret}". E.g. "x-api-key: {secret}"' },
        project: { type: "string" },
        env: { type: "string" },
      },
      required: ["secret", "host", "path"],
      additionalProperties: false,
    },
  },
];

function mcpScope(a) {
  const args = [];
  if (a.project) args.push("--project", String(a.project));
  if (a.env) args.push("--env", String(a.env));
  return resolveScope(args);
}

async function mcp() {
  MCP_MODE = true;
  const grantsCache = new Map(); // "scope|secret|host|header" → { id, token, expires_at, value }
  let clientName = "MCP agent";
  const send = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");
  const text = (t, isError = false) => ({ content: [{ type: "text", text: t }], ...(isError ? { isError: true } : {}) });

  async function callTool(name, a = {}) {
    if (name === "list_secrets") {
      const scope = mcpScope(a);
      const { items } = await openVault(`let ${clientName} list secret names (${scope.label})`);
      const names = inScope(items, scope).map((it) => it.name);
      return text(JSON.stringify({ scope: scope.label, secrets: names }, null, 2));
    }
    if (name === "call_api") {
      const scope = mcpScope(a);
      const secret = String(a.secret || ""), host = String(a.host || "").toLowerCase();
      const method = String(a.method || "GET").toUpperCase();
      const header = String(a.auth_header || "Authorization: Bearer {secret}");
      if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) return text("Unsupported method.", true);
      // Validate the path before anything that could trigger a Touch ID prompt.
      if (!brokerTarget("00000000-0000-4000-8000-000000000000", String(a.path || "/"))) return text("Invalid path: it must start with / and must not contain dot segments.", true);
      const key = `${scope.label}|${secret}|${host}|${header}`;
      let g = grantsCache.get(key);
      if (!g || g.expires_at - Math.floor(Date.now() / 1000) < 30) {
        g = await createGrant({ scope, name: secret, host, ttl: MCP_GRANT_TTL, header, label: clientName });
        grantsCache.set(key, g);
      }
      const target = brokerTarget(g.id, String(a.path || "/"));
      if (!target) return text("Invalid path: it must start with / and must not contain dot segments.", true);
      const headers = { ...accessHeaders(), "X-Catarina-Grant": g.token };
      for (const [k, v] of Object.entries(a.headers || {})) {
        if (/^(authorization|cookie|host|x-catarina-|cf-access-)/i.test(k)) continue;
        headers[k] = String(v);
      }
      let wireMethod = method;
      if (["PUT", "PATCH", "DELETE"].includes(method)) { headers["X-Catarina-Method"] = method; wireMethod = "POST"; }
      const res = await fetch(target, { method: wireMethod, headers, redirect: "manual", body: wireMethod === "GET" ? undefined : a.body ?? "" });
      if (res.status >= 300 && res.status < 400 && !res.headers.get("x-catarina-broker")) return text("Blocked by Cloudflare Access: run `csec access-token` first.", true);
      let body = await res.text();
      if (g.value && g.value.length >= 4) body = body.split(g.value).join(`[REDACTED:${secret}]`);
      if (body.includes(g.token)) body = body.split(g.token).join("[REDACTED:grant]");
      const truncated = body.length > MCP_MAX_BODY;
      return text(JSON.stringify({
        status: res.status,
        content_type: res.headers.get("content-type"),
        body: truncated ? body.slice(0, MCP_MAX_BODY) : body,
        ...(truncated ? { truncated: true } : {}),
        ...(res.headers.get("x-catarina-broker") ? {} : { note: "Response came from Catarina, not the API (see body.error)." }),
      }, null, 2), res.status >= 400);
    }
    return text(`Unknown tool: ${name}`, true);
  }

  async function handle(msg) {
    switch (msg.method) {
      case "initialize": {
        const ci = msg.params && msg.params.clientInfo;
        if (ci && typeof ci.name === "string") clientName = ci.name.replace(/[^\w .@()-]/g, "").slice(0, 40) || clientName;
        return {
          protocolVersion: (msg.params && msg.params.protocolVersion) || "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "catarina-secrets", version: "0.1.4" },
          instructions: "Use call_api to call external APIs with the user's secrets without seeing them. Never ask the user to paste secret values into the chat.",
        };
      }
      case "ping": return {};
      case "tools/list": return { tools: MCP_TOOLS };
      case "tools/call": {
        const p = msg.params || {};
        try {
          return await callTool(p.name, p.arguments || {});
        } catch (e) {
          return text(e instanceof CliError ? e.message : `Error: ${e.message}`, true);
        }
      }
      default: throw Object.assign(new Error(`Method not found: ${msg.method}`), { code: -32601 });
    }
  }

  // Agents must never get silent access: without Touch ID nobody would approve grants.
  const rec = loadDevice();
  if (rec && !rec.sealed && process.env.CSEC_MCP_ALLOW_NO_TOUCHID !== "1") {
    out("✗ csec mcp needs Touch ID protection, so every agent grant is approved by you. Run: csec logout && csec login");
    process.exit(1);
  }
  out(`csec mcp: serving ${BASE} over stdio`);
  const rl = (await import("node:readline")).createInterface({ input: process.stdin });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }); continue; }
    if (msg.id === undefined || msg.id === null) continue; // notification
    try { send({ jsonrpc: "2.0", id: msg.id, result: await handle(msg) }); }
    catch (e) { send({ jsonrpc: "2.0", id: msg.id, error: { code: e.code || -32603, message: e.message } }); }
  }
}

async function status() {
  const dev = loadDevice();
  if (!dev) return out(`Not linked to ${BASE}. Run: csec login`);
  out(`Linked to ${BASE} as "${dev.name}" since ${dev.linked_at}`);
  const scope = resolveScope([]);
  out(`Scope: ${scope.label}${scope.cfg ? `  (from ${scope.cfg.path})` : ""}`);
  out(`Touch ID: ${dev.sealed ? "required (Secure Enclave)" : "off — turn on with: csec touchid on"}`);
  const signPub = dev.sign_pub || (dev.sign_priv ? C.toB64u(new Uint8Array(await crypto.subtle.exportKey("raw", await publicFromPkcs8(dev.sign_priv)))) : null);
  if (signPub) out(`Fingerprint: ${await C.deviceFingerprint(signPub, dev.enc_pub)}`);
}
async function publicFromPkcs8(signPrivB64u) {
  // Re-derive the Ed25519 public key from the stored private key via JWK (x is the public part).
  const k = await crypto.subtle.importKey("pkcs8", C.fromB64u(signPrivB64u), { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", k);
  return crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, { name: "Ed25519" }, true, ["verify"]);
}

async function logout() {
  const rec = loadDevice();
  if (!rec) return out("Not linked.");
  const dev = await unlockDevice(rec, "sign out this device from csec");
  const { status } = await signedFetch(dev, "/api/device/logout", "POST", {});
  deleteDevice();
  out(status === 200 ? "✓ Device revoked on the server and keys removed from this computer." : "✓ Keys removed from this computer (server revoke failed; revoke it in the vault page).");
}

async function accessToken(args) {
  if (args[0] === "--clear") { storeDelete(ACCESS_ACCOUNT); return out("✓ Access service token removed."); }
  // Reads two lines from stdin (client ID, then client secret) so nothing lands in shell history.
  if (process.stdin.isTTY) out("Paste the Access service token Client ID, Enter, then the Client Secret, Enter:");
  let input = "";
  for await (const chunk of process.stdin) { input += chunk; if (input.split("\n").filter(Boolean).length >= 2) break; }
  const [id, secret] = input.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  if (!/^[0-9a-f]{32}\.access$/.test(id || "") || !/^[A-Za-z0-9_-]{32,256}$/.test(secret || "")) die("That doesn't look like an Access service token (expected <32 hex>.access and its client secret).");
  storeSave(ACCESS_ACCOUNT, "Catarina Secrets Access service token", { id, secret });
  out(`✓ Access service token saved in ${FILE_STORE ? fileFor(ACCESS_ACCOUNT) : "the macOS Keychain"}.`);
}

/** csec scan: offline, no account needed. Exit code 1 when a high-confidence secret is found (for CI/hooks). */
const HOOK_MARK = "# csec-scan-hook";

/** Install or remove a git pre-commit hook that runs `csec scan --staged`. Never overwrites someone else's hook. */
function scanHook(root, install) {
  let hooksDir;
  try {
    hooksDir = execFileSync("git", ["-C", root, "rev-parse", "--git-path", "hooks"], { encoding: "utf8" }).trim();
  } catch { die("Not a git repository."); }
  if (!hooksDir.startsWith("/")) hooksDir = join(root, hooksDir);
  const hook = join(hooksDir, "pre-commit");
  const existing = existsSync(hook) ? readFileSync(hook, "utf8") : null;
  const ours = existing != null && existing.includes(HOOK_MARK);
  if (!install) {
    if (!ours) return out(existing == null ? "No pre-commit hook installed." : "The pre-commit hook isn't csec's; left it alone.");
    rmSync(hook);
    return out("✓ Removed the csec pre-commit hook.");
  }
  if (existing != null && !ours) {
    die(`${hook} already exists and isn't csec's. Add this line to it instead:\n    csec scan --staged || exit 1`);
  }
  // Absolute paths: commits from editors and GUI apps don't always have your shell's PATH.
  const script = [
    "#!/bin/sh",
    `${HOOK_MARK} (remove with: csec scan --uninstall-hook)`,
    `NODE="${process.execPath}"; CSEC="${realpathSync(process.argv[1])}"`,
    'ROOT="$(git rev-parse --show-toplevel)"',
    'if [ -x "$NODE" ] && [ -f "$CSEC" ]; then "$NODE" "$CSEC" scan --staged "$ROOT"',
    'elif command -v csec >/dev/null 2>&1; then csec scan --staged "$ROOT"',
    'else echo "csec not found: secret scan skipped (reinstall: npm i -g catarina-secrets)" >&2; exit 0; fi',
    'if [ $? -ne 0 ]; then',
    `  echo "Commit blocked by csec: a secret is staged. Move it into your vault, or commit with --no-verify if it's not a secret." >&2`,
    "  exit 1",
    "fi",
    "",
  ].join("\n");
  mkdirSync(hooksDir, { recursive: true });
  writeFileSync(hook, script, { mode: 0o755 });
  out(`✓ ${ours ? "Updated" : "Installed"} the pre-commit hook: commits that add a secret are blocked.`);
}

async function scan(args) {
  const history = args.includes("--history");
  const staged = args.includes("--staged");
  const asJson = args.includes("--json");
  const root = args.find((a) => !a.startsWith("-")) || process.cwd();
  if (!existsSync(root)) die(`No such folder: ${root}`);
  if (args.includes("--install-hook") || args.includes("--uninstall-hook")) return scanHook(root, args.includes("--install-hook"));
  let isGit = false;
  try { execFileSync("git", ["-C", root, "rev-parse", "--git-dir"], { stdio: "ignore" }); isGit = true; } catch {}
  if ((history || staged) && !isGit) die(`${history ? "--history" : "--staged"} needs a git repository.`);
  if (staged) {
    // Pre-commit: only lines being added in this commit. Silent when clean.
    const secrets = summarize((await scanStaged(root)).findings);
    const high = secrets.filter((x) => x.confidence === "high");
    if (asJson) { process.stdout.write(JSON.stringify({ staged: true, secrets }, null, 2) + "\n"); process.exit(high.length ? 1 : 0); }
    for (const x of secrets) {
      out(`  ${x.confidence === "high" ? "HIGH    " : "POSSIBLE"}  ${x.name}  ${x.preview}`);
      for (const p of x.places.slice(0, 5)) out(`            ${p.file}:${p.line}`);
    }
    if (secrets.length && !high.length) out("  (possible secrets only: commit allowed. Add csec:ignore to silence a line.)");
    process.exit(high.length ? 1 : 0);
  }
  if (!asJson) out(`Scanning ${root}${history ? " and its git history" : ""}…`);
  const { findings, files } = scanFiles(root);
  let commits = 0;
  if (history) {
    const h = await scanHistory(root);
    findings.push(...h.findings);
    commits = h.commits;
  }
  const secrets = summarize(findings);
  const high = secrets.filter((s) => s.confidence === "high").length;
  if (asJson) {
    process.stdout.write(JSON.stringify({ files, commits, secrets }, null, 2) + "\n");
    process.exit(high ? 1 : 0);
  }
  const scope = `${files} files${history ? `, ${commits} commits` : ""}`;
  if (!secrets.length) {
    out(`✓ No secrets found in ${scope}.`);
    if (isGit && !history) out("  Add --history to also check every past commit.");
    process.exit(0);
  }
  out(`✗ ${secrets.length} secret${secrets.length === 1 ? "" : "s"} found in ${scope} (${high} high confidence, ${secrets.length - high} possible)`);
  out("");
  for (const s of secrets) {
    out(`  ${s.confidence === "high" ? "HIGH    " : "POSSIBLE"}  ${s.name}  ${s.preview}`);
    for (const p of s.places.slice(0, 5)) out(`            ${p.where === "file" ? `${p.file}:${p.line}` : `history: ${p.file} (commit ${p.commit})`}`);
    if (s.places.length > 5) out(`            …and ${s.places.length - 5} more places`);
  }
  const inFiles = secrets.some((s) => s.places.some((p) => p.where === "file"));
  const inHistory = secrets.some((s) => s.places.some((p) => p.where === "history"));
  // .env-style files with findings can be moved into the vault in one step each.
  const envFiles = [...new Set(secrets.flatMap((s) => s.places.filter((p) => p.where === "file" && isEnvFile(basename(p.file))).map((p) => p.file)))];
  const linked = !!loadDevice();
  out("");
  out("Next steps:");
  if (inFiles && linked && envFiles.length) {
    const cfg = findConfig();
    out(`  • Move them into your vault${cfg ? "" : " (first: csec init <project>)"}, then delete the file when asked:`);
    const here = realpathSync(process.cwd()), base = realpathSync(root);
    for (const f of envFiles) {
      const rel = relative(here, join(base, f));
      out(`      csec import ${rel.startsWith("../../../") ? join(base, f) : rel}`); // short path, or absolute if it's far away
    }
    out("    Then start your app with csec run -- <cmd>. Keys in code: csec set NAME and read them from the environment.");
  } else if (inFiles && linked) {
    out("  • Move them into your vault with csec set NAME, read them from the environment, and run your app with csec run -- <cmd>.");
  }
  // Advice that applies with or without a vault.
  const codeFiles = secrets.some((s) => s.places.some((p) => p.where === "file" && !isEnvFile(basename(p.file))));
  const tracked = isGit ? envFiles.filter((f) => { try { execFileSync("git", ["-C", root, "ls-files", "--error-unmatch", f], { stdio: "ignore" }); return true; } catch { return false; } }) : [];
  for (const f of tracked) out(`  • ${f} is tracked by git: run git rm --cached ${f}, add it to .gitignore, and rotate its keys.`);
  if (!linked && codeFiles) out("  • Keys in source code: move them to environment variables and rotate any that were committed.");
  if (inHistory) out("  • Rotate keys found in git history at the provider. Deleting a file doesn't remove it from past commits.");
  out("  • Not a secret? Add the comment csec:ignore on that line.");
  if (isGit && !history) out("  • Add --history to also check every past commit.");
  if (!linked) {
    out("");
    out("Catarina Secrets keeps API keys in an end-to-end encrypted vault that your apps and AI agents");
    out("use without seeing them. Early access: https://secret.getcatarina.com/?utm_source=csec-scan");
  }
  process.exit(high ? 1 : 0);
}

const HELP = `csec — Catarina Secrets CLI

  csec login [--name N] [--no-touchid]  Link this computer (approve it in the vault page)
  csec init <project> [--env dev]   Create .csec.json in this folder (project + default env)
  csec run [-e env] -- <cmd> [args] Run a command with this project's secrets as env vars
  csec list [--all]                 List secret names for this project/env (or everything)
  csec get NAME                     Print one secret to stdout
  csec set NAME [--all-envs]        Save a secret (value from a hidden prompt or stdin)
  csec set NAME --generate [--type T] [--length N]
                                    Create a random secret and save it without showing it
  csec gen [--type T] [--length N]  Print a random secret. Types: password (default), alnum, hex, b64u
  csec backup [-o file]             Write an encrypted backup file (restore it in the vault page)
  csec delete NAME [--all-envs]     Move a secret to the trash (restorable for 30 days)
  csec trash                        List deleted secrets
  csec restore NAME|ID [--replace]  Bring a secret back from the trash
  csec purge NAME|ID [--yes]        Delete a trashed secret forever
  csec import [.env] [--overwrite] [--delete]
                                    Encrypt a .env file into the vault, then offer to delete it
  csec grant NAME --host H [--for 15m] [--uses N] [--header "Authorization: Bearer {secret}"]
                                    Let an AI agent USE a secret on host H without seeing it
  csec grants                       List broker grants
  csec revoke <grant-id>            Revoke a grant early
  csec proxy [--port 7777]          Local broker proxy for agents on this computer
  csec connect <api>[:SECRET] | SECRET@host … [--for 1h] -- <cmd>
                                    Run an app with base URLs + grant tokens instead of real keys
  csec connect --list               APIs with a preset (openai, anthropic, gemini, groq, mistral, …)
  csec mcp                          MCP server (stdio) for AI agents: list_secrets, call_api
  csec touchid [status|on|off]      Require Touch ID (Secure Enclave) before secrets are used
  csec status                       Show link status, device fingerprint and current scope
  csec logout                       Revoke this device and delete its keys
  csec scan [dir] [--history] [--json]
                                    Find API keys and passwords in files (and git history). Offline, no account
  csec scan --install-hook          Block commits that add a secret (git pre-commit hook; --uninstall-hook)
  csec version                      Print the CLI version
  csec access-token [--clear]       Save (from stdin) or remove the Cloudflare Access service token

  Scope: -p/--project and -e/--env flags > CSEC_PROJECT/CSEC_ENV > .csec.json > env "dev".
  A secret saved without an env applies to every env of its project.

Server: ${BASE}  (override with CATARINA_URL)`;

const [cmd, ...args] = process.argv.slice(2);
const commands = { login, init, run, get, list, ls: list, set, gen, delete: del, rm: del, trash, restore, purge, backup, import: importEnv, status, logout, "access-token": accessToken, grant, grants, revoke, proxy, connect: connectCmd, touchid, mcp, scan };
if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") { out(HELP); process.exit(0); }
if (cmd === "version" || cmd === "--version" || cmd === "-v") {
  // The npm build writes package.json next to csec.js; in the repo it's two folders up.
  for (const rel of ["./package.json", "../package.json"]) {
    try { process.stdout.write(JSON.parse(readFileSync(new URL(rel, import.meta.url), "utf8")).version + "\n"); process.exit(0); } catch {}
  }
  process.stdout.write("dev\n");
  process.exit(0);
}
if (!commands[cmd]) die(`Unknown command "${cmd}". Run csec --help`);
commands[cmd](args).catch((e) => die(e && e.name === "OperationError" ? "Decryption failed: the vault key for this device is invalid." : String((e && e.message) || e)));
