// Catarina Secrets — client-side cryptography. Everything here runs in the browser.
// The server only ever receives the outputs of seal(): random IVs and AES-256-GCM ciphertext.
//
// Key hierarchy
//   Vault Key (VK, 256-bit random)
//     ├─ wrapped by each "unlocker":
//     │    passkey  → HKDF(WebAuthn PRF output, salt) → AES-GCM key
//     │    recovery → HKDF(256-bit recovery key, salt) → AES-GCM key
//     └─ wraps one Data Encryption Key (DEK, 256-bit random) per item
//          └─ encrypts the item JSON
// Every ciphertext carries associated data (AAD) naming its purpose and ID, so the server
// can't swap a ciphertext from one item or unlocker into another without decryption failing.

const te = new TextEncoder();
const td = new TextDecoder();
const V = "catarina/v1";

export const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

export function toB64u(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function fromB64u(str) {
  const pad = "=".repeat((4 - (str.length % 4)) % 4);
  const bin = atob((str + pad).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function hkdfAesKey(ikm, salt, info) {
  const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: te.encode(info) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

const importAes = (raw) => crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

async function seal(key, bytes, aad) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(aad) }, key, bytes);
  return { iv: toB64u(iv), ct: toB64u(new Uint8Array(ct)) };
}
async function open(key, box, aad) {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64u(box.iv), additionalData: te.encode(aad) },
    key,
    fromB64u(box.ct)
  );
  return new Uint8Array(pt);
}

// ---------- Vault key ----------

export const newVaultKeyRaw = () => rand(32);
export const importVaultKey = (raw) => importAes(raw);

/** Wrap the raw vault key for an unlocker; returns {iv, ct}. */
export async function wrapVaultKey(vkRaw, secret, salt, kind, unlockerId) {
  const wk = await hkdfAesKey(secret, salt, `${V}/unlocker/${kind}`);
  return seal(wk, vkRaw, `${V}/vk/${unlockerId}`);
}
/** Unwrap; throws if the secret is wrong or the data was tampered with. */
export async function unwrapVaultKey(unlocker, secret) {
  const wk = await hkdfAesKey(secret, fromB64u(unlocker.salt), `${V}/unlocker/${unlocker.kind}`);
  const raw = await open(wk, { iv: unlocker.iv, ct: unlocker.ct }, `${V}/vk/${unlocker.id}`);
  if (raw.length !== 32) throw new Error("bad_vault_key");
  return raw;
}

// ---------- Items ----------

export async function encryptItem(vk, itemId, data) {
  const dekRaw = rand(32);
  const dek = await importAes(dekRaw);
  const blob = {
    v: 1,
    dek: await seal(vk, dekRaw, `${V}/dek/${itemId}`),
    data: await seal(dek, te.encode(JSON.stringify(data)), `${V}/item/${itemId}`),
  };
  dekRaw.fill(0);
  return JSON.stringify(blob);
}
export async function decryptItem(vk, itemId, blobStr) {
  const blob = JSON.parse(blobStr);
  if (blob.v !== 1) throw new Error("unsupported_version");
  const dekRaw = await open(vk, blob.dek, `${V}/dek/${itemId}`);
  const dek = await importAes(dekRaw);
  dekRaw.fill(0);
  return JSON.parse(td.decode(await open(dek, blob.data, `${V}/item/${itemId}`)));
}

// ---------- Recovery key (Crockford base32, 52 chars, shown in groups of 4) ----------

const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function formatRecoveryKey(bytes) {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out.match(/.{1,4}/g).join("-");
}
export function parseRecoveryKey(text) {
  const clean = String(text).toUpperCase().replace(/[\s-]/g, "").replace(/[IL]/g, "1").replace(/O/g, "0");
  if (clean.length !== 52) throw new Error("recovery_length");
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const v = B32.indexOf(ch);
    if (v < 0) throw new Error("recovery_chars");
    value = ((value << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  if (out.length !== 32) throw new Error("recovery_length");
  return new Uint8Array(out);
}

// ---------- Passkeys with the WebAuthn PRF extension ----------

export const passkeysAvailable = () => typeof window.PublicKeyCredential === "function";

/** Create a passkey and return { credentialId, prfOutput } for wrapping the vault key. */
export async function createPasskey(email, salt) {
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { id: location.hostname, name: "Catarina Secrets" },
      user: { id: rand(16), name: email, displayName: email },
      challenge: rand(32), // PRF is used for key derivation, not server login (Access handles login).
      pubKeyCredParams: [{ type: "public-key", alg: -8 }, { type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      timeout: 120000,
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const ext = cred.getClientExtensionResults().prf;
  if (!ext || ext.enabled === false) throw new Error("prf_unsupported");
  const credentialId = new Uint8Array(cred.rawId);
  // Some authenticators return the PRF result at creation; others only on the next sign-in.
  if (ext.results && ext.results.first) return { credentialId: toB64u(credentialId), prfOutput: new Uint8Array(ext.results.first) };
  const again = await getPasskeyPrf([{ credential_id: toB64u(credentialId), salt: toB64u(salt) }]);
  return { credentialId: toB64u(credentialId), prfOutput: again.prfOutput };
}

/** Ask for any registered passkey; returns { credentialId, prfOutput }. */
export async function getPasskeyPrf(passkeyUnlockers) {
  const evalByCredential = {};
  for (const u of passkeyUnlockers) evalByCredential[u.credential_id] = { first: fromB64u(u.salt) };
  const assertion = await navigator.credentials.get({
    publicKey: {
      rpId: location.hostname,
      challenge: rand(32),
      userVerification: "required",
      timeout: 120000,
      allowCredentials: passkeyUnlockers.map((u) => ({ type: "public-key", id: fromB64u(u.credential_id) })),
      extensions: { prf: { evalByCredential } },
    },
  });
  const res = assertion.getClientExtensionResults().prf;
  if (!res || !res.results || !res.results.first) throw new Error("prf_unsupported");
  return { credentialId: toB64u(new Uint8Array(assertion.rawId)), prfOutput: new Uint8Array(res.results.first) };
}

// ---------- Accounts: one passkey tap signs in AND unlocks ----------
// Login passkeys use one fixed PRF input, so a discoverable sign-in (no username, no list of
// credential IDs) can still ask for the PRF output. Each credential's PRF secret is different;
// the fixed input only makes the request possible. Older passkeys keep their random salts.

export const LOGIN_PRF_SALT = te.encode("catarina/v1/passkey-login-prf-01"); // 32 bytes
export const LOGIN_PRF_SALT_B64U = toB64u(LOGIN_PRF_SALT);

/** Serialize a registration for the server (attestation "none"). */
function registrationJson(cred) {
  const r = cred.response;
  return {
    id: toB64u(new Uint8Array(cred.rawId)),
    clientDataJSON: toB64u(new Uint8Array(r.clientDataJSON)),
    authenticatorData: toB64u(new Uint8Array(r.getAuthenticatorData())),
    publicKey: toB64u(new Uint8Array(r.getPublicKey())),
    publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
  };
}
function assertionJson(a) {
  const r = a.response;
  return {
    id: toB64u(new Uint8Array(a.rawId)),
    clientDataJSON: toB64u(new Uint8Array(r.clientDataJSON)),
    authenticatorData: toB64u(new Uint8Array(r.authenticatorData)),
    signature: toB64u(new Uint8Array(r.signature)),
  };
}

/**
 * Create a login passkey for a server challenge ({challenge, user_id, email} from the server).
 * Returns { credential (for the server), credentialId, prfOutput }.
 */
export async function createLoginPasskey(opts, excludeIds = []) {
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { id: location.hostname, name: "Catarina Secrets" },
      user: { id: fromB64u(opts.user_id), name: opts.email, displayName: opts.email },
      challenge: fromB64u(opts.challenge),
      pubKeyCredParams: [{ type: "public-key", alg: -8 }, { type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      attestation: "none",
      excludeCredentials: excludeIds.map((id) => ({ type: "public-key", id: fromB64u(id) })),
      timeout: 120000,
      extensions: { prf: { eval: { first: LOGIN_PRF_SALT } } },
    },
  });
  const ext = cred.getClientExtensionResults().prf;
  if (!ext || ext.enabled === false) throw new Error("prf_unsupported");
  const credential = registrationJson(cred);
  // Some authenticators return the PRF result at creation; others only on the next use.
  if (ext.results && ext.results.first) return { credential, credentialId: credential.id, prfOutput: new Uint8Array(ext.results.first) };
  const again = await getPasskeyPrf([{ credential_id: credential.id, salt: LOGIN_PRF_SALT_B64U }]);
  return { credential, credentialId: credential.id, prfOutput: again.prfOutput };
}

/** Discoverable sign-in for a server challenge. Returns { credential, credentialId, prfOutput|null }. */
export async function signInWithPasskey(challengeB64u) {
  const a = await navigator.credentials.get({
    publicKey: {
      rpId: location.hostname,
      challenge: fromB64u(challengeB64u),
      userVerification: "required",
      timeout: 120000,
      allowCredentials: [],
      extensions: { prf: { eval: { first: LOGIN_PRF_SALT } } },
    },
  });
  const res = a.getClientExtensionResults().prf;
  const credential = assertionJson(a);
  return { credential, credentialId: credential.id, prfOutput: res && res.results && res.results.first ? new Uint8Array(res.results.first) : null };
}

/**
 * Recovery sign-in proof: a key only someone who can open the vault can compute.
 * The server stores verifierFor(proof) and compares; it never learns the vault key.
 */
export async function recoveryProof(vkRaw) {
  const base = await crypto.subtle.importKey("raw", vkRaw, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: te.encode(`${V}/recovery-auth`) }, base, 256));
}
export const verifierFor = async (proof) => toB64u(new Uint8Array(await crypto.subtle.digest("SHA-256", proof)));

// ---------- Devices (CLI): vault key wrapped to the device's X25519 public key ----------
// ECIES-style: ephemeral X25519 → HKDF-SHA256(salt = eph_pub || device_pub) → AES-256-GCM.
// (Post-quantum hybrid with ML-KEM is planned once it's available natively in WebCrypto.)

const concat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };

async function x25519Shared(privateKey, publicRaw) {
  const pub = await crypto.subtle.importKey("raw", publicRaw, { name: "X25519" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: pub }, privateKey, 256));
  if (shared.every((b) => b === 0)) throw new Error("bad_public_key"); // low-order point
  return shared;
}

export async function wrapVaultKeyForDevice(vkRaw, encPubB64u, deviceId) {
  const devPub = fromB64u(encPubB64u);
  const eph = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const ephPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const shared = await x25519Shared(eph.privateKey, devPub);
  const wk = await hkdfAesKey(shared, concat(ephPub, devPub), `${V}/device-wrap`);
  shared.fill(0);
  return { eph_pub: toB64u(ephPub), ...(await seal(wk, vkRaw, `${V}/vk-device/${deviceId}`)) };
}

export async function unwrapVaultKeyForDevice(encPrivateKey, encPubB64u, wrap, deviceId) {
  const ephPub = fromB64u(wrap.eph_pub);
  const shared = await x25519Shared(encPrivateKey, ephPub);
  const wk = await hkdfAesKey(shared, concat(ephPub, fromB64u(encPubB64u)), `${V}/device-wrap`);
  shared.fill(0);
  const raw = await open(wk, { iv: wrap.iv, ct: wrap.ct }, `${V}/vk-device/${deviceId}`);
  if (raw.length !== 32) throw new Error("bad_vault_key");
  return raw;
}

/** Short fingerprint of a device's public keys, shown in both the terminal and the browser. */
export async function deviceFingerprint(signPubB64u, encPubB64u) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", concat(fromB64u(signPubB64u), fromB64u(encPubB64u))));
  return [...d.slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase().match(/.{4}/g).join(" ");
}

// ---------- Broker grants (split key) ----------
// The device encrypts ONE secret with a fresh random grant key K. The server stores the ciphertext
// and SHA-256(K); the agent holds only K (its token). Neither side alone can recover the secret.

export async function sealGrant(value, grantId) {
  const k = rand(32);
  const key = await hkdfAesKey(k, te.encode(grantId), `${V}/grant`);
  const box = await seal(key, te.encode(value), `${V}/grant/${grantId}`);
  const keyHash = toB64u(new Uint8Array(await crypto.subtle.digest("SHA-256", k)));
  return { token: "csg_" + toB64u(k), keyHash, ...box };
}
/** Server side: verify the token against the stored hash and decrypt. Returns the secret or null. */
export async function openGrant(token, grant) {
  if (typeof token !== "string" || !/^csg_[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const k = fromB64u(token.slice(4));
  const hash = toB64u(new Uint8Array(await crypto.subtle.digest("SHA-256", k)));
  if (hash.length !== grant.key_hash.length) return null;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ grant.key_hash.charCodeAt(i);
  if (diff !== 0) return null;
  const key = await hkdfAesKey(k, te.encode(grant.id), `${V}/grant`);
  k.fill(0);
  try {
    return td.decode(await open(key, { iv: grant.iv, ct: grant.ct }, `${V}/grant/${grant.id}`));
  } catch {
    return null;
  }
}

// ---------- Audit chain verification (client re-checks what the server reports) ----------

export async function verifyAuditChain(entries) {
  // entries are newest-first
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const d = await crypto.subtle.digest("SHA-256", te.encode(`${e.prev_hash}|${e.ts}|${e.actor}|${e.action}|${e.target}`));
    const hex = [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
    if (hex !== e.hash) return false;
    if (i + 1 < entries.length && entries[i + 1].hash !== e.prev_hash) return false;
  }
  return true;
}

// ---------- encrypted labels (passkey labels, device names) ----------
// Stored as "e1.<iv>.<ct>", sealed with the vault key and bound to what they name.
const LABEL_RE = /^e1\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{22,400})$/;
export const isSealedLabel = (s) => typeof s === "string" && LABEL_RE.test(s);

export async function sealLabel(vk, purpose, id, text) {
  const b = await seal(vk, te.encode(String(text).slice(0, 100)), `${V}/label/${purpose}/${id}`);
  return `e1.${b.iv}.${b.ct}`;
}
/** Plain text of a label. Old plaintext labels pass through; a label that fails to open is flagged. */
export async function openLabel(vk, purpose, id, s) {
  if (!isSealedLabel(s)) return String(s || "");
  const [, iv, ct] = s.match(LABEL_RE);
  try { return td.decode(await open(vk, { iv, ct }, `${V}/label/${purpose}/${id}`)); }
  catch { return "⚠ unreadable name"; }
}

// ---------- signed vault manifest (detects rollback, hidden or swapped items) ----------
// Every client write sends {n, mac}: a counter one above the stored one, and an HMAC (keyed from
// the vault key, which the server never has) over the counter and every item's id, version and
// blob hash. Clients remember the highest n they have seen, so the server can't serve an older
// copy, drop or swap items, or forge a manifest without it showing.

export async function manifestKey(vkRaw) {
  const base = await crypto.subtle.importKey("raw", vkRaw, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: te.encode(`${V}/manifest-mac`) },
    base, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign", "verify"]
  );
}

async function manifestBytes(n, items) {
  const rows = [];
  for (const it of [...items].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))) {
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(it.blob)));
    rows.push(`${it.id} ${it.version} ${toB64u(d)}`);
  }
  return te.encode(`${V}/manifest\n${n}\n${rows.join("\n")}`);
}

/** items: [{id, version, blob}] exactly as the server will hold them after the write. */
export async function signManifest(key, n, items) {
  return { n, mac: toB64u(new Uint8Array(await crypto.subtle.sign("HMAC", key, await manifestBytes(n, items)))) };
}

/**
 * Check what the server served. Returns "ok", "unsigned" (an old vault that has never had a
 * manifest), "missing" (it had one before), "mismatch" (forged, or items don't match) or
 * "rollback" (an older copy than this device has already seen).
 */
export async function checkManifest(key, manifest, items, seenN = 0) {
  if (!manifest) return seenN > 0 ? "missing" : items.length ? "unsigned" : "ok";
  if (!Number.isInteger(manifest.n) || manifest.n < 1 || typeof manifest.mac !== "string") return "mismatch";
  let valid = false;
  try { valid = await crypto.subtle.verify("HMAC", key, fromB64u(manifest.mac), await manifestBytes(manifest.n, items)); } catch { valid = false; }
  if (!valid) return "mismatch";
  return manifest.n < seenN ? "rollback" : "ok";
}

/** Item rows after a write, for signing: put/replace, remove, or add. */
export function itemsAfter(items, { put = [], remove = [] } = {}) {
  const drop = new Set([...remove, ...put.map((p) => p.id)]);
  return [...items.filter((it) => !drop.has(it.id)).map(({ id, version, blob }) => ({ id, version, blob })), ...put.map(({ id, version, blob }) => ({ id, version, blob }))];
}

// ---------- secret generator (CSPRNG, unbiased) ----------
// Symbols avoid quotes, $, `, \, # and spaces so values are safe in .env files and shells.
const GEN_LOWER = "abcdefghijklmnopqrstuvwxyz", GEN_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", GEN_DIGITS = "0123456789", GEN_SYMBOLS = "!%*-_=+.,:~^@";
export const SECRET_TYPES = {
  password: { label: "Password (letters, digits, symbols)", classes: [GEN_LOWER, GEN_UPPER, GEN_DIGITS, GEN_SYMBOLS] },
  alnum: { label: "Letters and digits", classes: [GEN_LOWER, GEN_UPPER, GEN_DIGITS] },
  hex: { label: "Hex", classes: ["0123456789abcdef"] },
  b64u: { label: "Base64url", classes: [GEN_LOWER + GEN_UPPER + GEN_DIGITS + "-_"] },
};
export const SECRET_LEN = { min: 8, max: 256, default: 32 };

function randomChars(alphabet, n) {
  // Rejection sampling: drop bytes >= the largest multiple of alphabet.length (no modulo bias).
  const limit = 256 - (256 % alphabet.length);
  let out = "";
  while (out.length < n) {
    for (const b of rand(Math.max(16, (n - out.length) * 2))) {
      if (b < limit) out += alphabet[b % alphabet.length];
      if (out.length === n) break;
    }
  }
  return out;
}

/** Generate a random secret. For multi-class types, every class appears at least once. */
export function generateSecret(type = "password", length = SECRET_LEN.default) {
  const spec = SECRET_TYPES[type];
  if (!spec) throw new Error(`unknown secret type: ${type}`);
  const n = Number(length);
  if (!Number.isInteger(n) || n < SECRET_LEN.min || n > SECRET_LEN.max) throw new Error(`length must be ${SECRET_LEN.min}-${SECRET_LEN.max}`);
  const all = spec.classes.join("");
  for (;;) {
    const s = randomChars(all, n);
    if (spec.classes.every((c) => [...s].some((ch) => c.includes(ch)))) return s;
  }
}

/** Approximate entropy in bits (uniform choice from the whole alphabet). */
export const secretBits = (type, length) => Math.floor(length * Math.log2(SECRET_TYPES[type].classes.join("").length));

// ---------- encrypted backups ----------
// A backup is the vault's ciphertext as the server stores it (unlockers, items, trash) plus an
// HMAC keyed from the vault key, so a tampered, truncated or mixed file is rejected on restore.
// Opening it needs the recovery key (or a passkey) that was current when the backup was made.

const BACKUP_FORMAT = "catarina-backup";

/** HMAC key for backups, derived from the raw vault key. Non-extractable. */
export async function backupMacKey(vkRaw) {
  const base = await crypto.subtle.importKey("raw", vkRaw, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: te.encode(`${V}/backup-mac`) },
    base, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign", "verify"]
  );
}

/** Canonical bytes covered by the MAC: field order fixed, unknown fields ignored. */
function backupCanonical(p) {
  return te.encode(JSON.stringify([
    BACKUP_FORMAT, 1, p.created_at, p.source,
    p.unlockers.map((u) => [u.id, u.kind, u.label, u.credential_id || null, u.salt, u.iv, u.ct]),
    p.items.map((i) => [i.id, i.version, i.blob]),
    p.trash.map((t) => [t.id, t.version, t.blob, t.deleted_at]),
  ]));
}

/** Build a signed backup object from server state (all fields are already ciphertext). */
export async function makeBackup(macKey, { source, unlockers, items, trash }) {
  const p = {
    format: BACKUP_FORMAT, v: 1, created_at: new Date().toISOString(), source: String(source || ""),
    unlockers: unlockers.map((u) => ({ id: u.id, kind: u.kind, label: u.label, credential_id: u.credential_id || null, salt: u.salt, iv: u.iv, ct: u.ct })),
    items: items.map((i) => ({ id: i.id, version: i.version, blob: i.blob })),
    trash: (trash || []).map((t) => ({ id: t.id, version: t.version, blob: t.blob, deleted_at: t.deleted_at })),
  };
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", macKey, backupCanonical(p)));
  return { ...p, mac: toB64u(mac) };
}

/** Parse + structurally check a backup file's text. Throws Error("bad_backup") if it isn't one. */
export function parseBackup(text) {
  let b;
  try { b = JSON.parse(text); } catch { throw new Error("bad_backup"); }
  const ok = b && b.format === BACKUP_FORMAT && b.v === 1 && typeof b.created_at === "string" && typeof b.mac === "string"
    && Array.isArray(b.unlockers) && Array.isArray(b.items) && Array.isArray(b.trash) && b.unlockers.some((u) => u && u.kind === "recovery");
  if (!ok) throw new Error("bad_backup");
  return b;
}

/**
 * Open a backup with its recovery key: returns the raw vault key after checking the MAC.
 * Throws "wrong_recovery_key" or "backup_tampered".
 */
export async function openBackup(b, recoveryKeyText) {
  const rk = parseRecoveryKey(recoveryKeyText);
  let vkRaw = null;
  try {
    for (const u of b.unlockers.filter((x) => x.kind === "recovery")) {
      try { vkRaw = await unwrapVaultKey(u, rk); break; } catch { /* next */ }
    }
  } finally { rk.fill(0); }
  if (!vkRaw) throw new Error("wrong_recovery_key");
  const macKey = await backupMacKey(vkRaw);
  let valid = false;
  try { valid = await crypto.subtle.verify("HMAC", macKey, fromB64u(b.mac), backupCanonical(b)); } catch { valid = false; }
  if (!valid) { vkRaw.fill(0); throw new Error("backup_tampered"); }
  return vkRaw;
}
