// Test fixture kurucuları (TS tarafı). Trust + data manifest'leri @noble ile
// imzalar, R2'yi seed'ler, CF Access ES256 JWT üretir. Worker VERIFY-ONLY
// olduğundan, imzalama (sign) YALNIZCA testte yapılır — Worker crypto'su asla
// imzalamaz. Body serileştirme Go-canonical OLMAK ZORUNDA DEĞİL: Worker
// depolanan TAM baytları hash'ler + parse eder; test uçtan uca kendi zincirini
// kurar (prev = sakladığı sarmalayıcının hash'i).

import { env, fetchMock, createExecutionContext, waitOnExecutionContext, runInDurableObject } from "cloudflare:test";
import worker from "../src/index.js";
import { AUDIT_DO_NAME } from "../src/audit.js";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import {
  bytesToB64,
  bytesToHex,
  fingerprint,
  fingerprintRecipient,
  sha256,
  sha256Hex,
  utf8,
} from "../src/crypto/verify.js";
import { keyBlob, keyCurrent, keyManifest, keyTrustCurrent, keyTrustManifest } from "../src/storage.js";

// --- İmzalama anahtarları (fixed → deterministik pin) -----------------------

function fixed(n: number): Uint8Array {
  return new Uint8Array(32).fill(n);
}

export interface Ed25519Key {
  seed: Uint8Array;
  pub: Uint8Array;
  keyID: string;
  pubB64: string;
  sign(msg: Uint8Array): Uint8Array; // sha256(msg) üzerinde 64-bayt
}
export function ed25519Key(seedByte: number): Ed25519Key {
  const seed = fixed(seedByte);
  const pub = ed25519.getPublicKey(seed);
  return {
    seed,
    pub,
    keyID: fingerprint(pub),
    pubB64: bytesToB64(pub),
    sign: (msg) => ed25519.sign(sha256(msg), seed),
  };
}

export interface P256Key {
  priv: Uint8Array;
  pub: Uint8Array; // 65B SEC1
  keyID: string;
  pubB64: string;
  alg: "ecdsa-p256-sha256";
  sign(msg: Uint8Array): Uint8Array; // compact 64-bayt r‖s over sha256(msg)
}
function p256Compact(sig: unknown): Uint8Array {
  const s = sig as { toBytes?: (f: string) => Uint8Array; toCompactRawBytes?: () => Uint8Array };
  if (typeof s.toBytes === "function") return s.toBytes("compact");
  if (typeof s.toCompactRawBytes === "function") return s.toCompactRawBytes();
  throw new Error("no compact serializer on p256 signature");
}
export function p256Key(privByte: number): P256Key {
  const priv = fixed(privByte);
  const pub = p256.getPublicKey(priv, false);
  return {
    priv,
    pub,
    keyID: fingerprint(pub),
    pubB64: bytesToB64(pub),
    alg: "ecdsa-p256-sha256",
    sign: (msg) => p256Compact(p256.sign(sha256(msg), priv, { lowS: false })),
  };
}

// --- Enc alıcı parmak izleri (Worker sadece string'i hash'ler) ---------------

export function recip(label: string): { pubkey: string; fp: string } {
  const pubkey = `age1${label}`;
  return { pubkey, fp: fingerprintRecipient(pubkey) };
}

// --- İmzalı sarmalayıcı üretimi (bytes = base64(body JSON)) -------------------

export interface SignedWrapper {
  wrapperStr: string;
  wrapperBytes: Uint8Array;
  objectSha256: string; // sha256 of the stored wrapper bytes (data manifest chaining)
}

function signWrapper(bodyObj: unknown, signers: { keyID: string; alg: string; sign(m: Uint8Array): Uint8Array }[]): SignedWrapper {
  const bodyStr = JSON.stringify(bodyObj);
  const bodyBytes = utf8(bodyStr);
  const sigs = signers.map((k) => ({
    schema: "wapps-secrets/sig/v1",
    key_id: k.keyID,
    alg: k.alg,
    sig: bytesToB64(k.sign(bodyBytes)),
  }));
  const wrapper = { bytes: bytesToB64(bodyBytes), sigs };
  const wrapperStr = JSON.stringify(wrapper);
  const wrapperBytes = utf8(wrapperStr);
  return { wrapperStr, wrapperBytes, objectSha256: bytesToHex(sha256(wrapperBytes)) };
}

// --- Trust genesis (deterministik) ------------------------------------------

export interface EncKeySpec {
  key_id: string;
  class: string;
  pubkey: string;
  media: string;
  added_at: number;
  status: string;
}
function encEntry(label: string, cls: string): EncKeySpec {
  const r = recip(label);
  return { key_id: r.fp, class: cls, pubkey: r.pubkey, media: "software", added_at: 1, status: "active" };
}

export interface TrustContext {
  pin: string;
  roots: Ed25519Key[];
  writer: P256Key;
  writerId: string;
  writerDevice: string; // fp
  writerBackup: string;
  reader: P256Key;
  readerId: string;
  readerDevice: string;
  readerBackup: string;
  escrowFp: string;
  // G7: admin (write-AUD API) + machine (token mint) fixture'ları.
  adminEmail: string;
  adminId: string;
  admin: P256Key; // admin presence-key (ceremony sign; API auth'unda kullanılmaz)
  machineCommonName: string; // service-token common_name → seedToMachineId
  machineId: string; // machine:<cn>
  machineKey: Ed25519Key; // automation writer signing key
  machineDevice: string; // machine device enc fp
  machineGrantKey: string; // makinenin read grant tuttuğu anahtar adı
}

/**
 * seedTrust, deterministik bir trust genesis kurar, 2-of-3 root ile imzalar,
 * R2'ye yazar (trust/manifests/1.json + trust/current) ve Worker env pin'ini
 * set eder. Tek sabit genesis tüm testleri besler. G7'de admin + machine kimlikleri
 * eklendi (grant'sız admin + MACHINE_KEY-only read grant → mevcut wrap-set testlerini
 * ETKİLEMEZ: requiredRecipients yalnızca read-grant'lı kimlikleri kapsar).
 */
export async function seedTrust(): Promise<TrustContext> {
  const roots = [ed25519Key(0x11), ed25519Key(0x12), ed25519Key(0x13)];
  const holder = "human:adnan@wapps.dev";
  const writer = p256Key(0x21); // writer daily key
  const reader = p256Key(0x22); // reader daily key
  const admin = p256Key(0x31); // admin presence key (P-256)
  const machineKey = ed25519Key(0x44); // automation writer signing key (Ed25519)
  const writerId = "human:writer@wapps.dev";
  const readerId = "human:reader@wapps.dev";
  const adminEmail = "admin@wapps.dev";
  const adminId = `human:${adminEmail}`;
  const machineCommonName = "ci-vaulter";
  const machineId = `machine:${machineCommonName}`;
  const machineGrantKey = "MACHINE_KEY";

  const wDev = encEntry("writer-device", "device");
  const wBak = encEntry("writer-backup", "backup");
  const rDev = encEntry("reader-device", "device");
  const rBak = encEntry("reader-backup", "backup");
  const aDev = encEntry("admin-device", "device");
  const aBak = encEntry("admin-backup", "backup");
  const mDev = encEntry("machine-device", "device");
  const escrow = encEntry("escrow-primary", "device");

  const body = {
    schema: "wapps-trust/v1",
    admin_epoch: 1,
    prev_trust_sha256: "",
    created_at: "2026-07-10T12:00:00Z",
    change_class: "roster",
    bootstrap_solo: true,
    quorum: { m: 2, n: 3 },
    roots: roots.map((r, i) => ({
      key_id: r.keyID,
      alg: "ed25519",
      pubkey: r.pubB64,
      media: ["yubikey-piv", "secure-enclave", "paper-steel"][i],
      holder,
      status: "active",
    })),
    admins: [adminId],
    identities: [
      {
        id: writerId,
        type: "human",
        enc_keys: [wDev, wBak],
        signing_keys: [{ key_id: writer.keyID, class: "daily", alg: "ecdsa-p256-sha256", pubkey: writer.pubB64, media: "secure-enclave", status: "active" }],
        status: "active",
      },
      {
        id: readerId,
        type: "human",
        enc_keys: [rDev, rBak],
        signing_keys: [{ key_id: reader.keyID, class: "daily", alg: "ecdsa-p256-sha256", pubkey: reader.pubB64, media: "secure-enclave", status: "active" }],
        status: "active",
      },
      {
        id: adminId,
        type: "human",
        enc_keys: [aDev, aBak],
        signing_keys: [{ key_id: admin.keyID, class: "admin", alg: "ecdsa-p256-sha256", pubkey: admin.pubB64, media: "yubikey-piv", status: "active" }],
        status: "active",
      },
      {
        id: machineId,
        type: "machine",
        enc_keys: [mDev],
        signing_keys: [{ key_id: machineKey.keyID, class: "automation", alg: "ed25519", pubkey: machineKey.pubB64, media: "software", status: "active" }],
        status: "active",
        rotate_by: "2099-01-01T00:00:00Z",
      },
      { id: "escrow:primary", type: "escrow", enc_keys: [escrow], signing_keys: [], status: "active" },
    ],
    grants: [
      { principal: writerId, project: "vaulter", verbs: ["read", "write"], keys: ["*"] },
      { principal: readerId, project: "vaulter", verbs: ["read"], keys: ["SHARED_KEY"] },
      { principal: machineId, project: "vaulter", verbs: ["read"], keys: [machineGrantKey] },
    ],
    writer_allowlists: [{ principal: machineId, project: "vaulter", keys: [machineGrantKey] }],
    worker_receipt_pubkey: { kid: "att-1", alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: "AAAA", y: "BBBB" } },
    worker_mint_pubkeys: [{ kid: "mint-2026-07", alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: "CCCC", y: "DDDD" } }],
  };

  const w = signWrapper(body, [roots[0], roots[1]].map((k) => ({ keyID: k.keyID, alg: "ed25519", sign: k.sign })));
  const pin = bytesToHex(sha256(utf8(JSON.stringify(body)))); // İMZALANAN payload hash (§4.2.2)

  await env.SECRETS_BUCKET.put(keyTrustManifest(1), w.wrapperBytes);
  await env.SECRETS_BUCKET.put(keyTrustCurrent(), utf8(JSON.stringify({ schema: "wapps-trust-current/v1", admin_epoch: 1, trustSha256: pin })));
  (env as unknown as { GENESIS_TRUST_SHA256: string }).GENESIS_TRUST_SHA256 = pin;

  return {
    pin,
    roots,
    writer,
    writerId,
    writerDevice: wDev.key_id,
    writerBackup: wBak.key_id,
    reader,
    readerId,
    readerDevice: rDev.key_id,
    readerBackup: rBak.key_id,
    escrowFp: escrow.key_id,
    adminEmail,
    adminId,
    admin,
    machineCommonName,
    machineId,
    machineKey,
    machineDevice: mDev.key_id,
    machineGrantKey,
  };
}

// --- Data manifest kurucu ---------------------------------------------------

export interface EntrySpec {
  keyName: string;
  keyVersion: number;
  blobHash: string;
  wraps: { recipient: string; wrap: string }[];
}

export function signDataManifest(
  opts: { project: string; epoch: number; prev: string; trustEpoch: number; entries: EntrySpec[] },
  writer: { keyID: string; alg: string; sign(m: Uint8Array): Uint8Array },
): SignedWrapper {
  const body = {
    schema: "wapps-secrets/data-manifest/v1",
    project: opts.project,
    epoch: opts.epoch,
    prevManifestSha256: opts.prev,
    trustEpoch: opts.trustEpoch,
    createdAt: "2026-07-10T12:30:00Z",
    entries: opts.entries.map((e) => ({
      keyName: e.keyName,
      keyVersion: e.keyVersion,
      blobHash: e.blobHash,
      wraps: e.wraps.map((w) => ({ recipient: w.recipient, wrap: btoa(w.wrap) })),
    })),
  };
  return signWrapper(body, [writer]);
}

/** clearBucket, R2'deki tüm objeleri siler (isolatedStorage:false için per-test temizlik). */
export async function clearBucket(): Promise<void> {
  let cursor: string | undefined;
  do {
    const l = await env.SECRETS_BUCKET.list({ cursor });
    for (const o of l.objects) await env.SECRETS_BUCKET.delete(o.key);
    cursor = l.truncated ? l.cursor : undefined;
  } while (cursor);
}

/** putBlob, bir blob objesini R2'ye içerik-adresli yazar; blobHash döner. */
export async function putBlob(project: string, bytes: Uint8Array): Promise<string> {
  const h = sha256Hex(bytes);
  await env.SECRETS_BUCKET.put(keyBlob(project, h), bytes);
  return h;
}

/** seedGenesisData, epoch-1 data manifest'i doğrudan R2'ye seed'ler (chaining testleri için). */
export async function seedManifestObject(project: string, epoch: number, wrapper: SignedWrapper): Promise<void> {
  await env.SECRETS_BUCKET.put(keyManifest(project, epoch), wrapper.wrapperBytes);
  await env.SECRETS_BUCKET.put(
    keyCurrent(project),
    utf8(JSON.stringify({ schema: "wapps-secrets/current/v1", project, epoch, manifestSha256: wrapper.objectSha256 })),
  );
}

// --- CF Access ES256 JWT (auth testleri) ------------------------------------

export interface AccessSigner {
  jwks: string; // JSON {keys:[jwk]}
  makeJWT(claims: Record<string, unknown>, opts?: { kid?: string; alg?: string }): Promise<string>;
}

function b64url(bytes: Uint8Array): string {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlStr(s: string): string {
  return b64url(utf8(s));
}

/** makeAccessSigner, bir ES256 keypair üretir; JWKS + JWT üretici döner (fetchMock ile servis edilir). */
export async function makeAccessSigner(kid = "test-kid"): Promise<AccessSigner> {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
  const jwk = { ...pubJwk, kid, alg: "ES256", use: "sig" };
  const jwks = JSON.stringify({ keys: [jwk] });
  return {
    jwks,
    async makeJWT(claims, o) {
      const header = { alg: o?.alg ?? "ES256", kid: o?.kid ?? kid, typ: "JWT" };
      const signingInput = `${b64urlStr(JSON.stringify(header))}.${b64urlStr(JSON.stringify(claims))}`;
      const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, utf8(signingInput)));
      return `${signingInput}.${b64url(sig)}`;
    },
  };
}

export const TEAM_DOMAIN = "test-team.cloudflareaccess.com";
export const AUD_READ = "aud-read-000000000000000000000000000000000000";
export const AUD_WRITE = "aud-write-00000000000000000000000000000000000";
export const ISSUER = `https://${TEAM_DOMAIN}`;
export const CERTS_URL = `https://${TEAM_DOMAIN}/cdn-cgi/access/certs`;
export const MINT_KID = "mint-test-1";
export const MINT_KID_PREV = "mint-test-0";
export const DISCORD_HOST = "https://discord.test";

// fetchMock ile yakalanan Discord alert POST'ları (§6.10 test doğrulaması).
export const discordCalls: { body: string }[] = [];

// Tek paylaşımlı signer + JWKS mock (singleWorker → tüm dosyalar aynı isolate;
// tek signer → auth.ts jwks cache'i tek anahtarla tutarlı, cross-file collision yok).
let _signer: AccessSigner | null = null;
let _mocksReady = false;

/** ensureJwks, paylaşımlı ES256 signer'ı + JWKS + Discord fetchMock'unu (bir kez) kurar. */
export async function ensureJwks(): Promise<AccessSigner> {
  if (!_signer) _signer = await makeAccessSigner();
  if (!_mocksReady) {
    fetchMock.activate();
    fetchMock.disableNetConnect();
    fetchMock.get(`https://${TEAM_DOMAIN}`).intercept({ path: "/cdn-cgi/access/certs" }).reply(200, _signer.jwks).persist();
    // Discord webhook: her alert POST'unu kaydet + 204 dön (net-connect kapalı
    // olduğu için TÜM alert yolları buradan geçmeli, yoksa fetchMock patlar).
    fetchMock
      .get(DISCORD_HOST)
      .intercept({ path: () => true, method: "POST" })
      .reply((opts: { body?: unknown }) => {
        discordCalls.push({ body: typeof opts.body === "string" ? opts.body : String(opts.body ?? "") });
        return { statusCode: 204, data: "" };
      })
      .persist();
    _mocksReady = true;
  }
  return _signer;
}

/** validClaims, geçerli bir human read-AUD JWT claim seti üretir (email override edilebilir). */
export function validClaims(email = "writer@wapps.dev", extra: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, aud: [AUD_READ], email, iat: now, nbf: now - 10, exp: now + 3600, ...extra };
}

/** validClaimsWrite, write-AUD (control-plane) human JWT claim seti (§6.9 admin). */
export function validClaimsWrite(email: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, aud: [AUD_WRITE], email, iat: now, nbf: now - 10, exp: now + 3600, ...extra };
}

/** serviceTokenClaims, CF Access SERVICE-TOKEN şekilli JWT claim seti (common_name, email YOK). */
export function serviceTokenClaims(commonName: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, aud: [AUD_READ], common_name: commonName, iat: now, nbf: now - 10, exp: now + 3600, ...extra };
}

/**
 * resetWorld, testler arası TAM izolasyon: R2 + RATE/JTI KV + D1 (audit/grants/
 * mirror_state/pending_ops) + AUDIT_LOG DO storage (zincir head genesis'e döner) +
 * discordCalls temizlenir. RATE global sayaç sızıntısını (429) önler; audit zinciri
 * her testte genesis'ten başlar. ATTESTATION DO SIFIRLANMAZ (anahtar kararlı kalmalı).
 */
export async function resetWorld(): Promise<void> {
  await clearBucket();
  // RATE + JTI deny-list KV temizle.
  for (const ns of [env.RATE, env.JTI_DENYLIST]) {
    let cursor: string | undefined;
    do {
      const l = await ns.list({ cursor });
      for (const k of l.keys) await ns.delete(k.name);
      cursor = l.list_complete ? undefined : l.cursor;
    } while (cursor);
  }
  // D1 tabloları (varsa) temizle. Şema henüz kurulmadıysa DELETE patlayabilir → yut.
  // trust_pin dahil: testler arası last-verified pin sızıntısı (§4.4) yanlış
  // TRUST_DOWNGRADE'lere yol açar (bir testin ilerlettiği epoch, sonrakinin genesis
  // seed'inin altında kalır) → her testte sıfırla.
  for (const table of ["audit", "grants", "mirror_state", "pending_ops", "trust_pin"]) {
    try {
      await env.AUDIT_DB.prepare(`DELETE FROM ${table}`).run();
    } catch {
      /* şema henüz yok — ilk erişimde kurulur */
    }
  }
  // AUDIT_LOG DO storage'ı sıfırla → zincir head genesis'e döner (idem marker'lar dahil).
  // vitest-pool-workers geçici invalidation'ında (modül reload) retry+backoff; kalıcı
  // olarak cold ise best-effort atla (cold DO'nun sıfırlanacak durumu yoktur).
  const auditStub = env.AUDIT_LOG.get(env.AUDIT_LOG.idFromName(AUDIT_DO_NAME));
  try {
    await runInDoRetry(auditStub, (_i: unknown, state: DurableObjectState) => state.storage.deleteAll());
  } catch (e) {
    if (!/invalidating|broken|please retry/i.test(String(e))) throw e; // yalnızca cold-DO invalidation'ı yut
  }
  discordCalls.length = 0;
}

/**
 * runInDoRetry, bir runInDurableObject çağrısını geçici DO invalidation'ında
 * (vitest-pool-workers modül reload) retry+backoff ile yeniden dener.
 */
export async function runInDoRetry<T>(stub: DurableObjectStub, fn: (instance: unknown, state: DurableObjectState) => T | Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await runInDurableObject(stub, fn as never);
    } catch (e) {
      if (attempt >= 10 || !/invalidating|broken|please retry/i.test(String(e))) throw e;
      await new Promise((r) => setTimeout(r, 5 * (attempt + 1)));
    }
  }
}

/**
 * callGate, Worker'ın fetch handler'ını doğrudan çağırır — dinamik genesis
 * pin'i per-çağrı env override ile geçer (SELF.fetch config-env snapshot'ını
 * kullandığından mutasyon propagate ETMEZ). DO, pin'i Worker-forwarded header'dan
 * alır, kendi env'inden değil.
 */
export async function callGate(path: string, init: RequestInit, pin: string): Promise<Response> {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`https://gate${path}`, init), { ...env, GENESIS_TRUST_SHA256: pin } as never, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

/** authHeader, bir JWT için Cf-Access-Jwt-Assertion header'ı üretir. */
export function authHeader(jwt: string, extra: Record<string, string> = {}): Record<string, string> {
  return { "Cf-Access-Jwt-Assertion": jwt, ...extra };
}
