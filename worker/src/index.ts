// secrets-gate Worker entrypoint (SPEC §6). Router + read endpoints (DO-free) +
// auth middleware + blob PUT + commit dispatch (PROJECT_WRITER DO).
//
// G6 KAPSAM: read/commit/blob data-plane + CF Access auth + M-of-N trust okuma +
// semantik-diff authz (DO). ERTELENDİ (G7): machine-token mint/verify, D1 audit,
// freshness receipt, B2 escrow, admin API, GC, rate-limit.

import { Env, AuthFail, authenticate, loadAccessConfig, stripForgeableHeaders, Principal } from "./auth.js";
import { HTTP, jsonError } from "./errors.js";
import { sha256Hex } from "./crypto/verify.js";
import {
  keyBlob,
  keyCurrent,
  keyManifest,
  keyTrustCurrent,
  keyTrustManifest,
  getObject,
  validProject,
  validSha256Hex,
} from "./storage.js";
import { parseCurrentPointer } from "./manifest.js";
import { loadTrustHead } from "./trust-loader.js";
import { hasVerbGrant, identityByID, TrustError } from "./trust.js";
import { ProjectWriterDO } from "./writer-do.js";

export { ProjectWriterDO };

const BLOB_CAP = 65_536; // §5.7
const BLOB_OVERHEAD = 4 + 24 + 16; // magic + XChaCha nonce + Poly1305 tag (§3.5.4)

/** validFramingLength, depolanan blob uzunluğunun §3 padding-kova framing'ine uyduğunu doğrular. */
function validFramingLength(len: number): boolean {
  const bucket = len - BLOB_OVERHEAD;
  if (bucket === 256 || bucket === 1024) return true;
  const maxBucket = Math.floor((BLOB_CAP - BLOB_OVERHEAD) / 4096) * 4096; // 61440
  return bucket >= 4096 && bucket <= maxBucket && bucket % 4096 === 0;
}

function etagResponse(bytes: Uint8Array, etag: string, ifNoneMatch: string | null, contentType: string): Response {
  const quoted = `"${etag}"`;
  if (ifNoneMatch && ifNoneMatch.replace(/^W\//, "").trim() === quoted) {
    return new Response(null, { status: HTTP.NOT_MODIFIED, headers: { ETag: quoted } });
  }
  return new Response(bytes, { status: HTTP.OK, headers: { "content-type": contentType, ETag: quoted } });
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    // Fail-closed config (§6 intro): eksik → 503 tüm rotalarda.
    const cfg = loadAccessConfig(env);
    if (!cfg) return jsonError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", "access config missing");
    if (!(env.GENESIS_TRUST_SHA256 ?? "").trim()) return jsonError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", "genesis pin missing");

    // Forgeable Access header'ı her istekten strip et (§6.1 step 8).
    request = stripForgeableHeaders(request);

    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter((p) => p !== "");
    // Beklenen: v1 / ...
    if (parts[0] !== "v1") return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "unknown route");

    try {
      // Tüm v1 rotaları CF Access read-AUD gerektirir (data plane, §6.1/§6 route table).
      const principal = await authenticate(request, cfg, "read");

      // trust/current, trust/{epoch} (herhangi bir enrolled principal).
      if (parts[1] === "trust") {
        return await handleTrustRead(request, env, parts, principal);
      }

      // projects/{project}/...
      if (parts[1] === "projects" && parts.length >= 4) {
        const project = parts[2];
        if (!validProject(project)) return jsonError(HTTP.UNPROCESSABLE, "PROJECT_MISMATCH", "invalid project segment");
        const kind = parts[3];

        if (kind === "manifests" && request.method === "GET") {
          return await handleManifestRead(request, env, project, parts[4], principal);
        }
        if (kind === "blobs" && parts.length === 5) {
          const sha = parts[4];
          if (!validSha256Hex(sha)) return jsonError(HTTP.BAD_REQUEST, "BLOB_HASH_MISMATCH", "invalid blob address");
          if (request.method === "GET") return await handleBlobRead(request, env, project, sha, principal);
          if (request.method === "PUT") return await handleBlobPut(request, env, project, sha, principal);
        }
        if (kind === "commit" && request.method === "POST") {
          return await handleCommit(request, env, project, principal);
        }
      }
      return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "unknown route");
    } catch (e) {
      if (e instanceof AuthFail) return e.toResponse();
      if (e instanceof TrustError) return jsonError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", e.message);
      throw e;
    }
  },
};

// --- Data-plane confinement (§6.1 step 8): seed → minted token gerekir (G7) ---

function requireHuman(principal: Principal): void {
  if (principal.kind === "seed") {
    // Minted machine-token doğrulaması G7'de; G6'da seed data-plane'e giremez.
    throw new AuthFail(HTTP.FORBIDDEN, "MACHINE_TOKEN_REQUIRED", "service token needs a minted machine token (G7)");
  }
}

async function trustHeadOr503(env: Env) {
  return loadTrustHead(env.SECRETS_BUCKET, (env.GENESIS_TRUST_SHA256 ?? "").trim());
}

// --- Read handlers (DO-free, §5.5 rule 5) ----------------------------------

async function handleTrustRead(_request: Request, env: Env, parts: string[], principal: Principal): Promise<Response> {
  requireHuman(principal);
  const head = await trustHeadOr503(env);
  // Herhangi bir enrolled principal (§6 route table).
  if (!identityByID(head.manifest, principal.id)) return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "not an enrolled identity");
  const ifNoneMatch = _request.headers.get("if-none-match");
  if (parts[2] === "current") {
    const o = await getObject(env.SECRETS_BUCKET, keyTrustCurrent());
    if (!o) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "trust/current not found");
    return etagResponse(o.bytes, sha256Hex(o.bytes), ifNoneMatch, "application/json");
  }
  const epoch = Number(parts[2]);
  if (!Number.isInteger(epoch) || epoch < 1) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "bad trust epoch");
  const o = await getObject(env.SECRETS_BUCKET, keyTrustManifest(epoch));
  if (!o) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "trust epoch not found");
  return etagResponse(o.bytes, sha256Hex(o.bytes), ifNoneMatch, "application/json");
}

async function handleManifestRead(request: Request, env: Env, project: string, sel: string, principal: Principal): Promise<Response> {
  requireHuman(principal);
  const head = await trustHeadOr503(env);
  if (!hasVerbGrant(head.manifest, principal.id, project, "read")) {
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "no read grant in project");
  }
  const ifNoneMatch = request.headers.get("if-none-match");

  if (sel === "current") {
    const cur = await getObject(env.SECRETS_BUCKET, keyCurrent(project));
    if (!cur) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "no current manifest");
    const ptr = parseCurrentPointer(cur.bytes);
    // ETag = manifestSha256 (içerik-adresli, kararlı); 304 conditional.
    if (ifNoneMatch && ifNoneMatch.replace(/^W\//, "").trim() === `"${ptr.manifestSha256}"`) {
      return new Response(null, { status: HTTP.NOT_MODIFIED, headers: { ETag: `"${ptr.manifestSha256}"` } });
    }
    const man = await getObject(env.SECRETS_BUCKET, keyManifest(project, ptr.epoch));
    if (!man) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "current manifest object missing");
    return etagResponse(man.bytes, ptr.manifestSha256, ifNoneMatch, "application/json");
  }

  const epoch = Number(sel);
  if (!Number.isInteger(epoch) || epoch < 1) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "bad epoch");
  const man = await getObject(env.SECRETS_BUCKET, keyManifest(project, epoch));
  if (!man) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "manifest not found");
  return etagResponse(man.bytes, sha256Hex(man.bytes), ifNoneMatch, "application/json");
}

async function handleBlobRead(request: Request, env: Env, project: string, sha: string, principal: Principal): Promise<Response> {
  requireHuman(principal);
  const head = await trustHeadOr503(env);
  // G6: proje-seviyesi read grant. Kesin blob→key eşlemesi (§6.3) G7 rafinesi.
  if (!hasVerbGrant(head.manifest, principal.id, project, "read")) {
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "no read grant in project");
  }
  const o = await getObject(env.SECRETS_BUCKET, keyBlob(project, sha));
  if (!o) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "blob not found");
  const ifNoneMatch = request.headers.get("if-none-match");
  return etagResponse(o.bytes, sha, ifNoneMatch, "application/octet-stream");
}

// --- Blob PUT (§6.2 blob upload; Worker-level, content-addressed idempotent) --

async function handleBlobPut(request: Request, env: Env, project: string, sha: string, principal: Principal): Promise<Response> {
  requireHuman(principal);
  const head = await trustHeadOr503(env);
  if (!hasVerbGrant(head.manifest, principal.id, project, "write")) {
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "no write grant in project");
  }
  const body = new Uint8Array(await request.arrayBuffer());
  if (body.length > BLOB_CAP) return jsonError(HTTP.PAYLOAD_TOO_LARGE, "BLOB_TOO_LARGE", "blob exceeds 64 KB");
  if (!validFramingLength(body.length)) return jsonError(HTTP.BAD_REQUEST, "PADDING_INVALID", "blob length not a valid framing length");
  const got = sha256Hex(body);
  if (got !== sha) return jsonError(HTTP.BAD_REQUEST, "BLOB_HASH_MISMATCH", "bytes do not hash to path");
  // İçerik-adresli, idempotent: aynı hash zaten varsa no-op success (§5.3 rule 4).
  const existing = await env.SECRETS_BUCKET.head(keyBlob(project, sha));
  if (!existing) await env.SECRETS_BUCKET.put(keyBlob(project, sha), body, { onlyIf: { etagDoesNotMatch: "*" } });
  return new Response(JSON.stringify({ sha256: sha }), { status: HTTP.OK, headers: { "content-type": "application/json" } });
}

// --- Commit dispatch → PROJECT_WRITER DO (§6.2) -----------------------------

async function handleCommit(request: Request, env: Env, project: string, principal: Principal): Promise<Response> {
  requireHuman(principal);
  const rawWrapper = await request.text();
  const id = env.PROJECT_WRITER.idFromName(project);
  const stub = env.PROJECT_WRITER.get(id);
  const doReq = new Request(`https://do/commit?project=${encodeURIComponent(project)}`, {
    method: "POST",
    // Genesis pin Worker config'inden gelir (client-supplied DEĞİL) ve DO'ya
    // internal header ile iletilir — DO'nun kendi env timing'ine bağımlılığı olmasın.
    headers: { "content-type": "application/json", "x-principal-id": principal.id, "x-genesis-pin": (env.GENESIS_TRUST_SHA256 ?? "").trim() },
    body: rawWrapper,
  });
  return stub.fetch(doReq);
}
