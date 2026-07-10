// Per-project Durable Object write serializer (SPEC §6.2). idFromName=project →
// proje başına TEK linearize edilebilir yazar. Tüm commit transaction'ı
// blockConcurrencyWhile içinde çalışır: aynı projeye iki eşzamanlı yazımdan TAM
// OLARAK biri commit olur, diğeri 412 alır (CAS).
//
// KAPSAM (G6): imza + yazar-allowlist + M-of-N trust + epoch/prev zinciri +
// SEMANTİK DİFF authz (per-key grant, wrap-set eşitliği, shrink→re-key) + blob
// varlığı + manifest onlyIf-absent + pointer If-Match CAS + append-only pointer
// event. ERTELENDİ (G7): D1 audit DO (attempt/outcome satırları), freshness
// receipt, B2 escrow write-through, GC.

import { HTTP, jsonError, jsonOK } from "./errors.js";
import { parseSignedObject, utf8 } from "./crypto/verify.js";
import {
  DataManifest,
  KeyEntry,
  ManifestVerifyError,
  diffEntries,
  manifestObjectHash,
  parseCurrentPointer,
  parseManifestBody,
  recipientSet,
  verifyDataManifest,
  SCHEMA_CURRENT_POINTER,
} from "./manifest.js";
import {
  activeEscrowRecipients,
  findWriterSigningIdentity,
  requiredRecipients,
  verbKeyAllowed,
  writerKeyAllowed,
  TrustError,
  VerifiedEpoch,
  SIGN_CLASS_ADMIN,
  SIGN_CLASS_DAILY,
  TYPE_HUMAN,
  TYPE_MACHINE,
} from "./trust.js";
import { dataWriterKeyring, loadTrustHead } from "./trust-loader.js";
import {
  keyCurrent,
  keyManifest,
  keyBlob,
  keyPointerEvent,
  validKeyName,
  getObject,
  headEtag,
} from "./storage.js";

interface DOEnv {
  SECRETS_BUCKET: R2Bucket;
  GENESIS_TRUST_SHA256?: string;
}

/** CommitError, transaction içi tipli abort (ilk hata iptal eder, §6.2). */
class CommitError extends Error {
  constructor(public status: number, public code: string, public detail?: Record<string, unknown>) {
    super(code);
  }
  toResponse(): Response {
    return jsonError(this.status, this.code, this.code, this.detail);
  }
}

const AUTHZ_WRITE_VERB = "write"; // §6.3 verb kümesi (read|write|rotate)

// Pending pointer-event retry (§6.2 step-17 fail-soft). Pointer-event R2 yazımı
// başarısız olursa commit DÜŞMEZ; event DO storage'a "pending" işaretlenir ve alarm
// ile drene edilir. Marker key = <prefix><project>:<epoch>, value = {r2Key, body}.
const PENDING_POINTER_EVENT_PREFIX = "pending-pointer-event:";
const POINTER_EVENT_RETRY_MS = 30_000;

/** PendingPointerEvent, DO storage'da saklanan bekleyen pointer-event kaydı. */
interface PendingPointerEvent {
  r2Key: string;
  body: string; // orijinal JSON body — retry byte-bayt aynı immutable objeyi yazar.
}

export class ProjectWriterDO {
  private bucket: R2Bucket;
  private genesisSha: string;

  constructor(private ctx: DurableObjectState, env: DOEnv) {
    this.bucket = env.SECRETS_BUCKET;
    this.genesisSha = (env.GENESIS_TRUST_SHA256 ?? "").trim();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== "/commit" || request.method !== "POST") {
      return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "unknown DO route");
    }
    const project = url.searchParams.get("project") ?? "";
    const principalId = request.headers.get("x-principal-id") ?? "";
    // Genesis pin Worker-config'inden internal header ile gelir (fallback: DO env).
    const genesisPin = (request.headers.get("x-genesis-pin") ?? this.genesisSha).trim();
    const rawWrapper = await request.text();

    // Tüm transaction tek gate içinde → proje başına linearize (§6.2).
    return this.ctx.blockConcurrencyWhile(async () => {
      try {
        return await this.commit(project, principalId, rawWrapper, genesisPin);
      } catch (e) {
        if (e instanceof CommitError) return e.toResponse();
        if (e instanceof TrustError) {
          // Doğrulanamayan trust → asla ilerleme (§6.2 step 3).
          return jsonError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", e.message);
        }
        throw e;
      }
    });
  }

  private async commit(project: string, principalId: string, rawWrapper: string, genesisPin: string): Promise<Response> {
    const rawBytes = utf8(rawWrapper);

    // 1. Boyut (§6.2 step 1).
    if (rawBytes.length > 1_048_576) throw new CommitError(HTTP.PAYLOAD_TOO_LARGE, "MANIFEST_TOO_LARGE");

    // Sarmalayıcıyı çöz (imzalı BODY hâlâ ham; parse ETMEDEN doğrulanacak).
    let obj;
    try {
      obj = parseSignedObject(JSON.parse(rawWrapper));
    } catch {
      throw new CommitError(HTTP.UNPROCESSABLE, "MANIFEST_MALFORMED", { reason: "bad signed wrapper" });
    }

    // 3. CURRENT trust state'i yükle + M-of-N doğrula (§6.2 step 3).
    const head: VerifiedEpoch = await loadTrustHead(this.bucket, genesisPin);
    const ring = dataWriterKeyring(head.manifest);

    // 2/4. İmza TAM baytlar üzerinde + writer resolve (§6.2 step 2, verify-before-parse).
    let m: DataManifest;
    try {
      m = verifyDataManifest(obj, ring);
    } catch (e) {
      throw mapManifestError(e);
    }

    // Proje eşleşmesi (§5.2 rule 1).
    if (m.project !== project) throw new CommitError(HTTP.UNPROCESSABLE, "PROJECT_MISMATCH", { path: project, body: m.project });

    // keyName regex (§5.4.3 rule 1) + benzersizlik.
    const seenNames = new Set<string>();
    for (const e of m.entries) {
      if (!validKeyName(e.keyName)) throw new CommitError(HTTP.UNPROCESSABLE, "MANIFEST_MALFORMED", { reason: "invalid keyName", key: e.keyName });
      if (seenNames.has(e.keyName)) throw new CommitError(HTTP.UNPROCESSABLE, "MANIFEST_MALFORMED", { reason: "duplicate keyName", key: e.keyName });
      seenNames.add(e.keyName);
    }

    // 4. Writer allowlist: key_id enrolled + sınıfı data-write'a izin vermeli (§6.2 step 4).
    const writerKeyID = obj.sigs[0].key_id;
    const writer = findWriterSigningIdentity(head.manifest, writerKeyID);
    if (!writer) throw new CommitError(HTTP.FORBIDDEN, "WRITER_NOT_ALLOWED", { key_id: writerKeyID });
    const isHumanWriter = writer.cls === SIGN_CLASS_DAILY || writer.cls === SIGN_CLASS_ADMIN;
    const isAutomationWriter = writer.cls === "automation";
    if (!isHumanWriter && !isAutomationWriter) {
      // root/daily-on-trust vs. → data manifest yazamaz (§3.4 / §4.5).
      throw new CommitError(HTTP.FORBIDDEN, "WRITER_NOT_ALLOWED", { key_id: writerKeyID, class: writer.cls });
    }
    if (isHumanWriter && writer.identity.type !== TYPE_HUMAN) throw new CommitError(HTTP.FORBIDDEN, "WRITER_NOT_ALLOWED", { key_id: writerKeyID });
    if (isAutomationWriter && writer.identity.type !== TYPE_MACHINE) throw new CommitError(HTTP.FORBIDDEN, "WRITER_NOT_ALLOWED", { key_id: writerKeyID });

    // 5. Principal↔key binding (§6.2 step 5): oturum principal'ı key_id sahibi olmalı.
    if (principalId !== writer.identity.id) {
      throw new CommitError(HTTP.FORBIDDEN, "PRINCIPAL_KEY_MISMATCH", { principal: principalId, owner: writer.identity.id });
    }

    // 6. Epoch zinciri (§6.2 step 6): current pointer + current manifest.
    const curObj = await getObject(this.bucket, keyCurrent(project));
    let prevEntries: KeyEntry[] = [];
    let prevCurrentEtag: string | null = null;
    if (!curObj) {
      // Genesis.
      if (m.epoch !== 1 || m.prevManifestSha256 !== "") {
        throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: 0, current_manifest_sha256: "" });
      }
    } else {
      prevCurrentEtag = curObj.etag;
      const ptr = parseCurrentPointer(curObj.bytes);
      const curManifest = await getObject(this.bucket, keyManifest(project, ptr.epoch));
      if (!curManifest) throw new CommitError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: "current manifest missing" });
      const curHash = manifestObjectHash(curManifest.bytes);
      if (curHash !== ptr.manifestSha256) throw new CommitError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: "pointer/manifest hash mismatch" });
      if (m.epoch !== ptr.epoch + 1 || m.prevManifestSha256 !== curHash) {
        throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: ptr.epoch, current_manifest_sha256: curHash });
      }
      // Önceki girdiler için sarmalayıcıyı AÇ, sonra body'yi parse et (bytes =
      // stored wrapper). Zincir-bağı prevManifestSha256 == curHash zaten baytları
      // bağladığı için burada imza yeniden doğrulanmaz.
      const curSigned = parseSignedObject(JSON.parse(new TextDecoder().decode(curManifest.bytes)));
      prevEntries = parseManifestBody(curSigned.bytes).entries;
    }

    // 7. Trust freshness (§6.2 step 7): trustEpoch, trust/current epoch'undan eski olamaz.
    if (m.trustEpoch < head.manifest.admin_epoch) {
      throw new CommitError(HTTP.CONFLICT, "TRUST_EPOCH_STALE", { manifest_trust_epoch: m.trustEpoch, current_trust_epoch: head.manifest.admin_epoch });
    }

    // 8. Semantik diff — per-key grant (§6.2 step 8).
    const diff = diffEntries(prevEntries, m.entries);
    const touched = new Set<string>();
    for (const e of diff.added) touched.add(e.keyName);
    for (const c of diff.changed) touched.add(c.cur.keyName);
    for (const e of diff.removed) touched.add(e.keyName);
    for (const key of touched) {
      const allowed = isAutomationWriter
        ? writerKeyAllowed(head.manifest, principalId, project, key)
        : verbKeyAllowed(head.manifest, principalId, project, AUTHZ_WRITE_VERB, key);
      if (!allowed) throw new CommitError(HTTP.FORBIDDEN, "GRANT_DENIED", { key });
    }

    // 9. Semantik diff — gerekli wrap-set eşitliği (§6.2 step 9).
    const escrow = activeEscrowRecipients(head.manifest);
    for (const e of m.entries) {
      const req = requiredRecipients(head.manifest, project, e.keyName);
      const have = recipientSet(e);
      const missing = [...req].filter((r) => !have.has(r));
      const extra = [...have].filter((r) => !req.has(r));
      const missingEscrow = missing.find((r) => escrow.has(r));
      if (missingEscrow) throw new CommitError(HTTP.UNPROCESSABLE, "ESCROW_WRAP_MISSING", { key: e.keyName, recipient: missingEscrow });
      if (missing.length > 0) throw new CommitError(HTTP.FORBIDDEN, "WRAPSET_VIOLATION", { key: e.keyName, recipient: missing[0], reason: "missing" });
      if (extra.length > 0) throw new CommitError(HTTP.FORBIDDEN, "WRAPSET_VIOLATION", { key: e.keyName, recipient: extra[0], reason: "unauthorized" });
    }

    // 10. Semantik diff — shrink re-key'i zorlar (§6.2 step 10).
    for (const c of diff.changed) {
      const oldSet = recipientSet(c.old);
      const newSet = recipientSet(c.cur);
      const removed = [...oldSet].filter((r) => !newSet.has(r));
      if (removed.length > 0) {
        // Re-key: keyVersion tam +1 (§5.4.3 rule 2) VE blob hash değişti (§6.2 step 10).
        const reKeyed = c.cur.keyVersion === c.old.keyVersion + 1 && c.cur.blobHash !== c.old.blobHash;
        if (!reKeyed) throw new CommitError(HTTP.FORBIDDEN, "WRAPSET_VIOLATION", { key: c.cur.keyName, reason: "wrap-shrink without re-key" });
      }
    }

    // 11. Blob bağları (§6.2 step 11): her blobHash R2'de var olmalı (içerik-adresli).
    const missingBlobs: string[] = [];
    const checkedBlobs = new Set<string>();
    for (const e of m.entries) {
      if (checkedBlobs.has(e.blobHash)) continue;
      checkedBlobs.add(e.blobHash);
      const et = await headEtag(this.bucket, keyBlob(project, e.blobHash));
      if (!et) missingBlobs.push(e.blobHash);
    }
    if (missingBlobs.length > 0) throw new CommitError(HTTP.UNPROCESSABLE, "BLOB_MISSING", { hashes: missingBlobs });

    // 12. Audit ATTEMPT — ERTELENDİ (G7 D1 audit DO).

    // 13. Manifest yaz (§6.2 step 13): onlyIf-absent (gate içinde HEAD + put).
    const newManifestSha = manifestObjectHash(rawBytes);
    const manifestKey = keyManifest(project, m.epoch);
    if (await headEtag(this.bucket, manifestKey)) {
      throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: m.epoch - 1, reason: "manifest already exists" });
    }
    const wrote = await this.bucket.put(manifestKey, rawBytes, { onlyIf: { etagDoesNotMatch: "*" } });
    if (wrote === null) throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: m.epoch - 1, reason: "manifest already exists" });

    // 14. Pointer CAS (§6.2 step 14): If-Match prev etag (genesis'te onlyIf-absent).
    const pointerBody = utf8(
      JSON.stringify({ schema: SCHEMA_CURRENT_POINTER, project, epoch: m.epoch, manifestSha256: newManifestSha }),
    );
    if (prevCurrentEtag === null) {
      // Genesis: current henüz yok.
      const created = await this.bucket.put(keyCurrent(project), pointerBody, { onlyIf: { etagDoesNotMatch: "*" } });
      if (created === null) throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: 0, reason: "current already created" });
    } else {
      const updated = await this.bucket.put(keyCurrent(project), pointerBody, { onlyIf: { etagMatches: prevCurrentEtag } });
      if (updated === null) throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { reason: "pointer CAS lost (out-of-band mutation)" });
    }

    // 15. Audit OUTCOME — ERTELENDİ (G7).

    // 17. Escrow write-through: B2 push ERTELENDİ (G7), ama append-only pointer
    // event R2'ye yazılır (§9.2.3 / F2) — immutable, onlyIf-absent.
    //
    // §6.2(d)/step-17: pointer-event/escrow-push HATASI commit'i DÜŞÜREMEZ. Commit
    // bu noktada pointer CAS ile ZATEN kalıcı; transient bir R2 hatası buradan 5xx'e
    // dönüşürse çağıran commit'in başarısız olduğunu sanır (yanlış — ledger çift
    // yazımı vb. tetikler). Best-effort: hata → DO storage'a "pending" marker + alarm
    // retry + alert, ama kalıcı commit için YİNE 200 dön.
    const eventR2Key = keyPointerEvent(project, m.epoch);
    const eventBody = JSON.stringify({
      schema: "wapps.pointer-event.v1",
      project,
      epoch: m.epoch,
      manifestSha256: newManifestSha,
      committed_at: new Date().toISOString(),
    });
    try {
      await this.bucket.put(eventR2Key, utf8(eventBody), { onlyIf: { etagDoesNotMatch: "*" } });
    } catch (err) {
      // Kalıcı commit'i düşürme: retry kuyruğuna al + alert, ama 200 dön.
      console.error(`writer-do: pointer-event write failed, queued for retry (project=${project} epoch=${m.epoch})`, err);
      await this.enqueuePendingPointerEvent(project, m.epoch, eventR2Key, eventBody);
    }

    // 18. Yanıt (freshness receipt G7'ye ertelendi).
    return jsonOK({ epoch: m.epoch, manifestSha256: newManifestSha });
  }

  /**
   * enqueuePendingPointerEvent, R2'ye yazılamayan bir pointer-event'i DO storage'a
   * "pending" olarak kaydeder ve drenaj için bir alarm zamanlar (§6.2 step-17
   * fail-soft). Body AYNEN saklanır ki retry byte-bayt aynı immutable objeyi yazsın.
   */
  private async enqueuePendingPointerEvent(project: string, epoch: number, r2Key: string, body: string): Promise<void> {
    const rec: PendingPointerEvent = { r2Key, body };
    await this.ctx.storage.put(`${PENDING_POINTER_EVENT_PREFIX}${project}:${epoch}`, rec);
    // Tek alarm tüm bekleyenleri drene eder; mevcut alarmı ezmek zararsız (en erken
    // zamanı korumak yerine sabit gecikme — basit ve yeterli).
    await this.ctx.storage.setAlarm(Date.now() + POINTER_EVENT_RETRY_MS);
  }

  /**
   * alarm, DO storage'daki bekleyen pointer-event'leri drene eder (§6.2 step-17).
   * Her yazım idempotent onlyIf-absent'tir: obje zaten varsa put null döner (hata
   * DEĞİL) → marker temizlenir. Transient hata → marker kalır + alarm yeniden
   * zamanlanır (sonsuz-döngü değil; başarı her kaydı tek tek düşürür).
   */
  async alarm(): Promise<void> {
    const pending = await this.ctx.storage.list<PendingPointerEvent>({ prefix: PENDING_POINTER_EVENT_PREFIX });
    let remaining = 0;
    for (const [storageKey, rec] of pending) {
      try {
        // onlyIf-absent: zaten yazılmışsa null döner (idempotent) → yine temizle.
        await this.bucket.put(rec.r2Key, utf8(rec.body), { onlyIf: { etagDoesNotMatch: "*" } });
        await this.ctx.storage.delete(storageKey);
      } catch (err) {
        remaining++; // hâlâ transient → bırak, bir sonraki alarm tekrar dener.
        console.error(`writer-do: pointer-event retry still failing (${storageKey})`, err);
      }
    }
    if (remaining > 0) await this.ctx.storage.setAlarm(Date.now() + POINTER_EVENT_RETRY_MS);
  }
}

/** mapManifestError, verifyDataManifest hatalarını §6.2 error contract'ına eşler. */
function mapManifestError(e: unknown): CommitError {
  if (e instanceof ManifestVerifyError) {
    const me = e;
    switch (me.code) {
      case "BAD_SIGNATURE_COUNT":
        return new CommitError(HTTP.UNPROCESSABLE, "BAD_SIGNATURE_COUNT");
      case "WRITER_UNKNOWN":
        return new CommitError(HTTP.FORBIDDEN, "WRITER_NOT_ALLOWED", { key_id: me.message });
      case "SIG_INVALID":
        return new CommitError(HTTP.FORBIDDEN, "SIG_INVALID");
      case "UNSUPPORTED_SCHEMA":
        return new CommitError(HTTP.UNPROCESSABLE, "UNSUPPORTED_SCHEMA", { schema: me.message });
      default:
        return new CommitError(HTTP.UNPROCESSABLE, "MANIFEST_MALFORMED", { reason: me.message });
    }
  }
  return new CommitError(HTTP.UNPROCESSABLE, "MANIFEST_MALFORMED");
}
