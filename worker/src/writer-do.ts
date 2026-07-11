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
  validSha256Hex,
  getObject,
  headEtag,
} from "./storage.js";
import { auditAppendSync, AuditRow, PrincipalType } from "./audit.js";
import { TokenScope, scopeAllowsVerb, scopeAllowsKey } from "./mint.js";
import {
  EscrowConfig,
  EscrowEnv,
  escrowConfig,
  enqueueEscrowPushes,
  drainEscrowPushes,
  EscrowPushItem,
  escrowRetryMs,
} from "./escrow.js";
import { deliverAlert, ALERT } from "./alerts.js";

interface DOEnv extends EscrowEnv {
  SECRETS_BUCKET: R2Bucket;
  GENESIS_TRUST_SHA256?: string;
  // AUDIT_LOG: TEK global audit DO (§6.5). Commit attempt/outcome satırları BURADAN
  // SENKRON geçer — erişilemezse commit fail-closed (503 AUDIT_UNAVAILABLE).
  AUDIT_LOG: DurableObjectNamespace;
  // AUDIT_DB: last-verified trust pin aynası (§4.4). loadTrustHead downgrade tavanını
  // buradan yaptırır + doğrulanmış head'i monotonik kalıcılaştırır.
  AUDIT_DB: D1Database;
  // §6.8 escrow write-through: B2 hedefi + alert kanalı (fail-soft push).
  DISCORD_WEBHOOK_URL?: string;
}

/** ReqMeta, bir commit isteğinin principal/audit metadatası (Worker header'larından). */
interface ReqMeta {
  principalId: string;
  principalType: PrincipalType;
  tokenJti: string | null;
  // tokenScope: minted machine-token'ın scope'u (Worker'ın x-token-scope header'ından).
  // İnsan principal'larında null (CF-Access JWT scope taşımaz). §6.3 grants ∩ token scope.
  tokenScope: TokenScope | null;
  intent: string | null;
  ip: string | null;
  cfRay: string | null;
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
const PENDING_OUTCOME_PREFIX = "pending-audit-outcome:";
const POINTER_EVENT_RETRY_MS = 30_000;
// ESCROW_CONFIG_KEY: escrow config'in DO storage'a persist edildiği anahtar. ÜRETİMDE
// KULLANILMAZ (config env'den gelir, this.escrow); yalnızca bir dormant fallback —
// env config null iken storage'dan okunur. Test, config'i runInDurableObject ile
// buraya yazar; böylece config bir DO instance-recreation (modül reload) SONRASI
// SAĞ KALIR (this.escrow instance ile silinir, storage silinmez).
const ESCROW_CONFIG_KEY = "escrow-config";

/** PendingPointerEvent, DO storage'da saklanan bekleyen pointer-event kaydı. */
interface PendingPointerEvent {
  r2Key: string;
  body: string; // orijinal JSON body — retry byte-bayt aynı immutable objeyi yazar.
}

/** PendingOutcome, CAS sonrası yazılamayan audit outcome satırı (§6.2 case c recovery). */
interface PendingOutcome {
  row: AuditRow;
  idempotencyKey: string; // `${project}:${epoch}` — DO append idempotent dedup marker
}

export class ProjectWriterDO {
  private bucket: R2Bucket;
  private genesisSha: string;
  // AUDIT_DB: last-verified trust pin aynası (§4.4) — loadTrustHead'e geçilir.
  private auditDb: D1Database;
  // AUDIT_LOG namespace — testte runInDurableObject ile "unavailable" enjekte edilebilir.
  private auditLog: DurableObjectNamespace;
  // §6.8 escrow write-through config (null = B2 yapılandırılmamış → no-op).
  // Testte runInDurableObject ile enjekte edilebilir (instance.escrow = cfg).
  private escrow: EscrowConfig | null;
  private discordUrl: string;

  constructor(private ctx: DurableObjectState, env: DOEnv) {
    this.bucket = env.SECRETS_BUCKET;
    this.genesisSha = (env.GENESIS_TRUST_SHA256 ?? "").trim();
    this.auditDb = env.AUDIT_DB;
    this.auditLog = env.AUDIT_LOG;
    this.escrow = escrowConfig(env);
    this.discordUrl = (env.DISCORD_WEBHOOK_URL ?? "").trim();
  }

  /** escrowAlert, drenaj sırasında A4 (§6.10) tetikler (best-effort, throw etmez). */
  private escrowAlert = async (rule: string, summary: string, detail?: Record<string, unknown>): Promise<void> => {
    await deliverAlert({ DISCORD_WEBHOOK_URL: this.discordUrl, AUDIT_LOG: this.auditLog }, rule as typeof ALERT.A4, summary, detail);
  };

  /** effectiveEscrow, etkin escrow config'i çözer: env config (üretim, this.escrow)
   * yoksa DO storage'daki dormant fallback (test seam — instance-recreation'a dayanıklı). */
  private async effectiveEscrow(): Promise<EscrowConfig | null> {
    if (this.escrow) return this.escrow;
    return (await this.ctx.storage.get<EscrowConfig>(ESCROW_CONFIG_KEY)) ?? null;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== "/commit" || request.method !== "POST") {
      return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "unknown DO route");
    }
    const project = url.searchParams.get("project") ?? "";
    const meta: ReqMeta = {
      principalId: request.headers.get("x-principal-id") ?? "",
      principalType: (request.headers.get("x-principal-type") as PrincipalType) || "human",
      tokenJti: emptyToNull(request.headers.get("x-token-jti")),
      tokenScope: parseTokenScope(request.headers.get("x-token-scope")),
      intent: emptyToNull(request.headers.get("x-intent")),
      ip: emptyToNull(request.headers.get("x-cf-ip")),
      cfRay: emptyToNull(request.headers.get("x-cf-ray")),
    };
    // Genesis pin Worker-config'inden internal header ile gelir (fallback: DO env).
    const genesisPin = (request.headers.get("x-genesis-pin") ?? this.genesisSha).trim();
    const rawWrapper = await request.text();

    // Tüm transaction tek gate içinde → proje başına linearize (§6.2).
    return this.ctx.blockConcurrencyWhile(async () => {
      try {
        return await this.commit(project, meta, rawWrapper, genesisPin);
      } catch (e) {
        if (e instanceof CommitError) {
          // Red → deny satırı ekle (§6.2/§6.5 — denials her zaman kaydedilir).
          // İSTİSNA: AUDIT_UNAVAILABLE'ın kendisi (audit down → deny de yazılamaz).
          if (e.code !== "AUDIT_UNAVAILABLE") {
            await this.appendDeny(project, meta, e).catch(() => {});
          }
          return e.toResponse();
        }
        if (e instanceof TrustError) {
          // Doğrulanamayan trust → asla ilerleme (§6.2 step 3).
          return jsonError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", e.message);
        }
        throw e;
      }
    });
  }

  private async commit(project: string, meta: ReqMeta, rawWrapper: string, genesisPin: string): Promise<Response> {
    const principalId = meta.principalId;
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
    const head: VerifiedEpoch = await loadTrustHead(this.bucket, genesisPin, this.auditDb);
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

    // 8b. Makine principal'ları: efektif izin = grants ∩ token scope (§6.3 / §6.2 step 8).
    // Kimlik write-allowlist'i GENİŞ olsa bile, token DAR mint edilmişse (ör. verbs:["read"]
    // veya keys:["A"]) commit REDDEDİLİR — least-privilege enforcement point. Makine için
    // scope ZORUNLUDUR (Worker minted token'dan türetir); eksik/geçersizse fail-closed.
    // İnsan principal'larının (CF-Access JWT) token scope'u yoktur → etkilenmez.
    if (meta.principalType === "machine") {
      const scope = meta.tokenScope;
      if (!scope || !scopeAllowsVerb(scope, AUTHZ_WRITE_VERB)) {
        throw new CommitError(HTTP.FORBIDDEN, "TOKEN_SCOPE_EXCEEDED", { reason: "token scope lacks write verb" });
      }
      for (const key of touched) {
        if (!scopeAllowsKey(scope, key)) throw new CommitError(HTTP.FORBIDDEN, "TOKEN_SCOPE_EXCEEDED", { key });
      }
    }

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

    // 11. Blob bağları (§6.2 step 11): her blobHash KANONİK küçük-harf 64-hex olmalı
    // + R2'de var olmalı (içerik-adresli).
    //
    // İÇERİK-ADRESİ değişmezliği: blob PUT (index.ts handleBlobPut) hem path'i
    // validSha256Hex ile (küçük-harf 64-hex) hem sha256(body)===path ile yaptırır →
    // R2'de saklanan HER blob küçük-harf-hex anahtar altında + içerik-adreslidir. Bu
    // yüzden commit-zamanı YENİDEN-HASH GEREKSİZDİR: kanonik bir blobHash'e karşılık
    // gelen mevcut bir R2 objesi zaten byte'larıyla o hash'e çözülür → Go okuyucunun
    // read.go re-hash'i (VerifyBlobHash) geçer. Non-kanonik (büyük-harf/kısa) bir
    // blobHash'i REDDET: Go okuyucu blob'u Worker'ın küçük-harf-only GET'inden
    // (validSha256Hex) HİÇ çekemez → ilerletilmiş `current` OKUNAMAZ manifest'e işaret
    // ederdi (accept/read split). Go ParseManifestBody blobHash biçimini denetlemez, ama
    // accept-gate'i olan Worker, kendi GET'inin reddedeceği bir referansı kabul etmemeli.
    const missingBlobs: string[] = [];
    const checkedBlobs = new Set<string>();
    for (const e of m.entries) {
      if (!validSha256Hex(e.blobHash)) throw new CommitError(HTTP.UNPROCESSABLE, "MANIFEST_MALFORMED", { reason: "blobHash not lowercase 64-hex", key: e.keyName });
      if (checkedBlobs.has(e.blobHash)) continue;
      checkedBlobs.add(e.blobHash);
      const et = await headEtag(this.bucket, keyBlob(project, e.blobHash));
      if (!et) missingBlobs.push(e.blobHash);
    }
    if (missingBlobs.length > 0) throw new CommitError(HTTP.UNPROCESSABLE, "BLOB_MISSING", { hashes: missingBlobs });

    // 12. Audit ATTEMPT (SENKRON, §6.2 step 12): manifest yazımından ÖNCE global
    // audit DO'ya `commit.attempt` satırı. Audit DO erişilemezse commit BURADA
    // fail-close olur (503 AUDIT_UNAVAILABLE) — henüz HİÇBİR ŞEY yazılmadı (F7).
    const changedKeys = [...touched];
    try {
      await auditAppendSync(this.auditLog, {
        principal: principalId,
        principal_type: meta.principalType,
        project,
        key: changedKeys.length === 1 ? changedKeys[0] : null,
        verb: "commit.attempt",
        decision: "allow",
        intent: meta.intent ?? (changedKeys.length > 1 ? `keys:${changedKeys.length}` : null),
        ip: meta.ip,
        cf_ray: meta.cfRay,
        token_jti: meta.tokenJti,
      });
    } catch {
      // Fail closed: hiçbir store durumu değişmedi.
      throw new CommitError(HTTP.MISCONFIGURED, "AUDIT_UNAVAILABLE", { reason: "audit DO unavailable at attempt" });
    }

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

    // 15. Audit OUTCOME (SENKRON, YALNIZCA pointer CAS başarılı olduktan SONRA,
    // §6.2 step 15): `commit` allow satırı, idempotency-key `${project}:${epoch}`.
    // OUTCOME satırı — attempt DEĞİL — başarılı yazımın ledger kaydıdır (F7): current
    // gerçekten ilerlemeden allow-outcome var olamaz. Outcome append'i CAS SONRASI
    // patlarsa commit ZATEN kalıcı → pending-outcome marker + alarm retry (case c).
    const outcomeRow: AuditRow = {
      principal: principalId,
      principal_type: meta.principalType,
      project,
      key: changedKeys.length === 1 ? changedKeys[0] : null,
      verb: "commit",
      decision: "allow",
      intent: meta.intent,
      ip: meta.ip,
      cf_ray: meta.cfRay,
      token_jti: meta.tokenJti,
    };
    const idemKey = `${project}:${m.epoch}`;
    try {
      await auditAppendSync(this.auditLog, outcomeRow, idemKey);
    } catch (err) {
      console.error(`writer-do: audit outcome append failed post-CAS, queued for retry (${idemKey})`, err);
      await this.enqueuePendingOutcome(project, m.epoch, outcomeRow, idemKey);
    }

    // 17. Escrow write-through: B2 push ERTELENDİ (G10), ama append-only pointer
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

    // 17b. Escrow write-through (§6.8 / §9.2): yeni manifest + yeni referanslanan
    // blob'lar + immutable pointer event B2'ye PUSH edilir. FAIL-SOFT: yalnızca DO
    // storage'a kuyruklanır (yerel, write path'te DEĞİL) + alarm — gerçek B2 push
    // alarm()'da olur, hatası commit'i ASLA düşürmez. MUTABLE `current` ASLA
    // push edilmez (F2 — yalnızca pointer EVENT). B2 yapılandırılmamışsa no-op.
    const escrowPushCfg = await this.effectiveEscrow();
    if (escrowPushCfg) {
      const items: EscrowPushItem[] = [
        { b2Key: manifestKey, r2Key: manifestKey, contentType: "application/json" },
        { b2Key: eventR2Key, r2Key: eventR2Key, contentType: "application/json" },
      ];
      const seenBlobs = new Set<string>();
      for (const e of m.entries) {
        if (seenBlobs.has(e.blobHash)) continue;
        seenBlobs.add(e.blobHash);
        const bk = keyBlob(project, e.blobHash);
        items.push({ b2Key: bk, r2Key: bk, contentType: "application/octet-stream" });
      }
      await enqueueEscrowPushes(this.ctx.storage, items).catch((err) => {
        // Kuyruğa alma bile başarısız olsa kalıcı commit'i düşürme (yalnızca RPO gecikir).
        console.error(`writer-do: escrow enqueue failed (project=${project} epoch=${m.epoch})`, err);
      });
    }

    // 18. Yanıt (freshness receipt G7'ye ertelendi).
    return jsonOK({ epoch: m.epoch, manifestSha256: newManifestSha });
  }

  /**
   * appendDeny, reddedilen bir commit için `commit` deny satırı ekler (§6.5 —
   * denials her zaman kaydedilir). Best-effort: audit DO down ise çağıran yutar
   * (birincil red — GRANT_DENIED vb. — yine döner; deny logging kritik yol değil).
   */
  private async appendDeny(project: string, meta: ReqMeta, e: CommitError): Promise<void> {
    const key = e.detail && typeof e.detail.key === "string" ? e.detail.key : null;
    await auditAppendSync(this.auditLog, {
      principal: meta.principalId,
      principal_type: meta.principalType,
      project,
      key,
      verb: "commit",
      decision: "deny",
      intent: e.code, // başarısız check'in adı (§6.2)
      ip: meta.ip,
      cf_ray: meta.cfRay,
      token_jti: meta.tokenJti,
    });
  }

  /**
   * enqueuePendingOutcome, CAS sonrası yazılamayan audit outcome satırını DO storage'a
   * kaydeder + alarm zamanlar (§6.2 case c recovery). Retry idempotency-key ile
   * append eder → audit DO zaten yazılmışsa dedup eder (çift outcome yok).
   */
  private async enqueuePendingOutcome(project: string, epoch: number, row: AuditRow, idempotencyKey: string): Promise<void> {
    const rec: PendingOutcome = { row, idempotencyKey };
    await this.ctx.storage.put(`${PENDING_OUTCOME_PREFIX}${project}:${epoch}`, rec);
    await this.ctx.storage.setAlarm(Date.now() + POINTER_EVENT_RETRY_MS);
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
    let remaining = 0;
    // (1) Bekleyen pointer-event'ler (§6.2 step-17 fail-soft).
    const pendingEvents = await this.ctx.storage.list<PendingPointerEvent>({ prefix: PENDING_POINTER_EVENT_PREFIX });
    for (const [storageKey, rec] of pendingEvents) {
      try {
        // onlyIf-absent: zaten yazılmışsa null döner (idempotent) → yine temizle.
        await this.bucket.put(rec.r2Key, utf8(rec.body), { onlyIf: { etagDoesNotMatch: "*" } });
        await this.ctx.storage.delete(storageKey);
      } catch (err) {
        remaining++; // hâlâ transient → bırak, bir sonraki alarm tekrar dener.
        console.error(`writer-do: pointer-event retry still failing (${storageKey})`, err);
      }
    }
    // (2) Bekleyen audit outcome'ları (§6.2 case c). Idempotency-key ile retry →
    // audit DO zaten yazdıysa dedup, çift outcome yok.
    const pendingOutcomes = await this.ctx.storage.list<PendingOutcome>({ prefix: PENDING_OUTCOME_PREFIX });
    for (const [storageKey, rec] of pendingOutcomes) {
      try {
        await auditAppendSync(this.auditLog, rec.row, rec.idempotencyKey);
        await this.ctx.storage.delete(storageKey);
      } catch (err) {
        remaining++;
        console.error(`writer-do: audit outcome retry still failing (${storageKey})`, err);
      }
    }
    // (3) Bekleyen escrow B2 push'ları (§6.8). Pointer-event'ler ÖNCE drene edildi
    // (yukarıda) → escrow drenajı onları R2'den okuyabilir. 3 denemeden sonra A4.
    const escrowCfg = await this.effectiveEscrow();
    const escrowRemaining = await drainEscrowPushes(this.ctx.storage, escrowCfg, this.bucket, this.escrowAlert);
    remaining += escrowRemaining;
    if (remaining > 0) await this.ctx.storage.setAlarm(Date.now() + Math.min(POINTER_EVENT_RETRY_MS, escrowRetryMs));
  }
}

/** emptyToNull, boş/absent header string'ini null'a çevirir (audit alanları). */
function emptyToNull(v: string | null): string | null {
  return v && v.trim() !== "" ? v : null;
}

/**
 * parseTokenScope, Worker'ın forward ettiği x-token-scope header'ını (JSON) çözer.
 * Boş/parse-edilemez/şekilsiz → null (makine yolunda fail-closed: scope yoksa commit reddedilir).
 */
function parseTokenScope(raw: string | null): TokenScope | null {
  if (!raw || raw.trim() === "") return null;
  try {
    const p = JSON.parse(raw) as { verbs?: unknown; keys?: unknown };
    if (!Array.isArray(p.verbs) || !Array.isArray(p.keys)) return null;
    return {
      verbs: p.verbs.filter((v): v is string => typeof v === "string"),
      keys: p.keys.filter((k): k is string => typeof k === "string"),
    };
  } catch {
    return null;
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
