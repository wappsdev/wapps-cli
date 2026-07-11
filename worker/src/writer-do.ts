// Per-project Durable Object write serializer (SPEC §0.1 KEPT / §7.6 write path).
// idFromName=project → proje başına TEK linearize edilebilir yazar; tüm mutasyon
// blockConcurrencyWhile içinde çalışır: aynı projeye iki eşzamanlı yazımdan TAM
// olarak biri commit olur (epoch+1 + prevManifestSha256 zinciri + R2 onlyIf-absent
// manifest PUT + pointer If-Match CAS).
//
// v2 PIVOT DELTASI: trust-manifest / imza / wrap-set-eşitliği kontrolleri SİLİNDİ
// (§0.2). İstemci artık imzalı manifest DEĞİL, tipli bir MUTASYON gönderir
// (set/import/delete/rewrap); zarf kriptosu (DEK üret + WSB1 seal + WKW1 KEK-wrap)
// BURADA, serializer içinde çalışır — keyVersion ataması yarışsızdır (§2.7).
// Policy authz Worker'da (index.ts) yapılır ve internal header'larla taşınır;
// audit attempt→outcome sıralaması + crash-recovery durumları (a)–(d) KORUNDU.

import { HTTP, jsonError, jsonOK } from "./errors.js";
import { utf8 } from "./crypto/encoding.js";
import { MasterKey, loadMasterKeys, wrapDEK, unwrapDEK, WrapError } from "./crypto/kek.js";
import { sealValue, BlobError } from "./crypto/blob.js";
import {
  DataManifest,
  ManifestEntry,
  ManifestVerifyError,
  manifestObjectHash,
  parseCurrentPointer,
  parseManifest,
  serializeManifest,
  SCHEMA_CURRENT_POINTER,
  SCHEMA_DATA_MANIFEST,
} from "./manifest.js";
import { keyCurrent, keyManifest, keyBlob, keyPointerEvent, validKeyName, getObject, headEtag } from "./storage.js";
import { auditAppendSync, auditAppendBatch, AuditRow, PrincipalType } from "./audit.js";
import { sha256Hex } from "./crypto/encoding.js";
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
  AUDIT_LOG: DurableObjectNamespace;
  AUDIT_DB: D1Database;
  MASTER_KEK?: string;
  MASTER_KEK_PREV?: string;
  DISCORD_WEBHOOK_URL?: string;
}

/** WriteOp, Worker'dan DO'ya taşınan tipli mutasyon (§7.4 write API'lerinin iç şekli). */
export interface WriteOp {
  op: "set" | "import" | "delete" | "rewrap";
  // set/import: plaintext değerler (TLS + internal DO fetch; C2 gereği ASLA loglanmaz).
  values?: Record<string, string>;
  // delete: silinecek anahtar.
  key?: string;
  // Opsiyonel optimistic-concurrency: mevcut epoch bununla uyuşmazsa 412 (§7.4).
  ifEpoch?: number;
}

/** ReqMeta, bir mutasyonun principal/audit metadatası (Worker internal header'ları). */
interface ReqMeta {
  principalId: string;
  principalType: PrincipalType;
  tokenJti: string | null;
  intent: string | null;
  // auditVerb: outcome satırlarının verb'ü (key.set | key.import | key.sync |
  // key.delete | rotate.step | admin.rewrap_kek) — Worker türetir (§6.4).
  auditVerb: string;
  policyVersion: number;
  ip: string | null;
  cfRay: string | null;
}

/** CommitError, transaction içi tipli abort (ilk hata iptal eder). */
class CommitError extends Error {
  constructor(public status: number, public code: string, public detail?: Record<string, unknown>) {
    super(code);
  }
  toResponse(): Response {
    return jsonError(this.status, this.code, this.code, this.detail);
  }
}

// Crash-recovery marker'ları (KORUNAN desen): pointer-event + audit outcome,
// commit kalıcılaştıktan SONRA patlarsa DO storage'a pending yazılır + alarm drene eder.
const PENDING_POINTER_EVENT_PREFIX = "pending-pointer-event:";
const PENDING_OUTCOME_PREFIX = "pending-audit-outcome:";
const POINTER_EVENT_RETRY_MS = 30_000;
const ESCROW_CONFIG_KEY = "escrow-config"; // test seam (dormant fallback)

interface PendingPointerEvent {
  r2Key: string;
  body: string;
}

/** PendingOutcome, CAS sonrası yazılamayan per-key outcome batch'i (case c recovery). */
interface PendingOutcome {
  rows: AuditRow[];
  idempotencyKey: string; // `${project}:${epoch}` — batch dedup marker
}

export class ProjectWriterDO {
  private bucket: R2Bucket;
  private auditLog: DurableObjectNamespace;
  private masters: MasterKey[] | null;
  private escrow: EscrowConfig | null;
  private discordUrl: string;

  constructor(private ctx: DurableObjectState, env: DOEnv) {
    this.bucket = env.SECRETS_BUCKET;
    this.auditLog = env.AUDIT_LOG;
    this.masters = loadMasterKeys(env);
    this.escrow = escrowConfig(env);
    this.discordUrl = (env.DISCORD_WEBHOOK_URL ?? "").trim();
  }

  /** escrowAlert, drenaj sırasında A4 tetikler (best-effort, throw etmez). */
  private escrowAlert = async (rule: string, summary: string, detail?: Record<string, unknown>): Promise<void> => {
    await deliverAlert({ DISCORD_WEBHOOK_URL: this.discordUrl, AUDIT_LOG: this.auditLog }, rule as typeof ALERT.A4, summary, detail);
  };

  /** effectiveEscrow, etkin escrow config'i çözer (env → yoksa DO-storage fallback, test seam). */
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
      intent: emptyToNull(request.headers.get("x-intent")),
      auditVerb: request.headers.get("x-audit-verb") ?? "key.set",
      policyVersion: Number(request.headers.get("x-policy-version") ?? "0") || 0,
      ip: emptyToNull(request.headers.get("x-cf-ip")),
      cfRay: emptyToNull(request.headers.get("x-cf-ray")),
    };
    let op: WriteOp;
    try {
      op = (await request.json()) as WriteOp;
    } catch {
      return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "body not JSON");
    }

    // Tüm mutasyon tek gate içinde → proje başına linearize.
    return this.ctx.blockConcurrencyWhile(async () => {
      try {
        return await this.commit(project, meta, op);
      } catch (e) {
        if (e instanceof CommitError) {
          // Red → deny satırı (denials her zaman kaydedilir). İSTİSNA:
          // AUDIT_UNAVAILABLE'ın kendisi (audit down → deny de yazılamaz).
          if (e.code !== "AUDIT_UNAVAILABLE") {
            await this.appendDeny(project, meta, e).catch(() => {});
          }
          return e.toResponse();
        }
        throw e;
      }
    });
  }

  private async commit(project: string, meta: ReqMeta, op: WriteOp): Promise<Response> {
    if (!this.masters) throw new CommitError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: "MASTER_KEK missing" });

    // 1. Mevcut durum: current pointer + manifest (zincir bütünlüğü fail-closed).
    const curObj = await getObject(this.bucket, keyCurrent(project));
    let prevEntries: ManifestEntry[] = [];
    let prevEpoch = 0;
    let prevSha = "";
    let prevCurrentEtag: string | null = null;
    if (curObj) {
      prevCurrentEtag = curObj.etag;
      let ptr;
      try {
        ptr = parseCurrentPointer(curObj.bytes);
      } catch {
        throw new CommitError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: "current pointer malformed" });
      }
      const curManifest = await getObject(this.bucket, keyManifest(project, ptr.epoch));
      if (!curManifest) throw new CommitError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: "current manifest missing" });
      if (manifestObjectHash(curManifest.bytes) !== ptr.manifestSha256) {
        throw new CommitError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: "pointer/manifest hash mismatch" });
      }
      let m: DataManifest;
      try {
        m = parseManifest(curManifest.bytes);
      } catch (e) {
        if (e instanceof ManifestVerifyError) throw new CommitError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: e.message });
        throw e;
      }
      if (m.project !== project) throw new CommitError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: "manifest project mismatch" });
      prevEntries = m.entries;
      prevEpoch = ptr.epoch;
      prevSha = ptr.manifestSha256;
    }

    // 2. Optimistic-concurrency (§7.4 ifEpoch): istemci beklediği epoch'u pinlediyse.
    if (op.ifEpoch !== undefined && op.ifEpoch !== prevEpoch) {
      throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: prevEpoch, expected: op.ifEpoch });
    }

    // 3. Mutasyonu uygula → yeni entry kümesi + yazılacak blob'lar.
    const byName = new Map(prevEntries.map((e) => [e.keyName, e]));
    const newBlobs: { hash: string; bytes: Uint8Array }[] = [];
    const touched: string[] = [];
    let rewrapped = 0;

    const putValue = (keyName: string, value: string): void => {
      if (!validKeyName(keyName)) throw new CommitError(HTTP.UNPROCESSABLE, "MANIFEST_MALFORMED", { reason: "invalid keyName", key: keyName });
      const prev = byName.get(keyName);
      // keyVersion HER değer değişiminde artar (AAD benzersizliği, §2.1).
      const keyVersion = (prev?.keyVersion ?? 0) + 1;
      const dek = crypto.getRandomValues(new Uint8Array(32)); // taze DEK, asla yeniden kullanılmaz (§2.1)
      let blobBytes: Uint8Array;
      try {
        blobBytes = sealValue(dek, project, keyName, keyVersion, utf8(value));
      } catch (e) {
        if (e instanceof BlobError && e.code === "VALUE_TOO_LARGE") throw new CommitError(HTTP.PAYLOAD_TOO_LARGE, "VALUE_TOO_LARGE", { key: keyName });
        throw e;
      }
      const hash = sha256Hex(blobBytes);
      const wrap = wrapDEK(this.masters![0], project, keyName, keyVersion, dek);
      dek.fill(0); // best-effort bellek temizliği
      newBlobs.push({ hash, bytes: blobBytes });
      byName.set(keyName, { keyName, keyVersion, blobHash: hash, wrap, rotation: prev?.rotation });
      touched.push(keyName);
    };

    switch (op.op) {
      case "set": {
        const entries = Object.entries(op.values ?? {});
        if (entries.length !== 1) throw new CommitError(HTTP.BAD_REQUEST, "BAD_REQUEST", { reason: "set requires exactly one value" });
        putValue(entries[0][0], entries[0][1]);
        break;
      }
      case "import": {
        const entries = Object.entries(op.values ?? {});
        if (entries.length === 0) throw new CommitError(HTTP.BAD_REQUEST, "BAD_REQUEST", { reason: "import requires values" });
        for (const [k, v] of entries.sort(([a], [b]) => (a < b ? -1 : 1))) putValue(k, v);
        break;
      }
      case "delete": {
        const key = op.key ?? "";
        if (!byName.has(key)) throw new CommitError(HTTP.NOT_FOUND, "NOT_FOUND", { key });
        byName.delete(key); // silme = yokluk (§2.6)
        touched.push(key);
        break;
      }
      case "rewrap": {
        // §2.5: her DEK'i kid'e uyan anahtarla aç, YENİ (current) KEK altında yeniden sar.
        // Blob'lara dokunulmaz (aynı DEK, aynı baytlar, keyVersion değişmez — wrap
        // metadatası AAD slot'unun parçası değildir).
        const currentKid = this.masters[0].kid;
        for (const e of byName.values()) {
          if (e.wrap.kid === currentKid) continue;
          let dek: Uint8Array;
          try {
            dek = unwrapDEK(this.masters, project, e.keyName, e.keyVersion, e.wrap);
          } catch (err) {
            if (err instanceof WrapError) throw new CommitError(HTTP.MISCONFIGURED, "WRAP_INVALID", { key: e.keyName });
            throw err;
          }
          const wrap = wrapDEK(this.masters[0], project, e.keyName, e.keyVersion, dek);
          dek.fill(0);
          byName.set(e.keyName, { ...e, wrap });
          rewrapped++;
        }
        if (rewrapped === 0) {
          // Hiçbir wrap eski kid'de değil → yeni epoch üretme (idempotent no-op).
          return jsonOK({ project, epoch: prevEpoch, rewrapped: 0, noop: true });
        }
        break;
      }
      default:
        throw new CommitError(HTTP.BAD_REQUEST, "BAD_REQUEST", { reason: "unknown op" });
    }

    // 4. Yeni manifest'i kur (epoch+1, zincir, §2.6).
    const epoch = prevEpoch + 1;
    const manifest: DataManifest = {
      schema: SCHEMA_DATA_MANIFEST,
      project,
      epoch,
      prevManifestSha256: prevSha,
      policyVersion: meta.policyVersion,
      writer: meta.principalId, // bilgilendirici; authz girdisi DEĞİL (§2.6)
      createdAt: new Date().toISOString(),
      entries: [...byName.values()],
    };
    const manifestBytes = serializeManifest(manifest); // MANIFEST_TOO_LARGE burada fırlar
    const newManifestSha = manifestObjectHash(manifestBytes);

    // 5. Audit ATTEMPT (SENKRON, manifest yazımından ÖNCE): audit DO erişilemezse
    // fail-closed 503 AUDIT_UNAVAILABLE — henüz HİÇBİR store durumu değişmedi.
    // Bulk'ta attempt AGGREGATE kalabilir (keys:N intent, §6.4).
    try {
      await auditAppendSync(this.auditLog, {
        principal: meta.principalId,
        principal_type: meta.principalType,
        project,
        key: touched.length === 1 ? touched[0] : null,
        verb: "commit.attempt",
        decision: "allow",
        intent: meta.intent ?? (touched.length > 1 ? `keys:${touched.length}` : op.op === "rewrap" ? `rewrap:${rewrapped}` : null),
        ip: meta.ip,
        cf_ray: meta.cfRay,
        token_jti: meta.tokenJti,
      });
    } catch {
      throw new CommitError(HTTP.MISCONFIGURED, "AUDIT_UNAVAILABLE", { reason: "audit DO unavailable at attempt" });
    }

    // 6. Yeni blob'ları yaz (içerik-adresli, immutable). PARALEL + HEAD'siz: bulk
    //    import'ta (ör. migration 156 key) sıralı HEAD+PUT wall-time'ı aşıyordu
    //    (exceededWallTime, error 1101). `onlyIf: etagDoesNotMatch "*"` = yalnızca
    //    yokken yaz → ayrı bir HEAD gereksiz (varsa put no-op/null döner), böylece R2
    //    op'ları yarıya iner. Her blob bağımsız+idempotent → Promise.all güvenli;
    //    atomiklik korunur (tümü manifest/pointer'dan ÖNCE; başarısızlıkta manifest
    //    yazılmaz → yazılmış blob'lar referanssız = GC-safe).
    await Promise.all(
      newBlobs.map((b) => this.bucket.put(keyBlob(project, b.hash), b.bytes, { onlyIf: { etagDoesNotMatch: "*" } })),
    );

    // 7. Manifest yaz: onlyIf-absent (epoch slot'unu ilk yazan kazanır).
    const manifestKey = keyManifest(project, epoch);
    if (await headEtag(this.bucket, manifestKey)) {
      throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: prevEpoch, reason: "manifest already exists" });
    }
    const wrote = await this.bucket.put(manifestKey, manifestBytes, { onlyIf: { etagDoesNotMatch: "*" } });
    if (wrote === null) throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: prevEpoch, reason: "manifest already exists" });

    // 8. Pointer CAS: If-Match prev etag (genesis'te onlyIf-absent).
    const pointerBody = utf8(JSON.stringify({ schema: SCHEMA_CURRENT_POINTER, project, epoch, manifestSha256: newManifestSha }));
    if (prevCurrentEtag === null) {
      const created = await this.bucket.put(keyCurrent(project), pointerBody, { onlyIf: { etagDoesNotMatch: "*" } });
      if (created === null) throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: 0, reason: "current already created" });
    } else {
      const updated = await this.bucket.put(keyCurrent(project), pointerBody, { onlyIf: { etagMatches: prevCurrentEtag } });
      if (updated === null) throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { reason: "pointer CAS lost (out-of-band mutation)" });
    }

    // 9. Audit OUTCOME (SENKRON, YALNIZCA pointer CAS başarısından SONRA): bulk
    // op'lar için BİR SATIR / ANAHTAR, tek /append-batch ack'i (§6.4 — aggregate
    // keys:N outcome YASAK; ledger offboard rotate oracle'ıdır). Idempotency-key
    // `${project}:${epoch}` → post-CAS crash retry'ı çift satır üretmez (case c).
    const outcomeRows: AuditRow[] = touched.map((k) => ({
      principal: meta.principalId,
      principal_type: meta.principalType,
      project,
      key: k,
      verb: op.op === "rewrap" ? "admin.rewrap_kek" : meta.auditVerb,
      decision: "allow",
      intent: meta.intent,
      ip: meta.ip,
      cf_ray: meta.cfRay,
      token_jti: meta.tokenJti,
    }));
    if (op.op === "rewrap") {
      // Rewrap anahtar-değerlerini DEĞİŞTİRMEZ (aynı DEK/blob) → tek proje satırı yeter.
      outcomeRows.length = 0;
      outcomeRows.push({
        principal: meta.principalId,
        principal_type: meta.principalType,
        project,
        key: null,
        verb: "admin.rewrap_kek",
        decision: "allow",
        intent: `rewrapped:${rewrapped}`,
        ip: meta.ip,
        cf_ray: meta.cfRay,
        token_jti: meta.tokenJti,
      });
    }
    const idemKey = `${project}:${epoch}`;
    try {
      await auditAppendBatch(this.auditLog, outcomeRows, { idempotencyKey: idemKey });
    } catch (err) {
      console.error(`writer-do: audit outcome append failed post-CAS, queued for retry (${idemKey})`, err);
      await this.enqueuePendingOutcome(project, epoch, outcomeRows, idemKey);
    }

    // 10. Append-only pointer event (fail-soft; commit ZATEN kalıcı — retry marker).
    const eventR2Key = keyPointerEvent(project, epoch);
    const eventBody = JSON.stringify({
      schema: "wapps.pointer-event.v1",
      project,
      epoch,
      manifestSha256: newManifestSha,
      committed_at: new Date().toISOString(),
    });
    try {
      await this.bucket.put(eventR2Key, utf8(eventBody), { onlyIf: { etagDoesNotMatch: "*" } });
    } catch (err) {
      console.error(`writer-do: pointer-event write failed, queued for retry (project=${project} epoch=${epoch})`, err);
      await this.enqueuePendingPointerEvent(project, epoch, eventR2Key, eventBody);
    }

    // 11. Escrow write-through (§8.3): manifest + yeni blob'lar + pointer event
    // B2'ye kuyruklanır (FAIL-SOFT — gerçek push alarm()'da, write path DIŞINDA).
    const escrowPushCfg = await this.effectiveEscrow();
    if (escrowPushCfg) {
      const items: EscrowPushItem[] = [
        { b2Key: manifestKey, r2Key: manifestKey, contentType: "application/json" },
        { b2Key: eventR2Key, r2Key: eventR2Key, contentType: "application/json" },
      ];
      for (const b of newBlobs) {
        const bk = keyBlob(project, b.hash);
        items.push({ b2Key: bk, r2Key: bk, contentType: "application/octet-stream" });
      }
      await enqueueEscrowPushes(this.ctx.storage, items).catch((err) => {
        console.error(`writer-do: escrow enqueue failed (project=${project} epoch=${epoch})`, err);
      });
    }

    // 12. Yanıt: yeni epoch + manifest hash (+ set/import için yeni keyVersion'lar).
    const keyVersions: Record<string, number> = {};
    for (const k of touched) {
      const e = byName.get(k);
      if (e) keyVersions[k] = e.keyVersion;
    }
    return jsonOK({ project, epoch, manifestSha256: newManifestSha, keyVersions, ...(op.op === "rewrap" ? { rewrapped } : {}) });
  }

  /** appendDeny, reddedilen bir mutasyon için deny satırı ekler (best-effort). */
  private async appendDeny(project: string, meta: ReqMeta, e: CommitError): Promise<void> {
    const key = e.detail && typeof e.detail.key === "string" ? e.detail.key : null;
    await auditAppendSync(this.auditLog, {
      principal: meta.principalId,
      principal_type: meta.principalType,
      project,
      key,
      verb: meta.auditVerb,
      decision: "deny",
      intent: e.code, // başarısız check'in adı
      ip: meta.ip,
      cf_ray: meta.cfRay,
      token_jti: meta.tokenJti,
    });
  }

  /** enqueuePendingOutcome, CAS sonrası yazılamayan outcome batch'ini kalıcılaştırır (case c). */
  private async enqueuePendingOutcome(project: string, epoch: number, rows: AuditRow[], idempotencyKey: string): Promise<void> {
    const rec: PendingOutcome = { rows, idempotencyKey };
    await this.ctx.storage.put(`${PENDING_OUTCOME_PREFIX}${project}:${epoch}`, rec);
    await this.ctx.storage.setAlarm(Date.now() + POINTER_EVENT_RETRY_MS);
  }

  /** enqueuePendingPointerEvent, yazılamayan pointer-event'i pending işaretler + alarm kurar. */
  private async enqueuePendingPointerEvent(project: string, epoch: number, r2Key: string, body: string): Promise<void> {
    const rec: PendingPointerEvent = { r2Key, body };
    await this.ctx.storage.put(`${PENDING_POINTER_EVENT_PREFIX}${project}:${epoch}`, rec);
    await this.ctx.storage.setAlarm(Date.now() + POINTER_EVENT_RETRY_MS);
  }

  /**
   * alarm, bekleyen pointer-event / audit-outcome / escrow-push kayıtlarını drene
   * eder (crash-recovery). Her yazım idempotenttir (onlyIf-absent / idempotencyKey).
   */
  async alarm(): Promise<void> {
    let remaining = 0;
    // (1) Bekleyen pointer-event'ler.
    const pendingEvents = await this.ctx.storage.list<PendingPointerEvent>({ prefix: PENDING_POINTER_EVENT_PREFIX });
    for (const [storageKey, rec] of pendingEvents) {
      try {
        await this.bucket.put(rec.r2Key, utf8(rec.body), { onlyIf: { etagDoesNotMatch: "*" } });
        await this.ctx.storage.delete(storageKey);
      } catch (err) {
        remaining++;
        console.error(`writer-do: pointer-event retry still failing (${storageKey})`, err);
      }
    }
    // (2) Bekleyen outcome batch'leri (idempotency-key dedup — çift satır yok).
    const pendingOutcomes = await this.ctx.storage.list<PendingOutcome>({ prefix: PENDING_OUTCOME_PREFIX });
    for (const [storageKey, rec] of pendingOutcomes) {
      try {
        await auditAppendBatch(this.auditLog, rec.rows, { idempotencyKey: rec.idempotencyKey });
        await this.ctx.storage.delete(storageKey);
      } catch (err) {
        remaining++;
        console.error(`writer-do: audit outcome retry still failing (${storageKey})`, err);
      }
    }
    // (3) Bekleyen escrow B2 push'ları (pointer-event'ler ÖNCE drene edildi).
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
