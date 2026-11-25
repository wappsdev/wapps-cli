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
import { keyCurrent, keyManifest, keyBlob, keyPointerEvent, validKeyName, getObject, headEtag, mapPool, BLOB_POOL, deleteProjectObjects } from "./storage.js";
import { auditAppendSync, auditAppendBatch, AuditAppendError, AuditRow, AUDIT_FIELD_MAX, PrincipalType, denyIntent } from "./audit.js";
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
import { deliverAlert, ALERT, type BrokerAlertEnv, type BrokerAlertLink } from "./alerts.js";
import { CardPatch, applyCard } from "./card.js";
import { reserveCode, reserveCodes, validCode } from "./keycode.js";

interface DOEnv extends EscrowEnv, BrokerAlertEnv {
  SECRETS_BUCKET: R2Bucket;
  AUDIT_LOG: DurableObjectNamespace;
  AUDIT_DB: D1Database;
  MASTER_KEK?: string;
  MASTER_KEK_PREV?: string;
  DISCORD_WEBHOOK_URL?: string;
}

/** WriteOp, Worker'dan DO'ya taşınan tipli mutasyon (§7.4 write API'lerinin iç şekli). */
export interface WriteOp {
  // codes: the admin backfill; gives a key code to every key without one.
  // reserve: answers a key's code before the key exists (no commit; see reserve()).
  op: "set" | "import" | "delete" | "rewrap" | "meta" | "codes" | "reserve";
  // set/import: plaintext değerler (TLS + internal DO fetch; C2 gereği ASLA loglanmaz).
  values?: Record<string, string>;
  // delete / meta / reserve: the key.
  key?: string;
  // meta: the card change; set/import: an optional card change for every written
  // key (absent = each key keeps its card). Checked at the edge (card.ts).
  card?: CardPatch;
  // Opsiyonel optimistic-concurrency: mevcut epoch bununla uyuşmazsa 412 (§7.4).
  ifEpoch?: number;
  // set only (E-M3): write the key only if it does not exist; else 409 KEY_EXISTS.
  // Checked here, inside the serialized commit, so two racing creates cannot both land.
  createOnly?: boolean;
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
// Key code reservations (reserve()): `key-reservation:<KEY>` → the code. They live
// in this DO's storage because this DO is the store's one serialized writer: a
// reservation and the commit that consumes it never interleave.
const RESERVATION_PREFIX = "key-reservation:";
// E-M2: the commit intent. Written before the manifest PUT, deleted once the commit
// is finished (or found never to have landed). One at a time: commits are serialized.
const COMMIT_INTENT_KEY = "commit-intent";

/**
 * CommitIntent is everything needed to finish a commit whose manifest may be
 * written but whose pointer CAS may not have run: the CAS inputs, and the post-CAS
 * work (reservation clears, outcome rows, pointer event, escrow items).
 */
interface CommitIntent {
  project: string;
  epoch: number;
  manifestSha256: string;
  prevCurrentEtag: string | null; // null = genesis (no pointer yet)
  outcomeRows: AuditRow[];
  spentReservations: string[];
  blobHashes: string[];
}

interface PendingPointerEvent {
  r2Key: string;
  body: string;
}

/** PendingOutcome is a per-key outcome batch that could not be written after the CAS (case c recovery). */
interface PendingOutcome {
  rows: AuditRow[];
  idempotencyKey: string; // `${project}:${epoch}:${manifestSha}`, the batch dedup marker
}

export class ProjectWriterDO {
  private bucket: R2Bucket;
  private auditLog: DurableObjectNamespace;
  private masters: MasterKey[] | null;
  private escrow: EscrowConfig | null;
  private discordUrl: string;
  private brokerAlert: BrokerAlertLink | undefined;

  constructor(private ctx: DurableObjectState, env: DOEnv) {
    this.bucket = env.SECRETS_BUCKET;
    this.auditLog = env.AUDIT_LOG;
    this.masters = loadMasterKeys(env);
    this.escrow = escrowConfig(env);
    this.discordUrl = (env.DISCORD_WEBHOOK_URL ?? "").trim();
    this.brokerAlert = env.BROKER_ALERT;
  }

  /** escrowAlert, drenaj sırasında A4 tetikler (best-effort, throw etmez). */
  private escrowAlert = async (rule: string, summary: string, detail?: Record<string, unknown>): Promise<void> => {
    await deliverAlert({ DISCORD_WEBHOOK_URL: this.discordUrl, AUDIT_LOG: this.auditLog, BROKER_ALERT: this.brokerAlert }, rule as typeof ALERT.A4, summary, detail);
  };

  /** effectiveEscrow, etkin escrow config'i çözer (env → yoksa DO-storage fallback, test seam). */
  private async effectiveEscrow(): Promise<EscrowConfig | null> {
    if (this.escrow) return this.escrow;
    return (await this.ctx.storage.get<EscrowConfig>(ESCROW_CONFIG_KEY)) ?? null;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const project = url.searchParams.get("project") ?? "";
    if (url.pathname === "/purge" && request.method === "POST") {
      return this.ctx.blockConcurrencyWhile(() => this.purge(project));
    }
    if (url.pathname !== "/commit" || request.method !== "POST") {
      return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "unknown DO route");
    }
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

    // 0. A commit left half-done by a fault (E-M2) is finished or discarded first;
    // until it is, the store's next epoch slot may be taken and this commit would lose.
    try {
      await this.recoverIntent();
    } catch (e) {
      console.error(`writer-do: commit intent recovery failed (project=${project})`, e);
      throw new CommitError(HTTP.MISCONFIGURED, "COMMIT_RECOVERY_PENDING", { reason: "an earlier commit could not be finished yet; retry" });
    }

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

    if (op.op === "reserve") return await this.reserve(project, meta, op.key ?? "", prevEntries);

    // 2. Optimistic-concurrency (§7.4 ifEpoch): istemci beklediği epoch'u pinlediyse.
    if (op.ifEpoch !== undefined && op.ifEpoch !== prevEpoch) {
      throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: prevEpoch, expected: op.ifEpoch });
    }

    // 3. Mutasyonu uygula → yeni entry kümesi + yazılacak blob'lar.
    // One commit time: the manifest's createdAt and every touched entry's updatedAt.
    const now = new Date().toISOString();
    const byName = new Map(prevEntries.map((e) => [e.keyName, e]));
    const newBlobs: { hash: string; bytes: Uint8Array }[] = [];
    const touched: string[] = [];
    // Keys this commit creates: each gets a key code below.
    const created: string[] = [];
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
      // The card stays with the key unless the op carries a change for it; the
      // key code always stays (a new value is a rotation, not a new key).
      byName.set(keyName, { keyName, keyVersion, blobHash: hash, wrap, rotation: prev?.rotation, ...applyCard(prev, op.card), updatedAt: now, code: prev?.code });
      touched.push(keyName);
      if (!prev) created.push(keyName);
    };

    if (op.createOnly && op.op !== "set") throw new CommitError(HTTP.BAD_REQUEST, "BAD_REQUEST", { reason: "createOnly applies to set only" });
    switch (op.op) {
      case "set": {
        const entries = Object.entries(op.values ?? {});
        if (entries.length !== 1) throw new CommitError(HTTP.BAD_REQUEST, "BAD_REQUEST", { reason: "set requires exactly one value" });
        // Create-only (E-M3): decided against the state read above, inside the lock.
        if (op.createOnly && byName.has(entries[0][0])) throw new CommitError(HTTP.CONFLICT, "KEY_EXISTS", { key: entries[0][0] });
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
      case "meta": {
        // Card only: value, version, blob and wrap stay as they are.
        const key = op.key ?? "";
        const prev = byName.get(key);
        if (!prev) throw new CommitError(HTTP.NOT_FOUND, "NOT_FOUND", { key });
        byName.set(key, { ...prev, ...applyCard(prev, op.card), updatedAt: now });
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
      case "codes": {
        // The admin backfill: every key without a code, nothing else changes.
        for (const e of byName.values()) if (e.code === undefined) touched.push(e.keyName);
        if (touched.length === 0) return jsonOK({ project, epoch: prevEpoch, assigned: 0, noop: true });
        break;
      }
      default:
        throw new CommitError(HTTP.BAD_REQUEST, "BAD_REQUEST", { reason: "unknown op" });
    }

    // 3b. Key codes: a created key whose code was reserved (reserve()) takes that
    // code; every other created key, or each key the backfill names, takes a fresh
    // code from the gate-wide index (keycode.ts) before the manifest exists. The
    // draws run in parallel (one R2 round trip each).
    const reserved = created.length > 0 ? await this.reservations(created) : new Map<string, string>();
    for (const [k, code] of reserved) byName.set(k, { ...byName.get(k)!, code });
    const needCodes = (op.op === "codes" ? touched : created).filter((k) => !reserved.has(k));
    if (needCodes.length > 0) {
      let codes: Map<string, string>;
      try {
        codes = await reserveCodes(this.bucket, project, needCodes);
      } catch (e) {
        console.error(`writer-do: key code reservation failed (project=${project})`, e);
        throw new CommitError(HTTP.MISCONFIGURED, "KEY_CODE_UNAVAILABLE");
      }
      for (const [k, code] of codes) byName.set(k, { ...byName.get(k)!, code });
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
      createdAt: now,
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

    // 6. Yeni blob'ları yaz (içerik-adresli, immutable). SINIRLI-EŞZAMANLI + HEAD'siz:
    //    sıralı HEAD+PUT bulk import'ta wall-time'ı aşıyordu (exceededWallTime, error
    //    1101) ama sınırsız Promise.all da eşzamanlı-subrequest/bellek patlatır → mapPool
    //    (≤BLOB_POOL). `onlyIf: etagDoesNotMatch "*"` = yalnızca yokken yaz → ayrı HEAD
    //    gereksiz. Her blob bağımsız+idempotent; atomiklik korunur (tümü manifest'ten
    //    ÖNCE; başarısızlıkta manifest yazılmaz → yazılmış blob'lar referanssız = GC-safe).
    await mapPool(newBlobs, BLOB_POOL, (b) => this.bucket.put(keyBlob(project, b.hash), b.bytes, { onlyIf: { etagDoesNotMatch: "*" } }));

    // 7. Outcome rows, built before the CAS so the commit intent carries them: a
    // commit rolled forward after a fault still gets its rows. Bulk ops write ONE ROW
    // PER KEY (§6.4: an aggregate keys:N outcome is FORBIDDEN; the ledger is the
    // offboard rotate oracle).
    const outcomeRows: AuditRow[] = touched.map((k) => ({
      principal: meta.principalId,
      principal_type: meta.principalType,
      project,
      key: k,
      verb: op.op === "rewrap" ? "admin.rewrap_kek" : meta.auditVerb,
      decision: "allow",
      // A backfill row names the code it gave.
      intent: op.op === "codes" ? `code:${byName.get(k)?.code}` : meta.intent,
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

    // 8. Manifest slot: onlyIf-absent (epoch slot'unu ilk yazan kazanır).
    const manifestKey = keyManifest(project, epoch);
    if (await headEtag(this.bucket, manifestKey)) {
      throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: prevEpoch, reason: "manifest already exists" });
    }

    // 9. Commit intent (E-M2), durable BEFORE the manifest PUT. A fault between the
    // manifest PUT and the pointer CAS would otherwise leave epoch N+1 written with
    // the pointer at N, and every later commit would lose the slot forever. The next
    // commit and alarm() read the intent and finish or discard it (recoverIntent).
    // Spent reservations: a consumed one goes once the commit is durable, so a later
    // key of the same name never takes the old code again; a deleted key's goes too.
    const intent: CommitIntent = {
      project,
      epoch,
      manifestSha256: newManifestSha,
      prevCurrentEtag,
      outcomeRows,
      spentReservations: [...reserved.keys(), ...(op.op === "delete" ? touched : [])],
      blobHashes: newBlobs.map((b) => b.hash),
    };
    // The recovery alarm is armed BEFORE the intent exists, so no crash point leaves
    // an intent without a scheduled recovery (a crash before the intent put leaves
    // only an alarm, which finds no intent and does nothing). armAlarm never moves an
    // alarm that is already due sooner. The alarm stays set after the intent goes;
    // alarm() re-arms itself while an intent survives (recoverIntent failing).
    await this.armAlarm(Date.now() + POINTER_EVENT_RETRY_MS);
    await this.ctx.storage.put(COMMIT_INTENT_KEY, intent);

    // 10. Manifest PUT, then the pointer CAS (If-Match prev etag; genesis'te
    // onlyIf-absent). A typed refusal means this commit did not land: its intent
    // goes. Any other fault keeps the intent for the alarm armed above.
    try {
      const wrote = await this.bucket.put(manifestKey, manifestBytes, { onlyIf: { etagDoesNotMatch: "*" } });
      if (wrote === null) throw new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: prevEpoch, reason: "manifest already exists" });
      if (!(await this.casPointer(intent))) {
        throw prevCurrentEtag === null
          ? new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { current_epoch: 0, reason: "current already created" })
          : new CommitError(HTTP.PRECONDITION_FAILED, "EPOCH_CONFLICT", { reason: "pointer CAS lost (out-of-band mutation)" });
      }
    } catch (e) {
      if (e instanceof CommitError) await this.ctx.storage.delete(COMMIT_INTENT_KEY);
      throw e;
    }

    // 11. The commit is durable: reservations, audit outcome, pointer event and
    // escrow, then the intent goes (finishCommit). A fault in it keeps the intent,
    // and the alarm armed in step 9 re-runs it (every step is idempotent).
    await this.finishCommit(intent);

    // 12. Yanıt: yeni epoch + manifest hash (+ set/import için yeni keyVersion'lar).
    // keyCodes: the code of each touched key that has one; created (set/import):
    // the keys this commit created, so the CLI can print their issuer names.
    const keyVersions: Record<string, number> = {};
    const keyCodes: Record<string, string> = {};
    for (const k of touched) {
      const e = byName.get(k);
      if (e) keyVersions[k] = e.keyVersion;
      if (e?.code !== undefined) keyCodes[k] = e.code;
    }
    const res = jsonOK({
      project,
      epoch,
      manifestSha256: newManifestSha,
      keyVersions,
      keyCodes,
      ...(op.op === "set" || op.op === "import" ? { created } : {}),
      ...(op.op === "rewrap" ? { rewrapped } : {}),
    });
    // A create-only write answers 201 Created (If-None-Match: * semantics).
    return op.createOnly ? new Response(res.body, { status: HTTP.CREATED, headers: res.headers }) : res;
  }

  /**
   * reserve answers the code of `key` before its value exists (POST …/keys/<K>/code):
   * the existing key's own code; else the code already reserved for the key; else a
   * fresh code taken create-only in the gate-wide index (keycode.ts), kept as this
   * DO's reservation. It runs inside blockConcurrencyWhile like a commit, so two
   * concurrent reservations of one key answer one code, and the set that creates
   * the key takes it (step 3b). A reservation never frees its code. Every answer is
   * an allow row (intent `code:<C>`) written before the answer; a refusal is a
   * deny row (fetch's CommitError path).
   */
  private async reserve(project: string, meta: ReqMeta, key: string, entries: ManifestEntry[]): Promise<Response> {
    if (!validKeyName(key)) throw new CommitError(HTTP.BAD_REQUEST, "BAD_REQUEST", { reason: "invalid keyName", key });
    const existing = entries.find((e) => e.keyName === key);
    let code: string;
    if (existing) {
      if (existing.code === undefined) throw new CommitError(HTTP.CONFLICT, "KEY_CODE_MISSING", { key });
      code = existing.code;
    } else {
      const held = (await this.reservations([key])).get(key);
      if (held !== undefined) {
        code = held;
      } else {
        try {
          code = await reserveCode(this.bucket, project, key);
        } catch (e) {
          console.error(`writer-do: key code reservation failed (project=${project})`, e);
          throw new CommitError(HTTP.MISCONFIGURED, "KEY_CODE_UNAVAILABLE", { key });
        }
        await this.ctx.storage.put(RESERVATION_PREFIX + key, code);
      }
    }
    try {
      await auditAppendSync(this.auditLog, {
        principal: meta.principalId,
        principal_type: meta.principalType,
        project,
        key,
        verb: meta.auditVerb,
        decision: "allow",
        intent: `code:${code}`,
        ip: meta.ip,
        cf_ray: meta.cfRay,
        token_jti: meta.tokenJti,
      });
    } catch {
      throw new CommitError(HTTP.MISCONFIGURED, "AUDIT_UNAVAILABLE", { reason: "audit DO unavailable" });
    }
    return jsonOK({ store: project, keyName: key, code });
  }

  /** casPointer moves the store's pointer to the intent's manifest: If-Match the
   * pointer etag the commit read, or create-only at genesis. False = CAS lost. */
  private async casPointer(intent: CommitIntent): Promise<boolean> {
    const { project, epoch, manifestSha256 } = intent;
    const body = utf8(JSON.stringify({ schema: SCHEMA_CURRENT_POINTER, project, epoch, manifestSha256 }));
    const onlyIf: R2Conditional = intent.prevCurrentEtag === null ? { etagDoesNotMatch: "*" } : { etagMatches: intent.prevCurrentEtag };
    return (await this.bucket.put(keyCurrent(project), body, { onlyIf })) !== null;
  }

  /**
   * finishCommit does a durable commit's post-CAS work, then deletes its intent.
   * Each step is idempotent, so a recovery may run it again after a fault anywhere
   * in it: reservation deletes; the outcome batch under the idempotency key
   * `${project}:${epoch}:${manifestSha}` (a retry does not double the rows; the
   * manifest hash keeps a re-created project's epoch 1 from colliding with the old
   * one's); the onlyIf-absent pointer event (keyed by epoch and manifest hash); the escrow enqueue (keyed by B2 key).
   */
  private async finishCommit(intent: CommitIntent): Promise<void> {
    const { project, epoch, manifestSha256 } = intent;
    for (const k of intent.spentReservations) {
      await this.ctx.storage.delete(RESERVATION_PREFIX + k).catch((err) => {
        console.error(`writer-do: reservation clear failed (project=${project})`, err);
      });
    }

    // Audit OUTCOME (SYNC, ONLY after the pointer CAS succeeded), one /append-batch ack.
    const idemKey = `${project}:${epoch}:${manifestSha256}`;
    try {
      await auditAppendBatch(this.auditLog, intent.outcomeRows, { idempotencyKey: idemKey });
    } catch (err) {
      if (isTerminalRefusal(err)) {
        await this.outcomeRefused(idemKey, err);
      } else {
        console.error(`writer-do: audit outcome append failed post-CAS, queued for retry (${idemKey})`, err);
        await this.enqueuePendingOutcome(intent.outcomeRows, idemKey);
      }
    }

    // Append-only pointer event (fail-soft; commit ZATEN kalıcı — retry marker).
    const eventR2Key = keyPointerEvent(project, epoch, manifestSha256);
    const eventBody = JSON.stringify({
      schema: "wapps.pointer-event.v1",
      project,
      epoch,
      manifestSha256,
      committed_at: new Date().toISOString(),
    });
    try {
      await this.bucket.put(eventR2Key, utf8(eventBody), { onlyIf: { etagDoesNotMatch: "*" } });
    } catch (err) {
      console.error(`writer-do: pointer-event write failed, queued for retry (project=${project} epoch=${epoch})`, err);
      await this.enqueuePendingPointerEvent(eventR2Key, eventBody);
    }

    // Escrow write-through (§8.3): manifest + yeni blob'lar + pointer event B2'ye
    // kuyruklanır (FAIL-SOFT — gerçek push alarm()'da, write path DIŞINDA).
    const escrowPushCfg = await this.effectiveEscrow();
    if (escrowPushCfg) {
      const manifestKey = keyManifest(project, epoch);
      const items: EscrowPushItem[] = [
        { b2Key: manifestKey, r2Key: manifestKey, contentType: "application/json" },
        { b2Key: eventR2Key, r2Key: eventR2Key, contentType: "application/json" },
      ];
      for (const h of intent.blobHashes) {
        const bk = keyBlob(project, h);
        items.push({ b2Key: bk, r2Key: bk, contentType: "application/octet-stream" });
      }
      await enqueueEscrowPushes(this.ctx.storage, items).catch((err) => {
        console.error(`writer-do: escrow enqueue failed (project=${project} epoch=${epoch})`, err);
      });
    }

    await this.ctx.storage.delete(COMMIT_INTENT_KEY);
  }

  /**
   * recoverIntent finishes or discards a commit left by a fault (E-M2). Callers hold
   * the lock (blockConcurrencyWhile). The decision reads R2 only:
   *  - the pointer already names the intended manifest → the CAS landed; finish.
   *  - the pointer is still the one the commit read (same etag, or still absent at
   *    genesis) and the intended epoch's manifest hashes to the intended hash → the
   *    manifest PUT landed but the CAS did not; do the CAS, then finish.
   *  - otherwise the commit never landed (no manifest, a different one, or the
   *    pointer moved) → discard the intent. Nothing references its manifest.
   * It throws on an R2 or storage error and leaves the intent for the next try.
   */
  private async recoverIntent(): Promise<void> {
    const intent = await this.ctx.storage.get<CommitIntent>(COMMIT_INTENT_KEY);
    if (!intent) return;
    const { project, epoch, manifestSha256 } = intent;
    const cur = await getObject(this.bucket, keyCurrent(project));
    if (pointerNamesIntent(cur, intent)) {
      await this.finishCommit(intent);
      return;
    }
    const pointerUnchanged = cur === null ? intent.prevCurrentEtag === null : cur.etag === intent.prevCurrentEtag;
    if (pointerUnchanged) {
      const man = await getObject(this.bucket, keyManifest(project, epoch));
      if (man && manifestObjectHash(man.bytes) === manifestSha256 && (await this.casPointer(intent))) {
        console.error(`writer-do: rolled a faulted commit forward (project=${project} epoch=${epoch})`);
        await this.finishCommit(intent);
        return;
      }
    }
    console.error(`writer-do: discarded a commit intent that never landed (project=${project} epoch=${epoch})`);
    await this.ctx.storage.delete(COMMIT_INTENT_KEY);
  }

  /** armAlarm schedules the alarm at `at` unless an earlier one is already set. */
  private async armAlarm(at: number): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > at) await this.ctx.storage.setAlarm(at);
  }

  /**
   * purge deletes every data object of the store (L3, DELETE /v1/admin/projects/{p}
   * and /v1/admin/shared/{ns}/{name}). It runs under the same lock as a commit, so
   * no commit is between its manifest PUT and its CAS while the objects go. A
   * pending intent is settled first, before any object goes:
   *  - its CAS landed (the pointer names its manifest) → the write happened, so it
   *    is finished (finishCommit): its audit outcome and pointer event are history
   *    the purge must not erase. If that fails, nothing is deleted and the intent
   *    stays for the retry or the alarm.
   *  - otherwise → it is discarded, never rolled forward: the store is going.
   * So a purge that stops part-way never leaves an intent that a recovery would roll
   * forward onto a half-deleted store. The admin route has already written the
   * audit row. Pointer events and pending audit/escrow records stay (append-only
   * history, §8.3).
   */
  private async purge(project: string): Promise<Response> {
    try {
      const intent = await this.ctx.storage.get<CommitIntent>(COMMIT_INTENT_KEY);
      if (intent) {
        if (pointerNamesIntent(await getObject(this.bucket, keyCurrent(intent.project)), intent)) await this.finishCommit(intent);
        else await this.ctx.storage.delete(COMMIT_INTENT_KEY);
      }
      const deleted = await deleteProjectObjects(this.bucket, project);
      return jsonOK({ project, deleted_objects: deleted });
    } catch (e) {
      console.error(`writer-do: purge failed (project=${project})`, e);
      return jsonError(HTTP.MISCONFIGURED, "PURGE_INCOMPLETE", "store purge did not finish; retry");
    }
  }

  /** reservations answers key → reserved code for those of `keys` that hold a
   * reservation (a malformed stored code counts as none). */
  private async reservations(keys: string[]): Promise<Map<string, string>> {
    const wanted = new Set(keys);
    const all = await this.ctx.storage.list<string>({ prefix: RESERVATION_PREFIX });
    const out = new Map<string, string>();
    for (const [sk, code] of all) {
      const k = sk.slice(RESERVATION_PREFIX.length);
      if (wanted.has(k) && typeof code === "string" && validCode(code)) out.set(k, code);
    }
    return out;
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
      intent: denyIntent(e.code, meta.intent), // failed check, then the caller's label
      ip: meta.ip,
      cf_ray: meta.cfRay,
      token_jti: meta.tokenJti,
    });
  }

  /** enqueuePendingOutcome persists an outcome batch that could not be written after
   * the CAS (case c). It is keyed by the full idempotency key, so the outcome of a
   * re-created project (whose epochs restart at 1) never overwrites an older one. */
  private async enqueuePendingOutcome(rows: AuditRow[], idempotencyKey: string): Promise<void> {
    const rec: PendingOutcome = { rows, idempotencyKey };
    await this.ctx.storage.put(`${PENDING_OUTCOME_PREFIX}${idempotencyKey}`, rec);
    await this.ctx.storage.setAlarm(Date.now() + POINTER_EVENT_RETRY_MS);
  }

  /** outcomeRefused handles a deliberate refusal from the audit DO (409: the same key
   * already holds a DIFFERENT input; 400: a row field is invalid). No retry can
   * succeed: alert and stop; never loop. */
  private async outcomeRefused(idempotencyKey: string, err: unknown): Promise<void> {
    const code = err instanceof AuditAppendError && err.status === 400 ? "ROW_INVALID" : "IDEMPOTENCY_MISMATCH";
    console.error(`writer-do: audit outcome refused with ${code}, dropped (${idempotencyKey})`);
    await deliverAlert({ DISCORD_WEBHOOK_URL: this.discordUrl, AUDIT_LOG: this.auditLog, BROKER_ALERT: this.brokerAlert }, ALERT.A8, `audit outcome refused: ${code}; outcome rows not written`, { idempotencyKey }).catch(() => {});
  }

  /** enqueuePendingPointerEvent, yazılamayan pointer-event'i pending işaretler + alarm kurar. */
  private async enqueuePendingPointerEvent(r2Key: string, body: string): Promise<void> {
    const rec: PendingPointerEvent = { r2Key, body };
    // Keyed by the R2 key, which names the store generation (epoch + manifest hash).
    await this.ctx.storage.put(`${PENDING_POINTER_EVENT_PREFIX}${r2Key}`, rec);
    await this.ctx.storage.setAlarm(Date.now() + POINTER_EVENT_RETRY_MS);
  }

  /**
   * alarm, bekleyen pointer-event / audit-outcome / escrow-push kayıtlarını drene
   * eder (crash-recovery). Her yazım idempotenttir (onlyIf-absent / idempotencyKey).
   */
  async alarm(): Promise<void> {
    let remaining = 0;
    // (0) A commit left between its manifest PUT and its CAS (E-M2): finished or
    // discarded under the commit lock. Errors are caught inside the lock (a throw
    // there resets the object) and leave the intent for the next alarm.
    const recovered = await this.ctx.blockConcurrencyWhile(async () => {
      try {
        await this.recoverIntent();
        return true;
      } catch (err) {
        console.error("writer-do: commit intent recovery still failing", err);
        return false;
      }
    });
    if (!recovered) remaining++;
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
        await auditAppendBatch(this.auditLog, rec.rows.map(clampLegacyIntent), { idempotencyKey: rec.idempotencyKey });
        await this.ctx.storage.delete(storageKey);
      } catch (err) {
        if (isTerminalRefusal(err)) {
          await this.ctx.storage.delete(storageKey);
          await this.outcomeRefused(rec.idempotencyKey, err);
          continue;
        }
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

/**
 * clampLegacyIntent shortens the intent of a pending outcome queued before the
 * AUDIT_FIELD_MAX cap existed (its X-Wapps-Intent had no bound then). The cut is
 * explicit: the text ends with "…[truncated from N]", N = the original length.
 * New commits never need it: the edge refuses a longer intent header.
 */
function clampLegacyIntent(row: AuditRow): AuditRow {
  const intent = row.intent;
  if (typeof intent !== "string" || intent.length <= AUDIT_FIELD_MAX) return row;
  const marker = `…[truncated from ${intent.length}]`;
  return { ...row, intent: intent.slice(0, AUDIT_FIELD_MAX - marker.length) + marker };
}

/** pointerNamesIntent: the store's pointer names the intent's manifest, i.e. the
 * intent's pointer CAS landed. A malformed pointer is not the intent's. */
function pointerNamesIntent(cur: { bytes: Uint8Array } | null, intent: CommitIntent): boolean {
  if (!cur) return false;
  try {
    const ptr = parseCurrentPointer(cur.bytes);
    return ptr.epoch === intent.epoch && ptr.manifestSha256 === intent.manifestSha256;
  } catch {
    return false;
  }
}

/** isTerminalRefusal: the audit DO refused on purpose (400 ROW_INVALID, 409 IDEMPOTENCY_MISMATCH); a retry cannot succeed. */
function isTerminalRefusal(err: unknown): boolean {
  return err instanceof AuditAppendError && (err.status === 400 || err.status === 409);
}

/** emptyToNull, boş/absent header string'ini null'a çevirir (audit alanları). */
function emptyToNull(v: string | null): string | null {
  return v && v.trim() !== "" ? v : null;
}
