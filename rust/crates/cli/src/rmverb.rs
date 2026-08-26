// rmverb, `wapps secrets rm <KEY>` — bir anahtari store'dan KALDIRIR
// (DELETE /v1/projects/{p}/keys/{KEY}; silme = manifest'te yokluk, §2.6).
//
// NEDEN AYRI BIR FIIL: `set` yalnizca yazar, `rotate` degeri degistirir. Bir
// sirrin ait oldugu kaynak yok oldugunda (silinen servis hesabi, kapatilan
// saglayici) store'da OKSUZ bir kayit kaliyordu ve onu temizlemenin hicbir yolu
// yoktu.
//
// SOZLESME (get/list ayriminin AYNI cizgisi: AD gorunur, DEGER asla):
//   - ajan modunda REDDEDILIR (agentPolicy: refuse_agent) — silme geri alinamaz;
//   - sunucuda AYRI bir `delete` grant'i ister (write YETMEZ, §4.2 rev4);
//   - insan onayi ister ("yes"), --yes ile atlanir;
//   - olmayan anahtarda SESSIZ BASARI DEGIL: gate 404 → adi konmus NOT_FOUND;
//   - cikti yalnizca anahtar ADIdir, hicbir kosulda deger.
//
// OLCULEN KAPI SIRASI (differential: agent_rm_missing_arg):
//   1. arite            (cobra ExactArgs(1) — PersistentPreRunE'dan ONCE)
//   2. ajan politikasi  (refuse_agent → AGENT_MODE_REFUSED)
//   3. baglama kapisi   — ERISILEMEZ: 2 ajan modunda zaten reddediyor,
//                          insan modunda 2 hic ates etmiyor ama 3 ediyor
//   4. proje cozumu     (storeProject → NOT_FOUND)
//   5. onay             (--yes ile atlanir)
//   6. DELETE
//
// 1 ile 2'nin sirasi GOZLEMLENEBILIR: ajan modunda eksik arguman
// AGENT_MODE_REFUSED degil bir ARITE hatasi verir.
//
// ORACLE: cmd/secrets/rm.go.

/// prompt, onay istemini uretir. Hem anahtari hem projeyi ADIYLA gosterir:
/// operator neyi, NEREDEN sildigini gormeden onaylamamali.
pub fn prompt(key: &str, project: &str) -> String {
    format!("Remove {key} from {project}? This cannot be undone. Type 'yes' to confirm: ")
}

/// success_line, basari satiridir — yalnizca ANAHTAR ADI ve PROJE.
pub fn success_line(key: &str, project: &str) -> String {
    format!("✓ Removed {key} (store: {project})\n")
}
