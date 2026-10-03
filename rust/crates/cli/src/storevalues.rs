// storevalues, `cmd/secrets/archive_values.go`in portudur — ve BIR VERB DEGIL,
// bir KUTUPHANE FONKSIYONU.
//
// Adi tarihi: dosya bir zamanlar age-sifreli bir ARSIVI okuyordu (`ArchiveValues`).
// P1.7 yeniden-yonlendirmesinde arsiv okuyucusu SILINDI ve kaynak
// server-decrypt store oldu; ad kaldi. Bugun tek tuketicisi `wapps deploy`in
// credential fallback'idir: cagiran once env'e bakar, YALNIZCA env'de olmayan
// anahtarlar icin buraya duser.
//
// BU DILIMDE HICBIR VERB BURAYA ULASMIYOR (`wapps deploy` portlanmadi), yani
// differential'da OLCULEMEZ. Sozlesmesi bu yuzden Go'nun kendi testleriyle
// (cmd/secrets/archive_values_test.go) BIREBIR ayni sekilde, tests/storevalues.rs'te
// pinleniyor. Olculemeyen bir sey, hakkinda hicbir sey yazilmayan bir seyden
// iyidir — ama ikisi de differential'da yesil gorunur, o yuzden fark BURADA
// yaziliyor.
//
// UC SOZLESME, ve ucu de bir GUVENLIK ozelligi:
//
//  1. BEST-EFFORT ERISILEBILIRLIK: `.wapps.yaml` yoksa `Ok(None)` doner —
//     HATA DEGIL. Cagiran (deploy) o zaman env'e duser. Burada hata dondurmek,
//     store kullanmayan her projede deploy'u kirardi.
//  2. AD DUZLEMI KESISIMI ONCE: bulk read `all-or-nothing`tur, yani var
//     OLMAYAN tek bir aday adi TUM okumayi NOT_FOUND ile dusururdu. Once
//     degersiz `Keys` cagrilir (audit'e `value.read` DUSMEZ) ve yalnizca
//     MEVCUT adlar okunur — blast-radius minimum.
//  3. BOS KESISIM → OKUMA YOK: hicbir aday yoksa gate'e HIC gidilmez, yani
//     audit ledger'ina bir okuma satiri DUSMEZ. "Hicbir sey istemek" bir okuma
//     SAYILMAZ, ve rotate-plan bu ledger'i oracle olarak kullandigi icin bu
//     gercek bir fark.
//
// AI-safe: degerler yalnizca CAGIRANA doner; bu modul hicbir yere yazmaz.
use crate::clierr::Error;
use std::collections::BTreeMap;

/// wanted_subset, istenen aday adlardan store'da MEVCUT olanlari, ISTENEN
/// SIRAYLA ve TEKRARSIZ doner.
///
/// Tekrarsizlik Go'daki `present[k] = false` hilesinin karsiligi: ayni aday iki
/// kez gecerse bulk istege iki kez girmez. Sira KORUNUYOR (sıralanmıyor),
/// cunku Go da korumuyor.
pub fn wanted_subset(present: &[String], keys: &[String]) -> Vec<String> {
    let mut avail: std::collections::BTreeSet<&str> = present.iter().map(String::as_str).collect();
    let mut want = Vec::with_capacity(keys.len());
    for k in keys {
        if avail.remove(k.as_str()) {
            want.push(k.clone());
        }
    }
    want
}

/// KeysFn, AD DUZLEMI okuyucusudur (degersiz; audit'e `value.read` DUSMEZ).
///
/// `+ 'a`: cagiran odunc alan bir kapanis verebilsin diye. Varsayilan
/// `'static` olsaydi test sahtesi (yigindaki bir struct'i oduncleyen kapanis)
/// derlenmezdi ve seam KULLANILAMAZ olurdu.
pub type KeysFn<'a> = dyn Fn(&str) -> Result<Vec<String>, Error> + 'a;

/// ReadFn, DEGER duzlemi okuyucusudur (bulk, all-or-nothing).
pub type ReadFn<'a> = dyn Fn(&str, &[String]) -> Result<BTreeMap<String, String>, Error> + 'a;

/// store_values, `backend: store` bir `.wapps.yaml` varsa istenen anahtarlarin
/// DEGERLERINI store'dan ceker.
///
/// `keys_of` ve `read_of` ENJEKTE EDILIYOR — Go'daki `openStore` test seam'inin
/// karsiligi. Uretim cagiricisi gercek `store::keys`/`store::read`i verir;
/// test, aga cikmadan ayni akisi gezer.
///
/// Donusler:
///   - `Ok(None)`      → config YOK; cagiran env'e duser (HATA DEGIL)
///   - `Ok(Some(map))` → cozulen degerler (bos harita da olabilir)
///   - `Err(e)`        → GERCEK bir okuma hatasi (oturum, ag, grant reddi)
pub fn store_values(
    project: Option<&str>,
    keys: &[String],
    keys_of: &KeysFn<'_>,
    read_of: &ReadFn<'_>,
) -> Result<Option<BTreeMap<String, String>>, Error> {
    // Config yok → (None). Cagiran env-only cozumlemeye HATASIZ duser.
    let Some(project) = project else {
        return Ok(None);
    };

    let present = keys_of(project)?;
    let want = wanted_subset(&present, keys);
    if want.is_empty() {
        // GATE'E HIC GIDILMIYOR: bos bir kesisim icin bir okuma satiri
        // yazdirmak, audit ledger'ina olmamis bir okumayi kaydetmek olurdu.
        return Ok(Some(BTreeMap::new()));
    }
    Ok(Some(read_of(project, &want)?))
}
