// envverb, `wapps secrets env` fiilinin YAZICISIDIR.
//
// ORACLE: cmd/secrets/env.go (writeEnvFileAtomic).
//
// NEDEN `atomicfile::write` — ve neden ARTIK ayri bir yazici DEGIL: Go tarafi
// bu iki yolu ayri yazmisti ve farklar SIR TASIYAN bir dosyanin diskteki izin
// penceresini belirliyordu. Ucuncusu bir GUVENLIK kusuruydu:
//
//   atomicfile::write        eski yazici (burasi)
//   ----------------------   -----------------------------------------------
//   `.{ad}.{pid}.{ns}.tmp`   `{ad}.tmp` — SABIT, tahmin edilebilir ad
//   create_new (O_EXCL)      O_CREATE|O_TRUNC — VAR OLANI yeniden kullanir
//   mod acikca uygulanir     0600 ISTENIR ama var olan dosyanin modu KALIR
//   fsync VAR                fsync YOK
//
// UCUNCU SATIR BULGUYDU: hedefin yaninda onceden 0644 bir `<hedef>.tmp`
// duruyorsa open(2) modu YOK SAYAR ("the mode argument shall be ignored if the
// file exists") ve rename sonrasi duz metin sir 0644 ile kalir. Port bunu
// BILEREK taklit ediyordu — daraltmak sahadaki ikiliyle ayrisma demek olurdu.
// Artik IKI TARAF DA duzeltildi (ayni commit), yani ayrisma yok ve pencere
// kapali: bayat `.tmp` HIC acilmiyor.
//
// HATA METNI gecici dosyanin adini TASIMAZ: o ad rastgeledir ve ayni hata iki
// kosuda iki farkli cumle uretirdi. Adlandirilan sey HEDEF.
use crate::atomicfile;
use crate::envwrite;
use crate::goerr;
use std::path::Path;

/// write_env_file_atomic, export satirlarini HEDEFE atomik ve 0600 ile yazar.
/// Hatalarin metni Go'nun cumlesidir: "env: write <hedef>: <errno>".
pub fn write_env_file_atomic(path: &Path, values_json: &[u8], prefix: &str) -> Result<(), String> {
    // Bicimlendirme ONCE tampona: bir ayristirma hatasinda diskte HICBIR sey
    // olusmaz (eski yazici once dosyayi acip sonra siliyordu).
    let mut buf: Vec<u8> = Vec::new();
    envwrite::write_tofu_outputs_as_env(values_json, prefix, &mut buf)?;
    atomicfile::write(path, &buf, 0o600)
        .map_err(|e| format!("env: write {}: {}", path.display(), goerr::bare_errno(&e)))
}
