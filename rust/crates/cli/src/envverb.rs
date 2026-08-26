// envverb, `wapps secrets env` fiilinin YAZICISIDIR.
//
// ORACLE: cmd/secrets/env.go (writeEnvFileAtomic).
//
// NEDEN AYRI BIR YAZICI — ve neden `atomicfile::write` DEGIL: Go tarafi bu iki
// yolu ayri yazmis ve farklar SIR TASIYAN bir dosyanin diskteki izin
// penceresini belirliyor, yani gorunmez degiller:
//
//   atomicfile::write        writeEnvFileAtomic (burasi)
//   ----------------------   -----------------------------------------------
//   `.{ad}.{pid}.{ns}.tmp`   `{ad}.tmp` — SABIT, tahmin edilebilir ad
//   create_new (O_EXCL)      O_CREATE|O_TRUNC — VAR OLANI yeniden kullanir
//   mod acikca uygulanir     0600 ISTENIR ama var olan dosyanin modu KALIR
//   fsync VAR                fsync YOK
//
// UCUNCU SATIR BIR BULGU: hedefin yaninda onceden 0644 bir `<hedef>.tmp`
// duruyorsa open(2) modu YOK SAYAR ("the mode argument shall be ignored if the
// file exists") ve rename sonrasi duz metin sir 0644 ile kalir. Bu Go'da BUGUN
// boyle. Port AYNISINI yapiyor: daraltmak sahadaki ikiliyle ayrisma demek
// olurdu ve fark, ayni penceredeki bir operatore SESSIZ gorunurdu. Bulgu
// raporlanip olculuyor (tests/envverb.rs + differential
// human_env_write_reuses_a_wide_temp) — susturulmuyor.
//
// OLCULEMEYEN TEK DAL: Go'nun `f.Close()` hatasi ("env: close temp: ...").
// Rust'ta `File`in kapanisi `Drop`ta ve hatayi YUTUYOR; gorebilmenin tek yolu
// ham fd'yi alip libc::close cagirmak olurdu. Yerel bir dosyada bu dal
// pratikte hic ates etmiyor, ve TAKLIT bir metin uretmek yerine dalin
// olmadigi burada YAZILIYOR.
use crate::envwrite;
use crate::goerr;
use std::io::Write;
use std::path::{Path, PathBuf};

/// temp_path, Go'nun kullandigi gecici dosya yoludur: `<hedef>.tmp`.
/// Ayri bir fonksiyon cunku bu ADIN tahmin edilebilir olmasi yukaridaki
/// bulgunun ta kendisi — bir test onu adiyla kurabilsin.
pub fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(".tmp");
    path.with_file_name(name)
}

/// write_env_file_atomic, export satirlarini `<path>.tmp`e yazar ve yerine
/// rename eder. Hatalarin metni Go'nun cumleleridir.
pub fn write_env_file_atomic(path: &Path, values_json: &[u8], prefix: &str) -> Result<(), String> {
    let tmp = temp_path(path);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 0600 YALNIZCA dosya OLUSTURULUYORSA gecerli — Go ile ayni.
        opts.mode(0o600);
    }
    let tmp_s = tmp.to_string_lossy().to_string();
    let mut f = opts
        .open(&tmp)
        .map_err(|e| format!("env: open temp {tmp_s}: {}", goerr::open_error(&tmp_s, &e)))?;

    // Bicimlendirme ONCE tampona: Go'da writeTofuOutputsAsEnv dogrudan dosyaya
    // yaziyor ama hata halinde dosyayi SILIYOR. Tampon ayni sonucu verir ve
    // yarim yazilmis bir gecici dosya HIC olusmaz.
    let mut buf: Vec<u8> = Vec::new();
    let formatted = envwrite::write_tofu_outputs_as_env(values_json, prefix, &mut buf);
    let written = formatted.and_then(|()| f.write_all(&buf).map_err(|e| format!("env: write: {e}")));
    if let Err(e) = written {
        drop(f);
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(f);

    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!(
            "env: rename {tmp_s} -> {}: {}",
            path.display(),
            goerr::path_error("rename", &format!("{tmp_s} {}", path.display()), &e)
        )
    })
}
