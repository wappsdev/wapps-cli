// atomicfile, bir dosyayi ya TAMAMEN ya da HIC yazar.
//
// ORACLE: internal/atomicfile/atomicfile.go. Yaptigi isin sifrelemeyle ilgisi
// yok: `apply`in yazdigi tuketim hedefleri (.env.local vb.) DUZ METINDIR ve
// yarim yazilmis bir .env dosyasi bir dev sunucusunu SESSIZCE bozar.
//
// Sira ve her adimin sebebi:
//   1. AYNI dizinde gecici dosya — cross-filesystem rename atomikligi
//      kaybettirir;
//   2. fsync — rename METADATA atomikligini garanti eder ama VERININ diske
//      indigini ETMEZ; fsync'siz bir guc kesintisi yeni adi bos/bayat icerikle
//      birakabilir;
//   3. rename — POSIX'te atomik.
//
// Eskiden epochpin.rs'te ozeldi. Baglama defteri ve `apply` de ayni garantiyi
// istedigi icin buraya alindi: uc kopya, ucu de "atomik" diyen ama zamanla
// ayrisan uc yazici demek olurdu.
use std::io::Write;
use std::path::Path;

/// write, data'yi path'e ATOMIK ve verilen mod ile yazar.
pub fn write(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let base = path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // Rastgele sonek: es zamanli iki yazici birbirinin gecici dosyasini
    // truncate etmesin (Go'da CreateTemp'in "*"'i bu isi yapiyor).
    let tmp = dir.join(format!(".{base}.{}.{nanos}.tmp", std::process::id()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(&tmp)?;
    let res = f.write_all(data).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// create_dir_0700, hedef dizini kurar ve 0700'e sabitler.
pub fn create_dir_0700(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
