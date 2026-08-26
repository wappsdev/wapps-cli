// applyverb, bildirilen her tuketim hedefini yazar.
//
// ORACLE: cmd/secrets/apply.go.
//
// GARANTI SEVIYESI — dikkatle okunmali, cunku "duzeltilmek" istenecek yer
// burasi: hedef BASINA atomik (temp+fsync+rename, 0600) ve idempotent
// (bayt-es dosyaya DOKUNULMAZ, mtime korunur), ama hedefler ARASINDA atomik
// DEGIL. i'inci hedefte patlarsa 0..i-1 YAZILMIS kalir. Bu bildirilen
// sozlesmedir; hepsini geri almak sahadaki ikiliyle ayrisirdi.
use crate::atomicfile;
use crate::envwrite;
use crate::wappsyaml::WappsYaml;
use std::io::Write;
use std::path::Path;

/// apply_targets, bildirilen her hedefi IDEMPOTENT yazar.
///
/// `stdout_w` hedef basina tek bir insan-okunur satir alir (wrote / unchanged)
/// ki operator komutun ne yaptigini gorsun. DEGER ASLA BASILMAZ.
pub fn apply_targets<W: Write>(
    cfg: &WappsYaml,
    values_json: &[u8],
    config_root: &str,
    stdout_w: &mut W,
) -> Result<(), String> {
    for (i, t) in cfg.targets.iter().enumerate() {
        let prefix = t.effective_prefix(&cfg.default_prefix);

        let mut buf: Vec<u8> = Vec::new();
        envwrite::write_tofu_outputs_as_env(values_json, prefix, &mut buf)
            .map_err(|e| format!("apply: targets[{i}] {}: format: {e}", t.path))?;

        // Hedef yolu config_root'a gore cozuluyor: bir --project/--config
        // apply'i <proje>/.env.local yazsin, <cwd>/.env.local DEGIL — duz metin
        // sir dosyalarini operatorun bulundugu dizine ASLA sacma. Gosterilen
        // satirlar HAM t.path'i (depo-goreli) tutuyor, okunabilirlik icin.
        let target = t.resolve_path(config_root);
        let target = Path::new(&target);

        // IDEMPOTENS: dosya zaten TAM OLARAK bu baytlari tasiyorsa dokunma.
        // Gereksiz mtime guncellemeleri dosya izleyicilerini (Next.js dev
        // server, Vite HMR, fs.watch) bosuna tetikler.
        match std::fs::read(target) {
            Ok(existing) if existing == buf => {
                writeln!(stdout_w, "unchanged {}", t.path)
                    .map_err(|e| format!("apply: write report: {e}"))?;
                continue;
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!("apply: targets[{i}] {}: stat existing: {e}", t.path))
            }
        }

        atomicfile::write(target, &buf, 0o600)
            .map_err(|e| format!("apply: targets[{i}] {}: write: {e}", t.path))?;
        writeln!(stdout_w, "wrote {}", t.path)
            .map_err(|e| format!("apply: write report: {e}"))?;
    }
    Ok(())
}

/// apply_targets_after_write, store'u DEGISTIREN verb'lerin (set, import-env,
/// sync) yazim-sonrasi kancasidir. Bildirilen hedef yoksa NO-OP.
///
/// Hata, store yazimini ZATEN ISLENMIS olarak adlandirir: operator yalnizca
/// yerel dosya uretiminin tekrarlanmasi gerektigini bilsin — SIR YAZIMININ
/// DEGIL. Bu cumle operatorun elindeki tek ipucu.
pub fn apply_targets_after_write<W: Write>(
    cfg: &WappsYaml,
    values_json: &[u8],
    config_root: &str,
    stdout_w: &mut W,
) -> Result<(), String> {
    if cfg.targets.is_empty() {
        return Ok(());
    }
    apply_targets(cfg, values_json, config_root, stdout_w).map_err(|e| {
        format!("the store write succeeded but writing local targets failed: {e} (run 'wapps secrets apply' to retry)")
    })
}
