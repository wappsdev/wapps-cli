// execverb, `wapps secrets exec`in env kurucusu + calistirma blogudur.
//
// ORACLE: cmd/secrets/exec.go, cmd/secrets/exec_runner.go.
//
// AI-GUVENLI SOZLESME: wapps'in KENDISI hicbir sir degeri basmaz — yalnizca
// alt-surec basar, ve o cikti da enjekte edilen degerlerden ARINDIRILIR
// (scrubber, §7.4.3). Scrubber HER IKI modda da uygulanir: bir baglanti
// dizesini echo'layan bozuk bir arac, kimin transcript'inde olursa olsun ***
// basar.
use crate::envwrite;
use crate::scrubber;
use std::io::Write;

/// exec_env_and_values, zarf JSON'unu "KEY=VALUE" girdilerine cevirir ve AYRICA
/// enjekte edilen ham degerleri (scrubber ADAYLARI) doner.
///
/// Adaylar TUM bos-olmayan degerlerdir; floor + entropi suzgeci DAHA SONRA
/// (scrubber::filter_scrubbable) uygulanir ki cagiran taraf, atlamak ZORUNDA
/// kaldigi kisa sirlar icin tek seferlik bir sizinti notu basabilsin.
pub fn exec_env_and_values(
    archive_decrypted: &[u8],
    prefix: &str,
) -> Result<(Vec<String>, Vec<String>), String> {
    let outputs = envwrite::parse_archive(archive_decrypted, "parse archive")?;
    let mut env = Vec::with_capacity(outputs.len());
    let mut values = Vec::new();
    for (k, v) in &outputs {
        let val = value_to_shell_string(v);
        env.push(format!("{}={}", envwrite::env_name(prefix, k), val));
        if !val.is_empty() {
            values.push(val);
        }
    }
    Ok((env, values))
}

// value_to_shell_string, bir JSON degerini cocugun env'i icin TEK bir dizeye
// indirger.
//
// OLCULEN AYRISMA ve KORUNMASI gereken: burasi env DOSYASI yazicisindan farkli.
// Orada string-olmayan degerler json.Compact'ten geciyor; burada Go yalnizca
// TrimSpace yapiyor, yani `[1, 2]` bosluguyla birlikte kaliyor. Ikisini
// "tutarli" hale getirmek sahadaki ikiliyle ayrisirdi.
fn value_to_shell_string(v: &Option<Box<serde_json::value::RawValue>>) -> String {
    // Alan hic yoksa Go string(nil)=="" uretir; "null" DEGIL.
    let Some(raw) = v else { return String::new() };
    let trimmed = raw.get().trim();
    if trimmed == "null" {
        return "null".to_string();
    }
    if let Ok(s) = serde_json::from_str::<String>(trimmed) {
        return s;
    }
    // SIKISTIRMA YOK — yalnizca TrimSpace. Farki ureten satir bu.
    trimmed.to_string()
}

/// ExecRunner, alt-surec spawn dikisi. Uretimde default_exec_runner; testte
/// cocugu gercekten baslatmayan bir sahte ile degistirilebilir.
///
/// Imza `&str` (komut adi) + argumanlar + env + IKI ayri yazici alir; iki
/// yazici SART, cunku uretimde ikisi de AYRI birer scrubber.
pub type ExecRunner<'a> =
    &'a dyn Fn(&str, &[String], &[String], &mut dyn Write, &mut dyn Write) -> std::io::Result<i32>;

/// ExitAction, calistirma blogunun cagirana BIRAKTIGI karardir: alt-surecin
/// cikis kodu AYNEN yansitilmali. Surecten cikmak main'in isi, bir
/// kutuphane fonksiyonunun degil.
pub enum ExitAction {
    Ok,
    Exit(i32),
}

/// run_with_injected_env, exec-ailesinin ORTAK inject→scrub→run→flush→exit
/// blogudur:
///   - `injected` ("KEY=VALUE") kalitilan env'in SONUNA eklenir → cakismada
///     enjekte edilen KAZANIR (last-wins);
///   - `scrub_values`, filter_scrubbable'dan gecirilir (floor-alti atlanan
///     deger icin errw'ye TEK, DEGERSIZ uyari — child spawn'dan ONCE);
///   - cocugun stdout/stderr'i scrubber ile sarilir ve HER durumda flush
///     edilir (hata olsa bile kismi cikti REDAKTE EDILMIS kalir);
///   - sifir-disi cikis kodu cagirana AYNEN dondurulur.
pub fn run_with_injected_env<O: Write, E: Write>(
    args: &[String],
    injected: &[String],
    scrub_values: &[String],
    out: &mut O,
    errw: &mut E,
    runner: ExecRunner<'_>,
) -> Result<ExitAction, String> {
    // Uyari child spawn'dan ONCE basiliyor: sizinti notu, cocugun ciktisinin
    // arasina karismasin.
    let scrub_vals = scrubber::filter_scrubbable(scrub_values, Some(errw));

    let run_err;
    let exit_code;
    {
        let mut so = scrubber::Scrubber::new(out, &scrub_vals);
        let mut se = scrubber::Scrubber::new(errw, &scrub_vals);
        let mut so_dyn = ScrubSink(&mut so);
        let mut se_dyn = ScrubSink(&mut se);
        match runner(&args[0], &args[1..], injected, &mut so_dyn, &mut se_dyn) {
            Ok(code) => {
                exit_code = code;
                run_err = None;
            }
            Err(e) => {
                exit_code = -1;
                run_err = Some(e.to_string());
            }
        }
        // Flush HER yoldan gecer: hata durumunda bile kismi cikti redakte
        // edilmis kalmali.
        let _ = so.flush();
        let _ = se.flush();
    }

    if let Some(e) = run_err {
        return Err(format!("exec: {e}"));
    }
    if exit_code != 0 {
        return Ok(ExitAction::Exit(exit_code));
    }
    Ok(ExitAction::Ok)
}

// ScrubSink, Scrubber'i `dyn Write` olarak tasiyabilmek icin ince bir sarmal.
struct ScrubSink<'a, 'b, W: Write>(&'a mut scrubber::Scrubber<'b, W>);

impl<W: Write> Write for ScrubSink<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// default_exec_runner, istenen alt-sureci verilen env ile calistirir.
///
/// stdin wapps'in KENDI stdin'ine baglanir (TTY semantigi); stdout/stderr
/// CAGIRANIN verdigi yazicilara — uretimde bunlar streaming SCRUBBER'lardir,
/// yani exec edilen bir arac bir sirri transcript'e echo'layamaz.
///
/// Komut ad + argumanlarla calistiriliyor (bir KABUK DIZESI DEGIL), yani
/// komut-enjeksiyonu yuzeyi YOK.
pub fn default_exec_runner(
    name: &str,
    args: &[String],
    env: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> std::io::Result<i32> {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(name);
    cmd.args(args);
    // Enjekte edilenler kalitilan env'in SONUNA: cakismada enjekte edilen
    // kazanir (Go'daki append(os.Environ(), injected...) ile ayni).
    for entry in env {
        if let Some((k, v)) = entry.split_once('=') {
            cmd.env(k, v);
        }
    }
    cmd.stdin(Stdio::inherit()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Baslatma hatasi Go'nun METNIYLE sariliyor: sahadaki ikili
    // "fork/exec <yol>: no such file or directory" basiyor, Rust'in kendi
    // dizesi ise "No such file or directory (os error 2)" — buyuk harfli ve
    // numarali. Olculdu (human_exec_missing_command).
    let mut child = cmd.spawn().map_err(|e| {
        std::io::Error::other(crate::goerr::spawn_error(name, &e))
    })?;

    // stdout ve stderr AYRI okunuyor; tek bir borudan okumak ikisini karistirir.
    let mut child_out = child.stdout.take().expect("stdout borusu");
    let mut child_err = child.stderr.take().expect("stderr borusu");
    let mut ob = Vec::new();
    let mut eb = Vec::new();
    std::thread::scope(|s| {
        let h = s.spawn(|| {
            let _ = std::io::Read::read_to_end(&mut child_err, &mut eb);
        });
        let _ = std::io::Read::read_to_end(&mut child_out, &mut ob);
        let _ = h.join();
    });
    stdout.write_all(&ob)?;
    stderr.write_all(&eb)?;

    let status = child.wait()?;
    Ok(status.code().unwrap_or(-1))
}
