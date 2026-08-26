// setverb, `wapps secrets set <KEY>`in DEGER YAKALAMA yarisidir.
//
// Neden ayri bir modul: yakalama, store yaziminin aksine TERMINALE dokunuyor.
// Go tarafi degeri `golang.org/x/term`in ReadPassword'u ile YANKISIZ okuyor;
// bu, gizli degerin operatorun ekranina — ve pty ile kosan bir ajan
// transcript'ine — hic dusmemesini saglayan tek mekanizma. Portun bu yarisi
// bayt sadakatinden once GUVENLIK sadakati ister.
//
// HICBIR YERDE DEGER LOGLANMAZ: bu dosyadaki hata ve uyari metinlerinin hicbiri
// yakalanan degeri (ya da uzunlugunu) tasimaz.
use std::io::Write;

/// PROMPT_SUFFIX, prompt metninin sonu ("Value for <KEY>: ").
/// stderr'e yazilir — stdout gizli degerin ASLA gecmedigi kanal olarak kalir.
fn prompt_text(key: &str) -> String {
    format!("Value for {key}: ")
}

/// Captured, yakalanan deger + okumanin bir TTY'den gelip gelmedigi.
/// tty=false, degerin kabuk gecmisine dusmus OLABILECEGI anlamina gelir.
pub struct Captured {
    pub value: String,
    pub tty: bool,
}

/// trim_trailing_newline, sondaki \n / \r dizisini soyar.
/// `printf %s "$V" > f` yerine `echo "$V" > f` yazan operator ayni degeri
/// yazmis olsun diye (Go'daki trimTrailingNewline ile ayni dongu).
pub fn trim_trailing_newline(s: &str) -> &str {
    let b = s.as_bytes();
    let mut end = b.len();
    while end > 0 && (b[end - 1] == b'\n' || b[end - 1] == b'\r') {
        end -= 1;
    }
    &s[..end]
}

// go_open_error, goerr'a delege eder. Metnin GEREKCESI orada yazili; burada
// duran tek sey, bu modulun onu --from-file yolunda kullandigi.
fn go_open_error(path: &str, e: &std::io::Error) -> String {
    crate::goerr::open_error(path, e)
}

/// read_from_file, --from-file yolunu okur ve sondaki newline'i soyar.
pub fn read_from_file(path: &str) -> Result<String, String> {
    match std::fs::read(path) {
        // Deger UTF-8 olmayabilir; Go `string(raw)` ile ham baytlari tasiyor,
        // yani gecersiz diziler KAYBOLMAZ, degistirilir. from_utf8_lossy ayni
        // gozlemlenebilir sonucu verir (Go'nun string'i de dogrulanmamis bayt
        // dizisidir; JSON kodlamasinda ikisi de U+FFFD'ye duser).
        Ok(raw) => Ok(trim_trailing_newline(&String::from_utf8_lossy(&raw)).to_string()),
        Err(e) => Err(format!("secrets.set: read --from-file: {}", go_open_error(path, &e))),
    }
}

// --- YANKISIZ TTY OKUMASI ---------------------------------------------------
//
// Go'nun term.ReadPassword'unun (unix) portu, ADIM ADIM ayni:
//   1. mevcut termios saklanir,
//   2. ECHO KAPATILIR; ICANON + ISIG ACILIR; ICRNL ACILIR,
//   3. satir bayt bayt okunur (asagidaki dongu ReadPassword'un readPasswordLine'i),
//   4. termios HER durumda geri yuklenir.
//
// ICRNL kritik: operatorun Enter'i \r olarak gelir ve cekirdek onu \n'e cevirir,
// boylece iki tus da satiri ayni sekilde bitirir (human_set_prompt_cr).
// ISIG'in ACIK birakilmasi da bilincli: Ctrl-C bir sir prompt'unda calismalidir.

#[cfg(unix)]
fn read_password_line() -> Result<String, std::io::Error> {
    use rustix::termios::{
        tcgetattr, tcsetattr, InputModes, LocalModes, OptionalActions,
    };
    let stdin = rustix::stdio::stdin();

    let original = tcgetattr(stdin)?;
    let mut raw = original.clone();
    raw.local_modes &= !LocalModes::ECHO;
    raw.local_modes |= LocalModes::ICANON | LocalModes::ISIG;
    raw.input_modes |= InputModes::ICRNL;
    tcsetattr(stdin, OptionalActions::Now, &raw)?;

    let result = read_line_bytes(stdin);

    // Geri yukleme HER yoldan gecer (hata dahil): terminali yankisiz birakmak
    // operatorun kabugunu bozar.
    let _ = tcsetattr(stdin, OptionalActions::Now, &original);
    result
}

// read_line_bytes, Go'daki readPasswordLine'in dongusudur: TEK bayt okur,
// \b son bayti siler, \n satiri bitirir, digerleri birikir. EOF'ta biriken
// varsa onu doner.
//
// Neden tampon YOK: bir BufReader satir sonrasini da yutabilir. Go read(2)'yi
// tek baytla cagiriyor; ayni sey yapiliyor ki stdin'de kalan baytlar
// (varsa) bu okumaya kurban gitmesin.
#[cfg(unix)]
fn read_line_bytes(fd: rustix::fd::BorrowedFd<'_>) -> Result<String, std::io::Error> {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        match rustix::io::read(fd, &mut buf) {
            Ok(0) => {
                // EOF: biriken varsa deger odur (Go ile ayni), yoksa EOF hatasi.
                if out.is_empty() {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                }
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
            Ok(_) => match buf[0] {
                b'\x08' => {
                    out.pop();
                }
                b'\n' => return Ok(String::from_utf8_lossy(&out).into_owned()),
                b => out.push(b),
            },
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(std::io::Error::from_raw_os_error(e.raw_os_error())),
        }
    }
}

/// prompt_value, degeri operatorden okur.
///
/// TTY ise yankisiz; degilse duz okuma (cagiran o durumda bir UYARI basar —
/// deger kabuk gecmisine dusmus olabilir).
pub fn prompt_value<W: Write>(errw: &mut W, key: &str) -> Result<Captured, String> {
    let _ = write!(errw, "{}", prompt_text(key));
    let _ = errw.flush();

    if crate::agentmode::stdin_is_tty() {
        return match read_password_line() {
            Ok(v) => {
                // ReadPassword'dan SONRA tek bir newline: kullanicinin
                // basmadigi (cunku yankilanmadi) satir sonunu biz basiyoruz.
                let _ = writeln!(errw);
                Ok(Captured { value: v, tty: true })
            }
            Err(e) => {
                let _ = writeln!(errw);
                Err(format!("secrets.set: read value: {e}"))
            }
        };
    }

    // Non-TTY: tum stdin okunur, sondaki newline soyulur.
    let mut raw = Vec::new();
    match std::io::Read::read_to_end(&mut std::io::stdin(), &mut raw) {
        Ok(_) => Ok(Captured {
            value: trim_trailing_newline(&String::from_utf8_lossy(&raw)).to_string(),
            tty: false,
        }),
        Err(e) => Err(format!("secrets.set: read value: {e}")),
    }
}

/// capture_value, set'in deger yakalamasidir (Go'daki captureSetValue).
///
/// Sira Go ile AYNI: once kaynak (--from-file | prompt), sonra BOS reddi, en
/// son non-TTY uyarisi. Uyari BASARILI yolda da basilir — deger yazilir ama
/// operator gecmise dusmus olabilecegini gorur.
pub fn capture_value<W: Write>(
    errw: &mut W,
    key: &str,
    from_file: Option<&str>,
) -> Result<String, String> {
    let captured = match from_file {
        Some(path) => Captured { value: read_from_file(path)?, tty: true },
        None => prompt_value(errw, key)?,
    };

    if captured.value.is_empty() {
        return Err(
            "secrets.set: empty value rejected (use a placeholder if you need to declare an empty var)"
                .to_string(),
        );
    }
    if !captured.tty {
        let _ = writeln!(
            errw,
            "⚠ stdin is not a TTY — value may have been recorded in shell history"
        );
    }
    Ok(captured.value)
}

// BAGLAMA KAPISI BURADA DEGIL, ve bu bir eksiklik degil bir DUZELTME:
//
// Burada `binding_gate` adli dar bir kapi duruyordu. Yalnizca `--project <ad>`
// kolunu kapiyor, digerini "bu build'de erisilemez" diye geciyordu — cunku
// run_set Ctx'i HIC cozmuyordu. O varsayim OLCULDU ve YANLIS cikti: config
// yukleme portlanmisti, yani `set` .wapps.yaml'i olan bir dizinde Go'nun
// vardigi BINDING_UNPINNED'e HIC varmiyordu.
//
// Kapi artik run_set icinde, exec/apply ile AYNI `gate()` uzerinden
// (configctx::check_repo_binding). Dar kopya SILINDI: birakilsaydi, ileride
// onu cagiran biri baglama kontrolunu sessizce tek kola geri daraltirdi.
