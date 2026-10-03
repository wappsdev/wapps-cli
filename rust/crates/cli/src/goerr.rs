// goerr, Go'nun KULLANICIYA GOSTERDIGI hata dizelerini uretir.
//
// Bu, Go'nun ic hata tablosunu taklit etmek DEGILDIR: mesajin kendisi
// sozlesmenin parcasi ve POSIX errno adlari iki dilde de ayni. Rust'in kendi
// dizesi ("No such file or directory (os error 2)") buyuk harfli ve numara
// tasiyor — sahadaki ikiliyle ayrisirdi.
//
// Eskiden setverb.rs'te ozeldi; wappsyaml de ayni metne ihtiyac duyunca buraya
// alindi ki iki kopya birbirinden ayrisamasin.

/// errno_text, POSIX errno adini doner; tanimadigi bir errno'da None.
///
/// None donmesi bilincli: cagiran o durumda Rust'in KENDI dizesine duser
/// (uydurmaz). Olculmemis bir kolda sessizce yanlis bir metin uretmek, farkli
/// bir metin uretmekten kotudur.
pub(crate) fn errno_text(e: &std::io::Error) -> Option<&'static str> {
    use std::io::ErrorKind;
    Some(match e.kind() {
        ErrorKind::NotFound => "no such file or directory",
        ErrorKind::PermissionDenied => "permission denied",
        ErrorKind::IsADirectory => "is a directory",
        ErrorKind::NotADirectory => "not a directory",
        ErrorKind::AlreadyExists => "file exists",
        _ => return None,
    })
}

/// path_error, Go'nun *os.PathError metnini uretir: "<op> <yol>: <errno>".
pub fn path_error(op: &str, path: &str, e: &std::io::Error) -> String {
    match errno_text(e) {
        Some(d) => format!("{op} {path}: {d}"),
        None => format!("{op} {path}: {e}"),
    }
}

/// open_error, dosya acma hatasi ("open <yol>: <errno>").
pub fn open_error(path: &str, e: &std::io::Error) -> String {
    path_error("open", path, e)
}

/// spawn_error, Go'nun os/exec'inin alt-surec baslatamama metnini uretir.
///
/// IKI AYRI SEKIL, ve hangisinin ciktigi ADIN icinde egik cizgi olup
/// olmamasina bagli (Go: exec.Command LookPath'i yalnizca ayirac YOKSA yapar):
///   - ayirac VAR → LookPath yok, dogrudan fork → *os.PathError:
///     "fork/exec <yol>: <errno>"
///   - ayirac YOK → LookPath basarisiz → *exec.Error:
///     "exec: \"<ad>\": executable file not found in $PATH"
pub fn spawn_error(name: &str, e: &std::io::Error) -> String {
    if name.contains('/') {
        return path_error("fork/exec", name, e);
    }
    if e.kind() == std::io::ErrorKind::NotFound {
        return format!(
            "exec: {}: executable file not found in $PATH",
            crate::gojson::quote(name)
        );
    }
    format!("exec: {}: {}", crate::gojson::quote(name), e)
}

/// bare_errno, YALNIZCA errno metnini doner (yol/op ONEKI YOK).
///
/// Cagrildigi yer: sarmalayan Go hatasinin icindeki *os.PathError'in `.Err`i
/// alinip basildigi durumlar. Yol RASTGELE bir gecici dosya oldugunda metne
/// KOYULAMAZ — ayni hata iki kosuda iki farkli cumle uretirdi.
pub fn bare_errno(e: &std::io::Error) -> String {
    match errno_text(e) {
        Some(d) => d.to_string(),
        None => format!("{e}"),
    }
}
