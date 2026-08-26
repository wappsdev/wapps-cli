// confirm, YIKICI fiillerin (secrets rm, projects rm) onunde duran onay
// istemidir.
//
// Kabul edilen TEK cevap tam olarak "yes". "y" DEGIL, "YES" DEGIL, bos girdi
// DEGIL. Bu bir katilik gosterisi degil: silme geri alinamaz ve belirsizlik
// iptal demektir. Bir "kolaylik" olarak "y"yi kabul etmek, yanlis pencerede
// Enter'a basan operatoru bir sirdan ederdi.
//
// EOF de reddir (Go: sc.Scan() false → (false, nil)) — soru sorulamadiysa
// sorulmus gibi yapilmaz.
//
// ORACLE: cmd/secrets/policy.go (confirmTTY).
use std::io::{BufRead, BufReader, Read, Write};

/// ask, istemi yazar ve cevabin tam olarak "yes" oldugunu doner.
///
/// Istem cevabi OKUMADAN once yaziliyor ve akis bosaltiliyor: aksi halde bir
/// pty'de soru gorunmeden once okuma bloklanirdi ve operator bos bir ekrana
/// bakardi.
pub fn ask<R: Read, W: Write>(r: &mut R, w: &mut W, prompt: &str) -> bool {
    let _ = write!(w, "{prompt}");
    let _ = w.flush();
    let mut line = String::new();
    // bufio.Scanner gibi TEK satir okunur; EOF → cevap yok → ret.
    if BufReader::new(r).read_line(&mut line).unwrap_or(0) == 0 {
        return false;
    }
    line.trim() == "yes"
}
