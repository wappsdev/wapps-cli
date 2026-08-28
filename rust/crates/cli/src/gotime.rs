// gotime, Go'nun `time.Unix(n, 0).UTC().Format(time.RFC3339)` ciktisidir.
//
// NEDEN ELDE YAZILDI — `rotateplan::rfc3339_valid` ile AYNI karar: bir tarih
// kutuphanesi (chrono/time) bu grafige yeni crate'ler sokardi ve bu estate
// TEK bir bicimleme cagrisi icin bunu odemiyor. Aradaki fark su: orada elde
// yazilan sey bir KABUL KUMESIYDI (deger tel'e AYNEN biniyordu), burada
// gercek bir TAKVIM hesabi var — cunku `token exchange` gate'ten gelen bir
// unix damgasini INSANA basiyor.
//
// TEK MUSTERISI `token exchange`in stderr metadata satiri, ve o satirin
// baytlari Go ikilisinden OLCULDU (tests/gotime.rs).

/// rfc3339_utc, unix saniyesini `YYYY-MM-DDTHH:MM:SSZ` olarak yazar.
///
/// NEGATIF GIRDI TASINMIYOR ve bu bir eksiklik degil bir kapsam: tek cagiran
/// `exp > 0` dalinda. Go negatif damgalari da bicimliyor; onu tasimak
/// cagirani olmayan bir dal tasimak olurdu, ve olculmemis bir dal tasimak
/// daha da kotusu. Negatif bir girdi burada 1970 oncesine DUSMEZ, saturate
/// eder — sessizce yanlis bir tarih uretmektense sabit bir taban.
pub fn rfc3339_utc(unix: i64) -> String {
    let secs = unix.max(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

// civil_from_days, 1970-01-01'den bu yana gecen gunu (yil, ay, gun)'e cevirir.
//
// Howard Hinnant'in `civil_from_days` algoritmasi: takvimi MART'ta baslatarak
// artik gunu yilin SONUNA atiyor, boylece ay uzunluklari tek bir formule
// sigiyor ve artik yil kurallarinin ucu de (4 / 100 / 400) tek bir yerde
// kaliyor. Ay tablosuyla dongu yazmak da mumkundu; bu bicim, testteki uc
// artik-yil vakasinin AYNI iki satirdan gectigini gorunur kiliyor.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], MART = 0
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}
