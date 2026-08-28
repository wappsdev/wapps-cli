// Go'nun `time.Unix(n, 0).UTC().Format(time.RFC3339)` ciktisi.
//
// NEDEN ELDE YAZILDI: `rotateplan::rfc3339_valid` ile AYNI gerekce — bir tarih
// kutuphanesi (chrono/time) bu grafige yeni crate'ler sokardi ve tek bir
// bicimleme cagrisi icin bu odenmiyor. Aradaki fark su: orada bir KABUL
// KUMESI vardi, burada gercek bir TAKVIM hesabi var (artik yillar dahil).
//
// BEKLENEN DIZELERIN HEPSI Go ikilisinden OLCULDU (`token exchange`in stderr
// satiri), hatirlanmadi.
use wapps::gotime::rfc3339_utc;

#[test]
fn the_epoch_and_its_first_second() {
    assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(rfc3339_utc(1), "1970-01-01T00:00:01Z");
}

#[test]
fn a_minted_tokens_expiry_formats_like_the_go_binary() {
    assert_eq!(rfc3339_utc(1793318400), "2026-10-30T00:00:00Z");
    assert_eq!(rfc3339_utc(1767225599), "2025-12-31T23:59:59Z");
}

// ARTIK YIL UC KURALI DA GEZILIYOR: 4'e bolunen (2024), 100'e bolunup
// atlanan (2100 — 1 Mart), 400'e bolunup atlanmayan (2000).
#[test]
fn leap_year_rules_are_all_three_exercised() {
    assert_eq!(rfc3339_utc(1709164800), "2024-02-29T00:00:00Z");
    assert_eq!(rfc3339_utc(951782400), "2000-02-29T00:00:00Z");
    assert_eq!(rfc3339_utc(4102444800), "2100-01-01T00:00:00Z");
    // 2100 artik yil DEGIL: 28 Subat'in ERTESI GUNU 1 Mart, 29 Subat degil.
    assert_eq!(rfc3339_utc(4107456000), "2100-02-28T00:00:00Z");
    assert_eq!(rfc3339_utc(4107542400), "2100-03-01T00:00:00Z");
}

#[test]
fn four_digit_years_run_to_the_end_of_the_range_go_prints() {
    assert_eq!(rfc3339_utc(253402300799), "9999-12-31T23:59:59Z");
}
