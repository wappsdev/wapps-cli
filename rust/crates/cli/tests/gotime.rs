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

// --- time.Duration.String() + Round(time.Second) + time.Until -----------------
//
// `wapps login` prints the session TTL through these three. Every expected
// string was measured from a Go 1.26 program.
use wapps::gotime::{duration_string, round_second, until_unix};

#[test]
fn duration_strings_match_go_below_and_above_one_second() {
    for (ns, want) in [
        (0i64, "0s"),
        (1, "1ns"),
        (999, "999ns"),
        (1_000, "1µs"),
        (1_500_000, "1.5ms"),
        (1_000_000_000, "1s"),
        (3_599_000_000_000, "59m59s"),
        (3_600_000_000_000, "1h0m0s"),
        (86_400_000_000_000, "24h0m0s"),
        (-90_000_000_000, "-1m30s"),
        (61_500_000_000, "1m1.5s"),
        (i64::MAX, "2562047h47m16.854775807s"),
        (i64::MIN, "-2562047h47m16.854775808s"),
    ] {
        assert_eq!(duration_string(ns), want, "ns={ns}");
    }
}

// Round saturates instead of wrapping: both extremes keep their fraction.
#[test]
fn rounding_to_a_second_saturates_at_both_ends() {
    assert_eq!(duration_string(round_second(i64::MAX)), "2562047h47m16.854775807s");
    assert_eq!(duration_string(round_second(i64::MIN)), "-2562047h47m16.854775808s");
    assert_eq!(duration_string(round_second(-9_223_372_036_000_000_000)), "-2562047h47m16s");
    // 9223372037 * Second wraps negative in Go; Round then saturates low.
    let wrapped = 9_223_372_037i64.wrapping_mul(1_000_000_000);
    assert_eq!(duration_string(round_second(wrapped)), "-2562047h47m16.854775808s");
    assert_eq!(round_second(1_499_999_999), 1_000_000_000);
    assert_eq!(round_second(1_500_000_000), 2_000_000_000);
    assert_eq!(round_second(-1_500_000_000), -2_000_000_000);
}

// time.Until(time.Unix(exp, 0)): a far-future exp saturates to maxDuration,
// which is what makes `login`'s success line deterministic in the corpus.
#[test]
fn until_saturates_for_a_far_future_expiry() {
    let now = (1_790_000_000i64, 123_456_789i64);
    assert_eq!(until_unix(99_999_999_999_999, now.0, now.1), i64::MAX);
    assert_eq!(until_unix(1_790_000_060, now.0, now.1), 59_876_543_211);
    assert_eq!(until_unix(1_790_000_000, now.0, now.1), -123_456_789);
    assert_eq!(
        duration_string(round_second(until_unix(1, 1_790_000_000, 0))),
        "-497222h13m19s"
    );
}
