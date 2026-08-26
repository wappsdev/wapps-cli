// `secrets import-env`: bir .env dosyasindan store'a TOPLU yazim.
//
// ORACLE: internal/source/file.go (parseEnvFile, unquote) ve
// cmd/secrets/import_env.go (rapor satirlari).
//
// SIR DISIPLINI — bu dosyada gecen HICBIR deger gercek bir sir DEGIL; hepsi
// uydurma test dizeleri. Testler diske gercek bir sir yazmiyor ve gercek bir
// gate'e HIC baglanmiyor.
//
// AYRISTIRICI NEDEN PAYLASILIYOR: Go'da import-env, `file` kaynaginin
// ayristiricisini AYNEN cagiriyor (ParseEnvFileBytes). Boylece temiz import
// edilen bir .env, ayni depoda bir file-source olarak da calisiyor. Ayri bir
// ayristirici yazmak o esitligi sessizce bozardi.
use wapps::importenv;

fn parse(s: &str) -> Result<Vec<(String, String)>, String> {
    importenv::parse_env_file("in.env", s.as_bytes())
        .map(|m| m.into_iter().collect::<Vec<_>>())
}

#[test]
fn it_reads_plain_pairs() {
    assert_eq!(parse("A=1\nB=2\n").unwrap(), vec![("A".into(), "1".into()), ("B".into(), "2".into())]);
}

#[test]
fn comments_and_blank_lines_are_skipped() {
    assert_eq!(parse("# note\n\n   \n   # indented note\nA=1\n").unwrap(), vec![("A".into(), "1".into())]);
}

#[test]
fn the_export_prefix_is_stripped_but_only_with_its_space() {
    assert_eq!(parse("export A=1\n").unwrap(), vec![("A".into(), "1".into())]);
    // "exportA" bir ONEK DEGIL — anahtar adinin kendisi.
    assert_eq!(parse("exportA=1\n").unwrap(), vec![("exportA".into(), "1".into())]);
}

#[test]
fn surrounding_whitespace_is_trimmed_from_both_sides() {
    assert_eq!(parse("  A  =  1  \n").unwrap(), vec![("A".into(), "1".into())]);
}

#[test]
fn a_matching_quote_pair_is_stripped() {
    assert_eq!(parse("A=\"a b\"\n").unwrap(), vec![("A".into(), "a b".into())]);
    assert_eq!(parse("A='a b'\n").unwrap(), vec![("A".into(), "a b".into())]);
    // Es olmayan tirnaklar AYNEN kalir.
    assert_eq!(parse("A=\"a b'\n").unwrap(), vec![("A".into(), "\"a b'".into())]);
    // Tek karakter kisaltilmaz (Go: len < 2 -> as-is).
    assert_eq!(parse("A=\"\n").unwrap(), vec![("A".into(), "\"".into())]);
    // Bos tirnak cifti bos degere coker.
    assert_eq!(parse("A=\"\"\n").unwrap(), vec![("A".into(), "".into())]);
}

#[test]
fn an_empty_value_is_kept_not_rejected() {
    // `set`in aksine: import-env bos degeri REDDETMIYOR.
    assert_eq!(parse("A=\n").unwrap(), vec![("A".into(), "".into())]);
}

#[test]
fn a_later_line_wins_over_an_earlier_one() {
    assert_eq!(parse("A=first\nA=second\n").unwrap(), vec![("A".into(), "second".into())]);
}

#[test]
fn a_line_without_a_delimiter_reports_its_length_but_never_its_text() {
    // BU TESTIN ASIL KONUSU: `.env`e yanlislikla CIPLAK bir jeton yapistiran
    // birinde SATIRIN TAMAMI o jetondur. Hata mesaji satiri YANKILAMAMALI;
    // yalnizca uzunluk tasiniyor ki operator satiri bulabilsin ve deger
    // terminale/CI loguna/ajan transcript'ine DUSMESIN.
    let secretish = "aaaaaaaaaaaaaaaaaaaaaaaa"; // 24 karakter, uydurma
    let err = parse(&format!("A=1\n{secretish}\n")).unwrap_err();
    assert_eq!(err, "source[file (in.env)]: line 2: no '=' delimiter (line length 24)");
    assert!(!err.contains(secretish), "hata mesaji satirin ICERIGINI tasimamali: {err}");
}

#[test]
fn a_leading_equals_sign_is_a_delimiter_error_too() {
    // Go: idx <= 0, yani idx==0 da hata (bos anahtar adi kabul edilmiyor).
    assert_eq!(
        parse("=novalue\n").unwrap_err(),
        "source[file (in.env)]: line 1: no '=' delimiter (line length 8)"
    );
}

#[test]
fn a_value_may_contain_further_equals_signs() {
    assert_eq!(parse("A=b=c=d\n").unwrap(), vec![("A".into(), "b=c=d".into())]);
}

#[test]
fn a_trailing_carriage_return_is_dropped_like_bufio_scanlines() {
    assert_eq!(parse("A=1\r\nB=2\r\n").unwrap(), vec![("A".into(), "1".into()), ("B".into(), "2".into())]);
}

// --- rapor satirlari --------------------------------------------------------

#[test]
fn the_success_line_names_count_file_and_project_but_no_value() {
    let line = importenv::success_line(3, "in.env", "testproj");
    assert_eq!(line, "✓ Imported 3 keys from in.env into testproj\n");
}

#[test]
fn the_override_warning_uses_gos_slice_formatting() {
    // Go: fmt.Fprintf(..., "⚠ overwrote existing keys: %v\n", overridden)
    // ve []string{"A","B"} -> "[A B]" (virgul YOK).
    assert_eq!(
        importenv::override_line(&["A".to_string(), "B".to_string()]),
        "⚠ overwrote existing keys: [A B]\n"
    );
    assert_eq!(importenv::override_line(&["A".to_string()]), "⚠ overwrote existing keys: [A]\n");
}

// --- GET /keys hatasinin SINIFLANDIRILMASI ----------------------------------
//
// `import-env` GET /keys'i yalnizca bir KOLAYLIK icin cagiriyor: hangi adlarin
// UZERINE yazilacagini onceden soylemek. Hatasi bu yuzden yutuluyordu.
//
// Ama epoch pin kontrolu (check_and_advance_epoch_pin) bir rollback saldirisini
// durduran TEK kontrol ve YALNIZCA keys + read icinden cagriliyor — import onu
// HIC cagirmiyor. Yani bu cagri, `import-env`in epoch pin'ini gordugu TEK yer,
// ve hatasi tumuyle yutuldugunda EPOCH_DOWNGRADE de yutuluyordu: geri sarilmis
// bir store'a karsi `list` ve `env` REDDEDERKEN, toplu YAZAN fiil sessizce
// yazip 0 ile cikiyordu.
//
// Bu testler bir KARSILASTIRMA degil bir IDDIA: kusur IKI ikilide de canliydi,
// yani pty differential'in kor oldugu sinifta. Go karsiligi
// TestRunImportEnv_RefusesAnEpochDowngradeAndWritesNothing.
use wapps::clierr::{Code, Error};

#[test]
fn an_epoch_downgrade_from_the_keys_call_is_a_gate_not_a_convenience() {
    let e = Error::new(
        Code::EpochDowngrade,
        "served epoch 7 < pinned 9 for \"testproj\"",
    );
    let got = importenv::existing_names(Err(e));
    let err = got.expect_err("EPOCH_DOWNGRADE YUTULAMAZ — rollback kapisi");
    assert_eq!(err.code, Code::EpochDowngrade);
}

#[test]
fn any_other_keys_error_is_still_swallowed() {
    // Yutmanin ilk yazilma sebebi korunuyor: keys baska bir sebeple patlarsa
    // `import-env` kullanilamaz OLMAMALI. Ayrim DAR.
    for code in [Code::Internal, Code::RateLimited, Code::NotFound] {
        let names = importenv::existing_names(Err(Error::new(code, "bad day")))
            .unwrap_or_else(|e| panic!("{code:?} yutulmaliydi, geldi: {e}"));
        assert!(names.is_empty(), "yutulan bir hata BOS ad kumesi vermeli");
    }
}

#[test]
fn a_successful_keys_call_yields_the_name_set() {
    let names = importenv::existing_names(Ok(vec!["BETA".into(), "ALPHA".into()])).unwrap();
    assert_eq!(
        names.iter().cloned().collect::<Vec<_>>(),
        vec!["ALPHA", "BETA"]
    );
}
