// Go'nun `strconv.ParseInt(s, 0, 64)` semantigi.
//
// NEDEN VAR: `token exchange --ttl` cobra'da bir `IntVar`, yani deger
// AYRISTIRICIDA cozuluyor ve bozuk bir deger RunE'ye HIC girmeden Go'nun
// KENDI prozasiyla reddediliyor. Bayt bayt eslesme istiyorsak o prozayi da,
// onu ureten KABUL KUMESINI de tasimak gerekiyor.
//
// TABLONUN TAMAMI Go'dan OLCULDU (`strconv.ParseInt(s, 0, 64)` dogrudan
// cagrilarak), hatirlanmadi. Sasirtan noktalar:
//   - TABAN 0: `0x10`, `0o17`, `0b101`, `010` GECERLI;
//   - `0x` (uzunluk 2) GECERSIZ — onek dali `len(s) >= 3` istiyor, yani
//     "0" + "x" olarak okunup sekizlik bir 'x' araniyor;
//   - ALT CIZGI yalnizca basamaklarin ARASINDA gecerli, ve `0_10` = 8;
//   - aralik disi bir deger SOZDIZIMI hatasi DEGIL, AYRI bir hata.
use wapps::gostrconv::{parse_int_base0, ParseIntError};

fn ok(s: &str) -> i64 {
    parse_int_base0(s).unwrap_or_else(|e| panic!("{s:?} kabul edilmeliydi: {e:?}"))
}

#[test]
fn decimal_hex_octal_and_binary_prefixes_all_parse_at_base_zero() {
    assert_eq!(ok("300"), 300);
    assert_eq!(ok("0"), 0);
    assert_eq!(ok("00"), 0);
    assert_eq!(ok("0x10"), 16);
    assert_eq!(ok("0X1F"), 31);
    assert_eq!(ok("010"), 8);
    assert_eq!(ok("0o17"), 15);
    assert_eq!(ok("0b101"), 5);
}

#[test]
fn signs_are_accepted_on_either_side_of_zero() {
    assert_eq!(ok("+5"), 5);
    assert_eq!(ok("-5"), -5);
    assert_eq!(ok("-9223372036854775808"), i64::MIN);
    assert_eq!(ok("9223372036854775807"), i64::MAX);
}

#[test]
fn underscores_are_separators_only_between_digits() {
    assert_eq!(ok("1_0"), 10);
    assert_eq!(ok("0x_10"), 16);
    assert_eq!(ok("0_10"), 8);
    for bad in ["_1", "1_", "1__0"] {
        assert!(
            matches!(parse_int_base0(bad), Err(ParseIntError::Syntax)),
            "{bad:?}"
        );
    }
}

#[test]
fn go_rejects_what_looks_parseable_to_a_relaxed_reader() {
    // Bosluk, ondalik nokta, ASCII disi basamak, yalniz isaret, yarim onek,
    // ve tabanina uymayan basamak: HEPSI sozdizimi hatasi.
    for bad in [
        "abc", "", " ", " 5", "5 ", "5.0", "+", "-", "0x", "08", "\u{ff10}",
    ] {
        assert!(
            matches!(parse_int_base0(bad), Err(ParseIntError::Syntax)),
            "{bad:?}"
        );
    }
}

#[test]
fn out_of_range_is_a_distinct_error_from_bad_syntax() {
    assert!(matches!(
        parse_int_base0("99999999999999999999"),
        Err(ParseIntError::Range)
    ));
    assert!(matches!(
        parse_int_base0("9223372036854775808"),
        Err(ParseIntError::Range)
    ));
    assert!(matches!(
        parse_int_base0("-9223372036854775809"),
        Err(ParseIntError::Range)
    ));
}

// Go ikilisinden OLCULEN tam metinler. cobra hatayi
// `invalid argument %q for %q flag: %v` ile sariyor; sarmalayan taraf
// cagirana ait, ama `%v` bu dosyanin urettigi dize.
#[test]
fn the_error_text_is_gos_numerror_prose() {
    assert_eq!(
        parse_int_base0("abc").unwrap_err().go_text("abc"),
        "strconv.ParseInt: parsing \"abc\": invalid syntax"
    );
    assert_eq!(
        parse_int_base0("99999999999999999999")
            .unwrap_err()
            .go_text("99999999999999999999"),
        "strconv.ParseInt: parsing \"99999999999999999999\": value out of range"
    );
}

// --- ParseBool, Quote, QuoteRune ----------------------------------------------
//
// `coolify set-labels --strip-cert-resolver` is a pflag `BoolVar`: the value is
// parsed by `strconv.ParseBool` and a bad one is refused with its prose. The
// `coolify` errors quote user input with `%q` (`strconv.Quote`/`QuoteRune`).
// Every vector was produced by Go 1.26.
use wapps::gostrconv::{parse_bool, quote, quote_rune};

#[test]
fn parse_bool_accepts_exactly_go_s_twelve_spellings() {
    for s in ["1", "t", "T", "TRUE", "true", "True"] {
        assert_eq!(parse_bool(s), Ok(true), "{s:?}");
    }
    for s in ["0", "f", "F", "FALSE", "false", "False"] {
        assert_eq!(parse_bool(s), Ok(false), "{s:?}");
    }
    for s in ["", "yes", "tRUE", " true"] {
        assert_eq!(
            parse_bool(s),
            Err(format!(
                "strconv.ParseBool: parsing {}: invalid syntax",
                quote(s)
            )),
            "{s:?}"
        );
    }
}

#[test]
fn quote_matches_go_percent_q() {
    let vectors = [
        ("\x00", r#""\x00""#),
        ("\x01", r#""\x01""#),
        ("\x07\x08\x0c\x0b", r#""\a\b\f\v""#),
        ("\x7f", r#""\x7f""#),
        ("a\"b\\c", r#""a\"b\\c""#),
        ("é", "\"é\""),
        ("\u{200b}", r#""\u200b""#),
        ("\u{a0}", r#""\u00a0""#),
        ("'", r#""'""#),
        ("\t\n\r", r#""\t\n\r""#),
    ];
    for (input, want) in vectors {
        assert_eq!(quote(input), want, "input {input:?}");
    }
}

#[test]
fn quote_rune_matches_go_percent_q() {
    let vectors = [
        ('.', "'.'"),
        ('é', "'é'"),
        ('\'', r"'\''"),
        ('"', "'\"'"),
        ('\x00', r"'\x00'"),
        ('\t', r"'\t'"),
        ('\x7f', r"'\x7f'"),
        ('\u{200b}', r"'\u200b'"),
        ('\\', r"'\\'"),
        ('\u{a0}', r"'\u00a0'"),
    ];
    for (input, want) in vectors {
        assert_eq!(quote_rune(input), want, "input {input:?}");
    }
}
