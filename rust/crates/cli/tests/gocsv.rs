// gocsv: pflag's `readAsCSV` — the first record of Go's `encoding/csv` reader
// with the default settings — which every cobra `StringSliceVar` value goes
// through (`coolify update-env --env`, `coolify set-labels --label`).
//
// Every vector below was produced by Go 1.26 (`csv.NewReader(...).Read()`
// behind pflag's empty-string shortcut), not written from memory. The points
// a hand parser gets wrong: only the FIRST record is read (the rest of the
// value is dropped), empty lines before it are skipped, an input of only
// line breaks is `EOF`, a trailing `\r` is dropped but an inner one is kept,
// `\r\n` inside a quoted field becomes `\n`, and the error column is a
// 1-based BYTE offset whose line comes from two different counters.
use wapps::gocsv::read_as_csv;

type Want = Result<&'static [&'static str], &'static str>;

const VECTORS: &[(&str, Want)] = &[
    ("", Ok(&[])),
    ("a", Ok(&["a"])),
    ("a,b", Ok(&["a", "b"])),
    ("a,,b", Ok(&["a", "", "b"])),
    (",", Ok(&["", ""])),
    ("a,", Ok(&["a", ""])),
    (",a", Ok(&["", "a"])),
    ("\n", Err("EOF")),
    ("\r", Err("EOF")),
    ("\r\n", Err("EOF")),
    ("\n\n", Err("EOF")),
    ("\na", Ok(&["a"])),
    ("a\nb", Ok(&["a"])),
    ("a\r\nb", Ok(&["a"])),
    ("a\rb", Ok(&["a\rb"])),
    ("a\r", Ok(&["a"])),
    ("\"a,b\"", Ok(&["a,b"])),
    ("\"a\"\"b\"", Ok(&["a\"b"])),
    ("\"a\"b", Err("parse error on line 1, column 3: extraneous or missing \" in quoted-field")),
    ("a\"b", Err("parse error on line 1, column 2: bare \" in non-quoted-field")),
    ("\"", Err("parse error on line 1, column 2: extraneous or missing \" in quoted-field")),
    ("\"a", Err("parse error on line 1, column 3: extraneous or missing \" in quoted-field")),
    ("\"a\n", Err("parse error on line 1, column 4: extraneous or missing \" in quoted-field")),
    ("\"a\nb", Err("record on line 1; parse error on line 2, column 2: extraneous or missing \" in quoted-field")),
    ("\"a\nb\"", Ok(&["a\nb"])),
    ("\"a\r\nb\"", Ok(&["a\nb"])),
    ("\"a\nb\"c", Err("record on line 1; parse error on line 2, column 2: extraneous or missing \" in quoted-field")),
    ("\"a\n\nb\"x", Err("record on line 1; parse error on line 3, column 2: extraneous or missing \" in quoted-field")),
    ("x,\"y\nz\"q", Err("record on line 1; parse error on line 2, column 2: extraneous or missing \" in quoted-field")),
    ("é\"", Err("parse error on line 1, column 3: bare \" in non-quoted-field")),
    ("\"é\"x", Err("parse error on line 1, column 4: extraneous or missing \" in quoted-field")),
    (" a , b ", Ok(&[" a ", " b "])),
    ("\"\"", Ok(&[""])),
    ("\"\",\"\"", Ok(&["", ""])),
    ("a,\"b\",c", Ok(&["a", "b", "c"])),
    ("\"a\"\n", Ok(&["a"])),
    ("\"a\"\r\n", Ok(&["a"])),
    ("\"a\"\r", Ok(&["a"])),
    ("\n\n\"a\"\"", Err("parse error on line 3, column 5: extraneous or missing \" in quoted-field")),
    ("k=v,\"x=1,2\"", Ok(&["k=v", "x=1,2"])),
    ("a\n\"b", Ok(&["a"])),
];

#[test]
fn read_as_csv_matches_go_on_every_measured_vector() {
    for (input, want) in VECTORS {
        let got = read_as_csv(input);
        match want {
            Ok(fields) => {
                let fields: Vec<String> = fields.iter().map(|s| s.to_string()).collect();
                assert_eq!(got.as_ref(), Ok(&fields), "input {input:?}");
            }
            Err(text) => assert_eq!(got, Err(text.to_string()), "input {input:?}"),
        }
    }
}
