// gocsv, pflag's `readAsCSV`: how a cobra `StringSliceVar` reads ONE value.
//
// pflag hands the value to Go's `encoding/csv` with the default settings and
// keeps only the FIRST record (`csv.NewReader(s).Read()`), with one shortcut:
// an empty value is an empty list. So `--env A=1,B=2` is two entries, a quoted
// field keeps its comma, a stray quote is a parse error whose text reaches the
// user, and everything after the first record's line break is dropped.
//
// Ported from Go 1.26 `encoding/csv/reader.go` (`readLine`, `readRecord`) for
// the default reader only: Comma ',', no Comment, LazyQuotes and
// TrimLeadingSpace off, FieldsPerRecord irrelevant to the first record. The
// vectors in tests/gocsv.rs were produced by Go, not written from memory.
//
// No crate: the `csv` crate's quoting and error texts are its own, and the
// texts are what a user sees.

/// read_as_csv, the fields of the first record, or Go's error text ("EOF" or
/// a `*csv.ParseError` sentence).
pub fn read_as_csv(val: &str) -> Result<Vec<String>, String> {
    if val.is_empty() {
        return Ok(Vec::new());
    }
    Reader {
        rest: val.as_bytes(),
        num_line: 0,
    }
    .read_record()
}

struct Reader<'a> {
    rest: &'a [u8],
    num_line: usize,
}

// One `readLine` result: the line and whether it was the EOF read (an EOF read
// is always empty — a last line without '\n' comes back without an error).
struct Line {
    bytes: Vec<u8>,
    eof: bool,
}

const ERR_BARE_QUOTE: &str = "bare \" in non-quoted-field";
const ERR_QUOTE: &str = "extraneous or missing \" in quoted-field";

fn parse_error(start_line: usize, line: usize, column: usize, err: &str) -> String {
    if start_line != line {
        format!("record on line {start_line}; parse error on line {line}, column {column}: {err}")
    } else {
        format!("parse error on line {line}, column {column}: {err}")
    }
}

fn length_nl(b: &[u8]) -> usize {
    usize::from(b.last() == Some(&b'\n'))
}

impl Reader<'_> {
    fn read_line(&mut self) -> Line {
        let (mut line, eof) = match self.rest.iter().position(|&b| b == b'\n') {
            Some(i) => {
                let l = self.rest[..=i].to_vec();
                self.rest = &self.rest[i + 1..];
                (l, false)
            }
            None => {
                let l = self.rest.to_vec();
                self.rest = &[];
                // A last line without '\n' is not an error; only an empty
                // read is EOF. Its trailing '\r' is dropped.
                let eof = l.is_empty();
                let mut l = l;
                if l.last() == Some(&b'\r') {
                    l.pop();
                }
                (l, eof)
            }
        };
        self.num_line += 1;
        let n = line.len();
        if n >= 2 && line[n - 2] == b'\r' && line[n - 1] == b'\n' {
            line[n - 2] = b'\n';
            line.pop();
        }
        Line { bytes: line, eof }
    }

    fn read_record(&mut self) -> Result<Vec<String>, String> {
        // Skip empty lines; an input of nothing else is EOF.
        let first = loop {
            let l = self.read_line();
            if !l.eof && l.bytes.len() == length_nl(&l.bytes) {
                continue;
            }
            break l;
        };
        if first.eof {
            return Err("EOF".to_string());
        }

        let rec_line = self.num_line;
        let mut record: Vec<u8> = Vec::new();
        let mut field_ends: Vec<usize> = Vec::new();
        let mut pos_line = self.num_line;
        let mut pos_col = 1usize;
        // The line being parsed is `buf[off..]` (Go reslices `line`).
        let mut buf = first.bytes;
        let mut off = 0usize;

        'field: loop {
            if buf.get(off) != Some(&b'"') {
                // Unquoted field.
                let line = &buf[off..];
                let comma = line.iter().position(|&b| b == b',');
                let field = match comma {
                    Some(i) => &line[..i],
                    None => &line[..line.len() - length_nl(line)],
                };
                if let Some(j) = field.iter().position(|&b| b == b'"') {
                    return Err(parse_error(
                        rec_line,
                        self.num_line,
                        pos_col + j,
                        ERR_BARE_QUOTE,
                    ));
                }
                record.extend_from_slice(field);
                field_ends.push(record.len());
                match comma {
                    Some(i) => {
                        off += i + 1;
                        pos_col += i + 1;
                        continue 'field;
                    }
                    None => break 'field,
                }
            }
            // Quoted field.
            off += 1;
            pos_col += 1;
            loop {
                let line = &buf[off..];
                if let Some(i) = line.iter().position(|&b| b == b'"') {
                    record.extend_from_slice(&line[..i]);
                    off += i + 1;
                    pos_col += i + 1;
                    let line = &buf[off..];
                    match line.first() {
                        Some(b'"') => {
                            record.push(b'"');
                            off += 1;
                            pos_col += 1;
                        }
                        Some(b',') => {
                            off += 1;
                            pos_col += 1;
                            field_ends.push(record.len());
                            continue 'field;
                        }
                        _ if length_nl(line) == line.len() => {
                            field_ends.push(record.len());
                            break 'field;
                        }
                        _ => {
                            return Err(parse_error(
                                rec_line,
                                self.num_line,
                                pos_col - 1,
                                ERR_QUOTE,
                            ));
                        }
                    }
                } else if !line.is_empty() {
                    // The field continues on the next line.
                    record.extend_from_slice(line);
                    pos_col += line.len();
                    let next = self.read_line();
                    if !next.bytes.is_empty() {
                        pos_line += 1;
                        pos_col = 1;
                    }
                    buf = next.bytes;
                    off = 0;
                } else {
                    // Input ended inside the quotes.
                    return Err(parse_error(rec_line, pos_line, pos_col, ERR_QUOTE));
                }
            }
        }

        // Every split is at an ASCII byte, so the fields stay valid UTF-8.
        let mut fields = Vec::with_capacity(field_ends.len());
        let mut start = 0usize;
        for end in field_ends {
            fields.push(String::from_utf8_lossy(&record[start..end]).into_owned());
            start = end;
        }
        Ok(fields)
    }
}
