// yaml is the one YAML ingress of this binary: `.wapps.yaml`, projects.yaml
// and the broker's client.yaml all parse through `from_slice`.
//
// ORACLE: Go's gopkg.in/yaml.v3 (internal/config, internal/projects). The
// parser is serde-saphyr (safe Rust, see Cargo.toml for the measurement).
// Its scalar rules differ from yaml.v3 in two places that a config file can
// reach; the field helpers below restore the yaml.v3 behavior, and
// tests/yaml_ingress.rs pins every case.
//
//   * A YAML null (`key:`, `~`, `null`) into a string: yaml.v3 leaves the
//     string empty, serde-saphyr refuses it. `string` maps null to "".
//   * A QUOTED scalar into an integer or a boolean: yaml.v3 refuses
//     `version: "2"` and `delete_unmanaged: "true"`, serde-saphyr parses the
//     text. `int` and `boolean` accept only a resolved (unquoted or
//     explicitly tagged) integer or boolean.
use serde::de::{self, Deserialize, DeserializeOwned, Deserializer, Unexpected, Visitor};
use std::fmt;

/// from_slice parses one YAML document into `T`.
///
/// `with_snippet: false` keeps the error on one line. The default wrapper
/// renders an excerpt of the input under the message; that would echo file
/// content into the operator's terminal and into agent transcripts.
pub fn from_slice<T: DeserializeOwned>(data: &[u8]) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_slice_with_options(data, serde_saphyr::options! { with_snippet: false })
}

/// string is a `deserialize_with` for a `String` field: YAML null becomes "".
pub fn string<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Option::<String>::deserialize(d).map(Option::unwrap_or_default)
}

/// int is a `deserialize_with` for an `i64` field that refuses quoted text.
pub fn int<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    struct Int;
    impl Visitor<'_> for Int {
        type Value = i64;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("an i64 integer")
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<i64, E> {
            Ok(v)
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<i64, E> {
            i64::try_from(v).map_err(|_| E::invalid_value(Unexpected::Unsigned(v), &self))
        }
    }
    d.deserialize_any(Int)
}

/// boolean is a `deserialize_with` for a `bool` field that refuses quoted
/// text. Unquoted YAML 1.1 forms (`yes`, `on`, `off`) are booleans, as in
/// yaml.v3.
pub fn boolean<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    struct Bool;
    impl Visitor<'_> for Bool {
        type Value = bool;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a boolean")
        }
        fn visit_bool<E: de::Error>(self, v: bool) -> Result<bool, E> {
            Ok(v)
        }
    }
    d.deserialize_any(Bool)
}
