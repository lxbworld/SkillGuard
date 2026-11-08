//! YAML parsing for untrusted input.
//!
//! Every YAML document this crate reads is hostile: a skill's frontmatter is
//! authored by whoever wrote the skill, and `SKILLGUARD.policy.yaml` is read
//! before a decision that can block an install. Parsing therefore goes through
//! one place with one configuration, so the trust boundary cannot drift.
//!
//! # Why `serde-saphyr`
//!
//! The previous parser, `serde_yaml`, is deprecated upstream and pulls in
//! `unsafe-libyaml`, which is unmaintained (RUSTSEC-2024-0449). Forks inherit
//! the same C parser, so the advisory's fix is a safe-Rust parser. The parser
//! used here is fuzz-tested, built with `unsafe` denied, and — unlike the old
//! one — accepts an explicit resource budget, which matters most for exactly
//! the input this tool handles.
//!
//! # Deliberate settings
//!
//! * `strict_booleans`: YAML 1.1 treats `on`, `off`, `yes` and `no` as
//!   booleans. A shell command or host named `on` is not a boolean, and the
//!   declaration reader must see the text the author wrote.
//! * A small budget: no multi-document streams, bounded nesting, bounded
//!   anchors and merge keys, and a bounded event count. A 4 MiB frontmatter
//!   that tries to be a parser bomb fails as a parse error instead of becoming
//!   a denial of service.
//! * Duplicate mapping keys are rejected (the crate's default). A skill that
//!   declares `network.outbound` twice is ambiguous, and a policy that sets the
//!   same key twice must fail loudly rather than silently keep one.

use serde::de::DeserializeOwned;

/// Parse a single YAML document into a generic JSON value.
///
/// The scanner walks this value to recover declared permissions. JSON's value
/// model is used because it is already a dependency and because YAML mappings
/// in frontmatter are string-keyed in practice; a non-string key is a parse
/// error rather than a silently invented one.
pub fn parse_value(src: &str) -> Result<serde_json::Value, String> {
    from_str(src)
}

/// Parse a single YAML document into a typed value.
pub fn from_str<T: DeserializeOwned>(src: &str) -> Result<T, String> {
    serde_saphyr::from_str_with_options(src, options()).map_err(|e| e.to_string())
}

/// One parser configuration for the whole crate.
fn options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        strict_booleans: true,
        budget: serde_saphyr::budget! {
            max_documents: 1,
            max_depth: 32,
            max_nodes: 100_000,
            max_events: 500_000,
            max_aliases: 1_000,
            max_anchors: 1_000,
            max_merge_keys: 1_000,
            max_total_scalar_bytes: 4 * 1024 * 1024,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_mapping_and_a_block_scalar() {
        let v =
            parse_value("name: x\ndescription: |\n  line one\n  line two\n").expect("valid YAML");
        assert_eq!(v["name"], "x");
        assert!(v["description"]
            .as_str()
            .is_some_and(|s| s.contains("line one\nline two")));
    }

    #[test]
    fn yaml_11_boolean_words_stay_text() {
        // `on`/`off` are hostnames and commands in the wild, not booleans.
        let v = parse_value("hosts: [on, off, yes, no]").expect("valid YAML");
        assert_eq!(v["hosts"][0], "on");
        assert_eq!(v["hosts"][1], "off");
        assert_eq!(v["hosts"][2], "yes");
        assert_eq!(v["hosts"][3], "no");
    }

    #[test]
    fn null_spellings_are_null() {
        let v = parse_value("a: ~\nb: null\nc: Null\n").expect("valid YAML");
        assert!(v["a"].is_null());
        assert!(v["b"].is_null());
        assert!(v["c"].is_null());
    }

    #[test]
    fn anchors_and_merge_keys_work() {
        let v = parse_value("base: &b {x: 1}\nchild:\n  <<: *b\n  y: 2\n").expect("valid YAML");
        assert_eq!(v["child"]["x"], 1);
        assert_eq!(v["child"]["y"], 2);
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        assert!(parse_value("a: 1\na: 2\n").is_err(), "ambiguous must fail");
    }

    #[test]
    fn a_parser_bomb_is_an_error_not_a_hang() {
        // Deep nesting beyond the configured depth must be refused.
        let mut deep = String::new();
        for _ in 0..200 {
            deep.push('[');
        }
        assert!(parse_value(&deep).is_err());
    }

    #[test]
    fn malformed_input_never_panics() {
        for bad in [
            "permissions: [unclosed",
            "\t- : :",
            "a: *missing\n",
            "%YAML 1.3\n---",
        ] {
            let _ = parse_value(bad);
        }
    }

    #[test]
    fn typed_deserialisation_rejects_unknown_fields() {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct P {
            #[serde(default)]
            a: bool,
        }
        assert!(from_str::<P>("a: true\n").is_ok_and(|p| p.a));
        assert!(from_str::<P>("typo: true\n").is_err());
    }
}
