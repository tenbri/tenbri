//! Tenbri action schemas from `tenbri.toml`, validated at write time.
//!
//! An action schema says what an entry for one action type must carry: the inputs it read, a
//! rule, an approval, a durability tier, a target pattern, and any other member by its dotted path
//! (`rule.result`, `ext.refund.amount`) with a type and allowed values. tenbrid checks every append
//! against them and `tenbri schema check` checks `tenbri.toml` and existing streams.
//!
//! ```toml
//! # An action type no [actions.*] table declares: "reject" (the default) or "warn".
//! unknown_actions = "reject"
//!
//! [actions.issue_refund]
//! inputs = ["policy:refund"]        # refs the entry's inputs must include
//! rule = true                       # a rule is required
//! approval = true                   # an approval is required
//! durability = "replicated"         # the tier the entry must carry
//! target = "stripe:charge/*"        # `*` matches any run of characters
//! policy = "policy:refund@14"       # a rule is required, with this ref and version
//!
//! [actions.issue_refund.fields."rule.result"]
//! allowed = ["allow"]
//!
//! [actions.issue_refund.fields."ext.refund.amount"]
//! required = true
//! type = "integer"
//! ```
//!
//! The requirements apply to intents, which state the decision before the action runs. Every
//! other entry naming an action (outcomes, approvals, notes, ingested decisions) is checked for a
//! declared action type only.
//!
//! A `target` may name the action's arguments in braces, `stripe:{charge}`: each placeholder matches
//! like `*`, and the SDKs' framework instrumentation fills it from the tool call's arguments, with
//! `policy` as the intent's `rule`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tenbri_core::{Durability, Entry, Phase};

/// The action schemas of one `tenbri.toml`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schemas {
    #[serde(default)]
    pub unknown_actions: Unknown,
    #[serde(default)]
    pub actions: BTreeMap<String, ActionSchema>,
}

/// What to do with an action type no schema declares.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unknown {
    #[default]
    Reject,
    Warn,
}

/// What an entry for one action type must carry.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSchema {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Refs the entry's `inputs` must include (any version).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<String>,
    /// A `rule` is required.
    #[serde(default, skip_serializing_if = "is_false")]
    pub rule: bool,
    /// An `approval` is required.
    #[serde(default, skip_serializing_if = "is_false")]
    pub approval: bool,
    /// The entry's `durability` must be this tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durability: Option<Durability>,
    /// `action.target` must be present and match; `*` and `{argument}` match any run of
    /// characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// `ref@version`: a `rule` is required, with this `ref` and `version`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Any member by its dotted path into the entry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Field>,
}

/// A rule for one member of the entry.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<Type>,
    /// The value must be one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<Value>,
    /// A string value must match; `*` matches any run of characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Type {
    String,
    Integer,
    Boolean,
    Object,
    Array,
}

fn is_false(b: &bool) -> bool {
    !b
}

/// A requirement an entry does not meet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    /// The member, as a dotted path (`action.type`, `rule.result`).
    pub path: String,
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// The result of [`Schemas::check`]: an entry with violations is refused; warnings are reported
/// and the entry is written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Checked {
    pub violations: Vec<Violation>,
    pub warnings: Vec<String>,
}

impl Schemas {
    /// Parses and checks a `tenbri.toml`: unknown keys, paths outside the entry, values that
    /// contradict their own type all fail here, so typos fail in CI rather than in an audit.
    pub fn parse(text: &str) -> Result<Schemas, String> {
        let s: Schemas = toml::from_str(text).map_err(|e| e.to_string())?;
        for (name, a) in &s.actions {
            let at = |m: String| format!("actions.{name}: {m}");
            if name.is_empty() {
                return Err("an action type cannot be empty".into());
            }
            if a.policy.as_deref().is_some_and(|p| policy(p).is_none()) {
                return Err(at("policy: expected ref@version".into()));
            }
            for (path, f) in &a.fields {
                let first = path.split('.').next().unwrap_or_default();
                if path.split('.').any(str::is_empty) || !tenbri_core::FIELDS.contains(&first) {
                    return Err(at(format!(
                        "fields.\"{path}\": not a member of a format v1 entry"
                    )));
                }
                if let Some(v) = f.allowed.iter().find(|v| f.kind.is_some_and(|t| !t.is(v))) {
                    return Err(at(format!(
                        "fields.\"{path}\": allowed value {v} is not of its type"
                    )));
                }
                if f.pattern.is_some() && f.kind.is_some_and(|t| t != Type::String) {
                    return Err(at(format!(
                        "fields.\"{path}\": a pattern needs type \"string\""
                    )));
                }
            }
        }
        Ok(s)
    }

    pub fn load(path: &Path) -> Result<Schemas, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Schemas::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Checks one entry (or draft) against the schema of its action type.
    pub fn check(&self, e: &Entry) -> Checked {
        let mut out = Checked::default();
        let Some(action) = &e.action else {
            return out;
        };
        let Some(a) = self.actions.get(&action.r#type) else {
            let msg = format!("`{}` is not declared in tenbri.toml", action.r#type);
            match self.unknown_actions {
                Unknown::Reject => out.violations.push(Violation {
                    path: "action.type".into(),
                    message: msg,
                }),
                Unknown::Warn => out.warnings.push(msg),
            }
            return out;
        };
        if e.phase != Some(Phase::Intent) {
            return out;
        }
        let mut bad = |path: &str, message: String| {
            out.violations.push(Violation {
                path: path.into(),
                message,
            })
        };
        for r in &a.inputs {
            if !e.inputs.iter().flatten().any(|i| &i.r#ref == r) {
                bad("inputs", format!("an input with ref `{r}` is required"));
            }
        }
        let v = serde_json::to_value(e).expect("an entry serializes");
        for (path, f) in a.rules() {
            let Some(got) = path.split('.').try_fold(&v, |v, k| v.get(k)) else {
                if f.required {
                    bad(&path, "required".into());
                }
                continue;
            };
            if let Some(t) = f.kind.filter(|t| !t.is(got)) {
                bad(&path, format!("expected {}", t.name()));
            } else if !f.allowed.is_empty() && !f.allowed.contains(got) {
                bad(&path, format!("{got} is not one of {}", list(&f.allowed)));
            } else if let Some(p) = &f.pattern {
                if !got.as_str().is_some_and(|s| glob(p, s)) {
                    bad(&path, format!("{got} does not match `{p}`"));
                }
            }
        }
        out
    }
}

impl ActionSchema {
    /// The shorthands (`rule`, `approval`, `durability`, `target`) as field rules, then `fields`.
    fn rules(&self) -> Vec<(String, Field)> {
        let required = || Field {
            required: true,
            ..Field::default()
        };
        let mut out = vec![];
        if self.rule {
            out.push(("rule".into(), required()));
        }
        if self.approval {
            out.push(("approval".into(), required()));
        }
        if let Some(d) = self.durability {
            let tier = serde_json::to_value(d).expect("a tier serializes");
            out.push((
                "durability".into(),
                Field {
                    allowed: vec![tier],
                    ..required()
                },
            ));
        }
        if let Some(t) = &self.target {
            out.push((
                "action.target".into(),
                Field {
                    pattern: Some(placeholders_as_globs(t)),
                    ..required()
                },
            ));
        }
        if let Some((r, v)) = self.policy.as_deref().and_then(policy) {
            for (path, value) in [("rule.ref", r), ("rule.version", v)] {
                out.push((
                    path.into(),
                    Field {
                        allowed: vec![Value::from(value)],
                        ..required()
                    },
                ));
            }
        }
        out.extend(self.fields.iter().map(|(k, f)| (k.clone(), f.clone())));
        out
    }
}

impl Type {
    fn is(self, v: &Value) -> bool {
        match self {
            Type::String => v.is_string(),
            Type::Integer => v.is_i64() || v.is_u64(),
            Type::Boolean => v.is_boolean(),
            Type::Object => v.is_object(),
            Type::Array => v.is_array(),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Type::String => "a string",
            Type::Integer => "an integer",
            Type::Boolean => "a boolean",
            Type::Object => "an object",
            Type::Array => "an array",
        }
    }
}

/// `ref@version` split at its last `@`, both non-empty.
fn policy(p: &str) -> Option<(&str, &str)> {
    p.rsplit_once('@')
        .filter(|(r, v)| !r.is_empty() && !v.is_empty())
}

/// A target with each `{argument}` placeholder as `*`.
fn placeholders_as_globs(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    let mut rest = t;
    while let Some(i) = rest.find('{') {
        match rest[i..].find('}') {
            Some(j) => {
                out.push_str(&rest[..i]);
                out.push('*');
                rest = &rest[i + j + 1..];
            }
            None => break,
        }
    }
    out.push_str(rest);
    out
}

fn list(vs: &[Value]) -> String {
    vs.iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether `s` matches `pattern`, where `*` matches any run of characters (none included).
pub fn glob(pattern: &str, s: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = s.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty();
    };
    for p in middle {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOML: &str = r#"
        [actions.issue_refund]
        inputs = ["policy:refund"]
        rule = true
        approval = true
        durability = "replicated"
        target = "stripe:charge/*"

        [actions.issue_refund.fields."rule.result"]
        allowed = ["allow"]

        [actions.issue_refund.fields."ext.refund.amount"]
        required = true
        type = "integer"

        [actions.reply_ticket]
    "#;

    fn entry(json: &str) -> Entry {
        let mut v: Value = serde_json::from_str(json).unwrap();
        for (k, d) in [("v", Value::from(1)), ("seq", Value::from(1))] {
            v[k] = d;
        }
        for k in ["id", "stream", "ts", "signer", "sig"] {
            v[k] = Value::from("");
        }
        serde_json::from_value(v).unwrap()
    }

    fn paths(c: &Checked) -> Vec<&str> {
        c.violations.iter().map(|v| v.path.as_str()).collect()
    }

    #[test]
    fn a_complete_refund_passes() {
        let s = Schemas::parse(TOML).unwrap();
        let e = entry(
            r#"{"kind":"decision","phase":"intent","durability":"replicated",
            "action":{"type":"issue_refund","target":"stripe:charge/ch_1"},
            "inputs":[{"ref":"policy:refund","version":"14","digest":"x"}],
            "rule":{"ref":"refund-limit","version":"3","result":"allow"},
            "approval":{"by":{"kind":"person","id":"alice"},"entry":"sha256:00"},
            "ext":{"refund":{"amount":4200}}}"#,
        );
        assert_eq!(s.check(&e), Checked::default());
    }

    #[test]
    fn every_missing_or_wrong_member_is_reported() {
        let s = Schemas::parse(TOML).unwrap();
        let e = entry(
            r#"{"kind":"decision","phase":"intent","durability":"local",
            "action":{"type":"issue_refund","target":"zendesk:ticket/1"},
            "rule":{"ref":"refund-limit","version":"3","result":"deny"},
            "ext":{"refund":{"amount":"4200"}}}"#,
        );
        assert_eq!(
            paths(&s.check(&e)),
            [
                "inputs",
                "approval",
                "durability",
                "action.target",
                "ext.refund.amount",
                "rule.result"
            ]
        );
    }

    #[test]
    fn other_entries_only_need_a_known_action() {
        let s = Schemas::parse(TOML).unwrap();
        let ok = entry(
            r#"{"kind":"decision","phase":"outcome","intent":"01J","status":"ok",
            "action":{"type":"issue_refund"}}"#,
        );
        assert_eq!(s.check(&ok), Checked::default());
        let approval = entry(r#"{"kind":"approval","action":{"type":"issue_refund"}}"#);
        assert_eq!(s.check(&approval), Checked::default());
        let typo =
            entry(r#"{"kind":"decision","phase":"outcome","action":{"type":"isue_refund"}}"#);
        assert_eq!(paths(&s.check(&typo)), ["action.type"]);
    }

    #[test]
    fn unknown_actions_reject_or_warn() {
        let e = entry(r#"{"kind":"decision","phase":"intent","action":{"type":"delete_db"}}"#);
        let reject = Schemas::parse("").unwrap().check(&e);
        assert_eq!(paths(&reject), ["action.type"]);
        let warn = Schemas::parse("unknown_actions = \"warn\"")
            .unwrap()
            .check(&e);
        assert!(warn.violations.is_empty());
        assert_eq!(warn.warnings.len(), 1);
        // Entries without an action (notes, key events) have nothing to check.
        let note = entry(r#"{"kind":"note"}"#);
        assert_eq!(Schemas::parse("").unwrap().check(&note), Checked::default());
    }

    #[test]
    fn bad_schema_files_fail() {
        for bad in [
            "unknown_action = \"warn\"",
            "[actions.x]\ninput = [\"a\"]",
            "[actions.x.fields.\"prams.amount\"]\nrequired = true",
            "[actions.x.fields.\"ext..a\"]\nrequired = true",
            "[actions.x.fields.\"ext.a\"]\ntype = \"integer\"\nallowed = [\"1\"]",
            "[actions.x.fields.\"ext.a\"]\ntype = \"integer\"\npattern = \"a*\"",
            "[actions.x]\ndurability = \"fast\"",
            "[actions.x]\npolicy = \"refund\"",
            "[actions.x]\npolicy = \"refund@\"",
            "unknown_actions = \"ignore\"",
        ] {
            assert!(Schemas::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn placeholder_targets_and_policies() {
        let s = Schemas::parse(
            "[actions.refund]\ntarget = \"stripe:{charge}/{amount}\"\npolicy = \"policy:refund@14\"",
        )
        .unwrap();
        let ok = entry(
            r#"{"kind":"decision","phase":"intent","action":{"type":"refund","target":"stripe:ch_1/20"},
            "rule":{"ref":"policy:refund","version":"14","result":"allow"}}"#,
        );
        assert_eq!(s.check(&ok), Checked::default());
        let bad = entry(
            r#"{"kind":"decision","phase":"intent","action":{"type":"refund","target":"zendesk:1"},
            "rule":{"ref":"policy:refund","version":"13","result":"allow"}}"#,
        );
        assert_eq!(paths(&s.check(&bad)), ["action.target", "rule.version"]);
        assert_eq!(placeholders_as_globs("a{b}c{d}"), "a*c*");
        assert_eq!(placeholders_as_globs("a{b"), "a{b");
    }

    #[test]
    fn globs() {
        for (p, s, m) in [
            ("a*", "abc", true),
            ("*c", "abc", true),
            ("a*c", "ac", true),
            ("a*b*c", "a-b-c", true),
            ("abc", "abc", true),
            ("*", "", true),
            ("a*c", "ab", false),
            ("abc", "abcd", false),
            ("a*a", "a", false),
            ("stripe:charge/*", "stripe:refund/1", false),
        ] {
            assert_eq!(glob(p, s), m, "{p} {s}");
        }
    }
}
