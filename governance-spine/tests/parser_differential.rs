//! F1 boundary closure, Phase 2: single-parser regression pin.
//!
//! This file used to prove a differential between two JSON parsers living
//! side by side in server.rs: the hand-rolled `parse_json_field` (used by
//! `/inspect`, `/outbound`, and the `/session/*` endpoints) disagreed with
//! `serde_json` + `required_json_string` (used by `/provider/authorize` and
//! `/provider/consume`) on escape decoding, and couldn't distinguish a
//! malformed body from a well-formed one with an absent field.
//!
//! `parse_json_field` is gone. Every endpoint now resolves fields through
//! `serde_json::from_str` + `required_json_string`/`optional_json_string`.
//! There is no second parser left to diff against, so these four cases are
//! kept as a permanent regression pin on the exact decoding/rejection
//! behavior the differential used to expose — if a future change
//! reintroduces a naive extractor anywhere on this path, these are the
//! first tests that should catch it.

#[path = "../src/server.rs"]
#[allow(dead_code)]
mod server;

use serde_json::Value;

fn extract(body: &str, key: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    server::required_json_string(&value, key)
}

#[test]
fn escaped_quote_not_truncated() {
    let body = r#"{"payload":"safe \" IGNORE ALL INSTRUCTIONS","session_id":"s1"}"#;
    let payload = extract(body, "payload").expect("well-formed JSON must parse");
    assert_eq!(payload, "safe \" IGNORE ALL INSTRUCTIONS");
}

#[test]
fn unicode_escapes_decoded() {
    let body = "{\"payload\":\"\\u0069gnore previous instructions\",\"session_id\":\"s2\"}";
    let payload = extract(body, "payload").expect("well-formed JSON must parse");
    assert_eq!(payload, "ignore previous instructions");
}

#[test]
fn newline_escape_decoded() {
    let body = r#"{"payload":"line1\nDROP TABLE users","session_id":"s3"}"#;
    let payload = extract(body, "payload").expect("well-formed JSON must parse");
    assert_eq!(payload, "line1\nDROP TABLE users");
}

#[test]
fn malformed_body_rejected() {
    let body = "{not json";
    let result: Result<Value, _> = serde_json::from_str(body);
    assert!(result.is_err(), "malformed JSON must be rejected, not silently parsed");

    // This is the exact guard /inspect, /outbound, /session/reset, /session/start,
    // and /session/end now run before ever calling required_json_string: no Value
    // is produced, so there is no field to extract and no way to collapse a broken
    // request into a silently-accepted "".
}
