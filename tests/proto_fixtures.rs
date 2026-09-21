//! Round-trip every fixture frame through the typed `Frame` enum and check
//! the re-serialized form against the shared JSON Schema.

use std::path::PathBuf;

use serde_json::Value;
use webmcp_daemon::proto::Frame;

fn repo_file(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn load_json(rel: &str) -> Value {
    let path = repo_file(rel);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
}

#[test]
fn fixtures_round_trip_and_validate() {
    let schema = load_json("proto/relay.schema.json");
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let fixtures = load_json("proto/fixtures/frames.json");
    let fixtures = fixtures.as_array().expect("fixtures is an array");
    assert!(!fixtures.is_empty());

    let mut seen_tags = Vec::new();
    for fixture in fixtures {
        let tag = fixture["t"].as_str().expect("fixture has t");
        // The fixture itself must be valid, otherwise the test proves nothing.
        let errs: Vec<String> = validator
            .iter_errors(fixture)
            .map(|e| e.to_string())
            .collect();
        assert!(errs.is_empty(), "fixture `{tag}` invalid: {errs:?}");

        let frame: Frame = serde_json::from_value(fixture.clone())
            .unwrap_or_else(|e| panic!("fixture `{tag}` did not deserialize: {e}"));
        assert_ne!(frame, Frame::Unknown, "fixture `{tag}` fell into Unknown");
        assert_eq!(frame.tag(), tag);

        let text = frame.to_json().unwrap();
        let back: Value = serde_json::from_str(&text).unwrap();
        let errs: Vec<String> = validator
            .iter_errors(&back)
            .map(|e| e.to_string())
            .collect();
        assert!(
            errs.is_empty(),
            "re-serialized `{tag}` invalid: {errs:?}\n{text}"
        );
        assert_eq!(back, *fixture, "re-serialized `{tag}` differs from fixture");

        let again = Frame::from_json(&text).unwrap();
        assert_eq!(again, frame);
        seen_tags.push(tag.to_string());
    }

    // Every frame the schema knows must be covered by a fixture.
    let defs = schema["oneOf"].as_array().unwrap();
    for d in defs {
        let name = d["$ref"].as_str().unwrap().rsplit('/').next().unwrap();
        assert!(
            seen_tags.iter().any(|t| t == name),
            "no fixture for `{name}`"
        );
    }
}

#[test]
fn unknown_frames_are_tolerated() {
    let f = Frame::from_json(r#"{"t":"future_frame","payload":{"a":1}}"#).unwrap();
    assert_eq!(f, Frame::Unknown);
}

#[test]
fn optional_fields_survive_round_trip() {
    let src = r#"{"t":"session_open","sid":"ses_0123456789abcdef","server":"x","client":{"name":"c","version":"1","extra":true}}"#;
    let f = Frame::from_json(src).unwrap();
    let back: Value = serde_json::from_str(&f.to_json().unwrap()).unwrap();
    assert_eq!(back, serde_json::from_str::<Value>(src).unwrap());
}
