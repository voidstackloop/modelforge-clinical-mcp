#![allow(
    clippy::panic,
    reason = "test failures must abort with protocol context"
)]

use std::{
    io::Write,
    process::{Command, Stdio},
};

use serde_json::{Value, json};

fn run_frames(frames: &[Value]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_modelforge-clinical-mcp-stdio"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn stdio gateway: {error}"));

    let mut stdin = child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("missing child stdin"));
    for frame in frames {
        writeln!(stdin, "{frame}")
            .unwrap_or_else(|error| panic!("failed to write MCP frame: {error}"));
    }
    drop(stdin);

    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("failed to wait for stdio gateway: {error}"));
    assert!(
        output.status.success(),
        "gateway stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("stdout was not UTF-8: {error}"))
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("invalid JSON-RPC frame {line:?}: {error}"))
        })
        .collect()
}

#[test]
fn supports_2026_discovery_and_self_contained_requests() {
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "smoke", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let responses = run_frames(&[
        json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":meta}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":meta}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"modelforge.capabilities","arguments":{"includeDescriptions":false},"_meta":meta}}),
    ]);

    let discover = responses
        .iter()
        .find(|frame| frame["id"] == 1)
        .unwrap_or_else(|| panic!("missing discover response"));
    let supported = discover["result"]["supportedVersions"]
        .as_array()
        .unwrap_or_else(|| panic!("missing supportedVersions"));
    assert!(supported.iter().any(|version| version == "2026-07-28"));

    let listed = responses
        .iter()
        .find(|frame| frame["id"] == 2)
        .unwrap_or_else(|| panic!("missing tools/list response"));
    assert_eq!(
        listed["result"]["tools"][0]["name"],
        "modelforge.capabilities"
    );

    let called = responses
        .iter()
        .find(|frame| frame["id"] == 3)
        .unwrap_or_else(|| panic!("missing tools/call response"));
    assert_eq!(called["result"]["structuredContent"]["readOnly"], true);
}

#[test]
fn exposes_deterministic_prompt_catalog_without_grants() {
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "smoke", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let responses = run_frames(&[
        json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":meta}}),
        json!({"jsonrpc":"2.0","id":2,"method":"prompts/list","params":{"_meta":meta}}),
        json!({"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"clinical.soap_draft","_meta":meta}}),
    ]);

    let listed = responses
        .iter()
        .find(|frame| frame["id"] == 2)
        .unwrap_or_else(|| panic!("missing prompts/list response"));
    let names = listed["result"]["prompts"]
        .as_array()
        .unwrap_or_else(|| panic!("missing prompts array"))
        .iter()
        .map(|prompt| prompt["name"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    for expected in [
        "clinical.response_contract",
        "clinical.soap_draft",
        "clinical.differential_support",
        "clinical.medication_review",
        "clinical.evidence_appraisal",
        "clinical.compute_incident_triage",
    ] {
        assert!(names.contains(&expected), "missing prompt {expected}");
    }

    let fetched = responses
        .iter()
        .find(|frame| frame["id"] == 3)
        .unwrap_or_else(|| panic!("missing prompts/get response"));
    let text = fetched["result"]["messages"][0]["content"]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("missing rendered prompt text"));
    assert!(text.contains("1. Summary"));
    assert!(text.contains("8. Uncertainty and limitations"));
    assert!(text.contains("Draft a SOAP note"));
}

#[test]
fn exposes_capabilities_resource_matching_the_tool_manifest() {
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "smoke", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let responses = run_frames(&[
        json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":meta}}),
        json!({"jsonrpc":"2.0","id":2,"method":"resources/list","params":{"_meta":meta}}),
        json!({"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"modelforge://capabilities","_meta":meta}}),
        json!({"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"modelforge://unknown","_meta":meta}}),
    ]);

    let listed = responses
        .iter()
        .find(|frame| frame["id"] == 2)
        .unwrap_or_else(|| panic!("missing resources/list response"));
    assert_eq!(
        listed["result"]["resources"][0]["uri"],
        "modelforge://capabilities"
    );

    let read = responses
        .iter()
        .find(|frame| frame["id"] == 3)
        .unwrap_or_else(|| panic!("missing resources/read response"));
    let text = read["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("missing resource text"));
    let manifest: Value =
        serde_json::from_str(text).unwrap_or_else(|error| panic!("resource was not JSON: {error}"));
    assert_eq!(manifest["tools"][0]["name"], "modelforge.capabilities");
    assert!(manifest["tools"][0]["description"].is_string());

    let missing = responses
        .iter()
        .find(|frame| frame["id"] == 4)
        .unwrap_or_else(|| panic!("missing resources/read error response"));
    assert!(missing.get("error").is_some(), "unknown URI should error");
}

#[test]
fn keeps_legacy_initialize_compatibility() {
    let responses = run_frames(&[
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"legacy-smoke","version":"1.0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    ]);

    let initialized = responses
        .iter()
        .find(|frame| frame["id"] == 1)
        .unwrap_or_else(|| panic!("missing initialize response"));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    assert!(responses.iter().any(|frame| frame["id"] == 2));
}
