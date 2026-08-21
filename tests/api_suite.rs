//! End-to-end API integration suite (#8).
//!
//! Spins the real axum app on an ephemeral loopback port (via
//! `common::spawn_app`) and drives it with reqwest. Covers the acceptance
//! criteria from issue #8:
//! - health endpoints,
//! - auth rejections (every admin route, missing and wrong tokens),
//! - the full policy CRUD flow,
//! - check allow/deny/default-deny paths plus request validation,
//! - attestation registration/verification over HTTP,
//! - audit log and stats surfacing,
//! - load smoke: 500 sequential checks in under one second.

mod common;

use std::time::{Duration, Instant};

const TOKEN: &str = "itest-admin-token";

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

fn auth() -> String {
    format!("Bearer {TOKEN}")
}

/// Every admin-plane route, with the method + body needed to reach the
/// handler (the middleware rejects before the handler sees anything).
fn admin_routes(base: &str) -> Vec<(reqwest::Method, String)> {
    use reqwest::Method;
    vec![
        (Method::GET, format!("{base}/api/egress/policies/agent-x")),
        (Method::POST, format!("{base}/api/egress/policies/agent-x")),
        (
            Method::DELETE,
            format!("{base}/api/egress/policies/agent-x/some-id"),
        ),
        (Method::GET, format!("{base}/api/egress/log")),
        (Method::GET, format!("{base}/api/egress/stats")),
        (Method::POST, format!("{base}/api/egress/prune")),
        (Method::POST, format!("{base}/api/attestation/attestate")),
        (Method::GET, format!("{base}/api/attestation/agents")),
    ]
}

#[tokio::test]
async fn health_endpoint_is_public_and_json() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle) = common::spawn_app(&config, Some(TOKEN)).await;
    let client = client();

    // No Authorization header: /health sits outside the admin plane (#1).
    let resp = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "aegis");

    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn every_admin_route_rejects_missing_token() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle) = common::spawn_app(&config, Some(TOKEN)).await;
    let client = client();

    for (method, url) in admin_routes(&base) {
        let mut req = client.request(method.clone(), &url);
        if method == reqwest::Method::POST {
            req = req.json(&serde_json::json!({"destination": "example.com", "action": "allow"}));
        }
        let resp = req.send().await.unwrap();
        assert_eq!(
            resp.status(),
            401,
            "{method} {url} must reject a missing admin token"
        );
    }

    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn every_admin_route_rejects_wrong_token() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle) = common::spawn_app(&config, Some(TOKEN)).await;
    let client = client();

    for (method, url) in admin_routes(&base) {
        let mut req = client
            .request(method.clone(), &url)
            .header("Authorization", "Bearer not-the-token");
        if method == reqwest::Method::POST {
            req = req.json(&serde_json::json!({"destination": "example.com", "action": "allow"}));
        }
        let resp = req.send().await.unwrap();
        assert_eq!(
            resp.status(),
            401,
            "{method} {url} must reject a wrong admin token"
        );
    }

    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn data_plane_routes_do_not_require_a_token() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle) = common::spawn_app(&config, Some(TOKEN)).await;
    let client = client();

    // Data-plane routes must be reachable WITHOUT a token. They may still
    // answer 403 (policy verdicts) — the point is they never answer 401.
    let resp = client
        .post(format!("{base}/api/egress/check"))
        .json(&serde_json::json!({"agent_id": "agent-1", "destination": "https://unlisted.example.com"}))
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 401);
    assert_eq!(resp.status(), 403, "default-deny still applies");

    let resp = client
        .post(format!("{base}/api/geo/check"))
        .json(&serde_json::json!({"destination": "https://api.github.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(format!("{base}/api/attestation/verify"))
        .json(&serde_json::json!({"agent_id": "nobody", "process_hash": "ff"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], false);

    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn policy_crud_full_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle) = common::spawn_app(&config, Some(TOKEN)).await;
    let client = client();
    let auth_header = ("Authorization", auth());

    // CREATE: add an allow policy via the admin API.
    let resp = client
        .post(format!("{base}/api/egress/policies/crud-agent"))
        .header(auth_header.0, &auth_header.1)
        .json(&serde_json::json!({"destination": "api.github.com", "action": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["added"], true);
    let policy_id = body["id"].as_str().expect("policy id").to_string();
    assert!(!policy_id.is_empty());

    // READ: the policy is listed with its fields intact.
    let resp = client
        .get(format!("{base}/api/egress/policies/crud-agent"))
        .header(auth_header.0, &auth_header.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["agent_id"], "crud-agent");
    let policies = body["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["id"], policy_id.as_str());
    assert_eq!(policies[0]["destination"], "api.github.com");
    assert_eq!(policies[0]["action"], "allow");
    assert!(policies[0]["created_at"].as_str().is_some());

    // The policy takes effect on the data plane.
    let resp = client
        .post(format!("{base}/api/egress/check"))
        .json(&serde_json::json!({"agent_id": "crud-agent", "destination": "https://api.github.com/repos"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["allowed"], true);
    assert_eq!(body["agent_id"], "crud-agent");

    // DELETE: remove the policy.
    let resp = client
        .delete(format!("{base}/api/egress/policies/crud-agent/{policy_id}"))
        .header(auth_header.0, &auth_header.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["removed"], true);

    // READ: the list is empty again and the check flips to default-deny.
    let resp = client
        .get(format!("{base}/api/egress/policies/crud-agent"))
        .header(auth_header.0, &auth_header.1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap()["policies"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let resp = client
        .post(format!("{base}/api/egress/check"))
        .json(
            &serde_json::json!({"agent_id": "crud-agent", "destination": "https://api.github.com"}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "removed policy must stop allowing");

    // DELETE of the same id again: 404, scoped to the agent.
    let resp = client
        .delete(format!("{base}/api/egress/policies/crud-agent/{policy_id}"))
        .header(auth_header.0, &auth_header.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn policy_scoped_per_agent_for_delete_and_list() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle) = common::spawn_app(&config, Some(TOKEN)).await;
    let client = client();
    let auth_header = ("Authorization", auth());

    for agent in ["agent-a", "agent-b"] {
        let resp = client
            .post(format!("{base}/api/egress/policies/{agent}"))
            .header(auth_header.0, &auth_header.1)
            .json(&serde_json::json!({"destination": "api.github.com", "action": "allow"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // Listing one agent never leaks the other agent's policies.
    let resp = client
        .get(format!("{base}/api/egress/policies/agent-a"))
        .header(auth_header.0, &auth_header.1)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let listed = body["policies"].as_array().unwrap();
    assert_eq!(listed.len(), 1);

    // Deleting agent-a's policy through agent-b's URL must not succeed.
    let id_a = listed[0]["id"].as_str().unwrap().to_string();
    let resp = client
        .delete(format!("{base}/api/egress/policies/agent-b/{id_a}"))
        .header(auth_header.0, &auth_header.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "cross-agent delete must not find it");

    // agent-a keeps its policy and can still check successfully.
    let resp = client
        .get(format!("{base}/api/egress/policies/agent-a"))
        .header(auth_header.0, &auth_header.1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap()["policies"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn add_policy_rejects_invalid_action() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle) = common::spawn_app(&config, Some(TOKEN)).await;
    let client = client();

    for bad in ["drop", "ALLOW", "", "read-write"] {
        let resp = client
            .post(format!("{base}/api/egress/policies/agent-x"))
            .header("Authorization", auth())
            .json(&serde_json::json!({"destination": "example.com", "action": bad}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "action '{bad}' must be rejected");
    }

    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn check_allow_deny_and_default_deny_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle) = common::spawn_app(&config, Some(TOKEN)).await;
    let client = client();
    let auth_header = ("Authorization", auth());

    // agent-ok: wildcard allow. agent-mixed: broad allow + specific deny.
    for (agent, dest, action) in [
        ("agent-ok", "*", "allow"),
        ("agent-mixed", "*.github.com", "allow"),
        ("agent-mixed", "secret.github.com", "deny"),
    ] {
        let resp = client
            .post(format!("{base}/api/egress/policies/{agent}"))
            .header(auth_header.0, &auth_header.1)
            .json(&serde_json::json!({"destination": dest, "action": action}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{dest} {action}");
    }

    // Allow path.
    let resp = client
        .post(format!("{base}/api/egress/check"))
        .json(&serde_json::json!({"agent_id": "agent-ok", "destination": "https://anything.example.net"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["allowed"], true);

    // Deny beats allow regardless of insertion order.
    let resp = client
        .post(format!("{base}/api/egress/check"))
        .json(&serde_json::json!({"agent_id": "agent-mixed", "destination": "https://secret.github.com/x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("denied"));

    // Broader allow still admits sibling hosts.
    let resp = client
        .post(format!("{base}/api/egress/check"))
        .json(&serde_json::json!({"agent_id": "agent-mixed", "destination": "https://api.github.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Default-deny: agent without any matching policy.
    let resp = client
        .post(format!("{base}/api/egress/check"))
        .json(&serde_json::json!({"agent_id": "stranger", "destination": "https://api.github.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Missing agent_id cannot match policies: default-deny, fail-closed.
    let resp = client
        .post(format!("{base}/api/egress/check"))
        .json(&serde_json::json!({"destination": "https://api.github.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn check_request_validation_rejects_bad_payloads() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle) = common::spawn_app(&config, Some(TOKEN)).await;
    let client = client();

    // Malformed JSON -> 400 (axum JSON syntax rejection).
    let resp = client
        .post(format!("{base}/api/egress/check"))
        .header("Content-Type", "application/json")
        .body("{\"destination\": ")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Well-formed JSON failing deserialization (destination missing) -> 422.
    let resp = client
        .post(format!("{base}/api/egress/check"))
        .json(&serde_json::json!({"agent_id": "agent-1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);

    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn egress_log_and_stats_surface_check_outcomes() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle, state) = common::spawn_app_with_state(&config, Some(TOKEN)).await;
    let client = client();

    // One allowed check, one blocked check.
    state
        .db
        .add_egress_policy("logged-agent", "api.github.com", "allow")
        .unwrap();

    client
        .post(format!("{base}/api/egress/check"))
        .json(&serde_json::json!({"agent_id": "logged-agent", "destination": "https://api.github.com"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/api/egress/check"))
        .json(&serde_json::json!({"agent_id": "logged-agent", "destination": "https://blocked.example.com"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/api/egress/log?limit=10"))
        .header("Authorization", auth())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let rows: serde_json::Value = resp.json().await.unwrap();
    let rows = rows.as_array().unwrap();
    // NOTE (#8 audit observation): allowed-by-policy checks currently return
    // from EgressEngine::check WITHOUT an audit row, so only the blocked
    // check appears. README line 97 promises every check is logged; closing
    // that gap is a #12 deep-audit finding.
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["status"], "blocked");
    assert_eq!(rows[0]["destination"], "blocked.example.com");
    for row in rows {
        assert!(row["timestamp"].as_str().is_some());
        assert!(row["destination"].as_str().is_some());
    }

    let resp = client
        .get(format!("{base}/api/egress/stats"))
        .header("Authorization", auth())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let stats: serde_json::Value = resp.json().await.unwrap();
    // Only the blocked check produced an audit row (see NOTE above).
    assert_eq!(stats["total_requests"], 1);
    assert_eq!(stats["allowed"], 0);
    assert_eq!(stats["blocked"], 1);

    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn attestation_register_verify_list_over_http() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle) = common::spawn_app(&config, Some(TOKEN)).await;
    let client = client();
    let auth_header = ("Authorization", auth());

    // Fake agent binary to register.
    let bin_dir = tempfile::tempdir().unwrap();
    let bin_path = bin_dir.path().join("agent-binary");
    std::fs::write(&bin_path, b"AEGIS-FAKE-BINARY-PAYLOAD").unwrap();
    let bin_str = bin_path.to_str().unwrap();

    let mut hasher = sha2::Sha256::default();
    sha2::Digest::update(&mut hasher, b"AEGIS-FAKE-BINARY-PAYLOAD");
    let expected_hash = hex::encode(sha2::Digest::finalize(hasher));

    // Register (admin-only endpoint).
    let resp = client
        .post(format!("{base}/api/attestation/attestate"))
        .header(auth_header.0, &auth_header.1)
        .json(&serde_json::json!({"agent_id": "att-agent", "binary_path": bin_str, "pid": 4242}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["attested"], true);
    assert_eq!(body["process_hash"], expected_hash.as_str());

    // Verify with matching binary path.
    let resp = client
        .post(format!("{base}/api/attestation/verify"))
        .json(&serde_json::json!({"agent_id": "att-agent", "binary_path": bin_str}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], true);

    // Verify with a tampered binary fails.
    let tampered = bin_dir.path().join("tampered");
    std::fs::write(&tampered, b"TAMPERED-PAYLOAD").unwrap();
    let resp = client
        .post(format!("{base}/api/attestation/verify"))
        .json(&serde_json::json!({"agent_id": "att-agent", "binary_path": tampered.to_str().unwrap()}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], false);

    // Verify with an explicit wrong hash fails.
    let resp = client
        .post(format!("{base}/api/attestation/verify"))
        .json(&serde_json::json!({"agent_id": "att-agent", "process_hash": "00"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], false);

    // Unknown agent verifies to false (fail closed).
    let resp = client
        .post(format!("{base}/api/attestation/verify"))
        .json(&serde_json::json!({"agent_id": "ghost", "process_hash": "00"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], false);

    // Listing attested agents is admin-only and shows the registration.
    let resp = client
        .get(format!("{base}/api/attestation/agents"))
        .header(auth_header.0, &auth_header.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let agents: serde_json::Value = resp.json().await.unwrap();
    let agents = agents.as_array().unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0]["agent_id"], "att-agent");
    assert_eq!(agents[0]["process_hash"], expected_hash.as_str());
    assert_eq!(agents[0]["pid"], 4242);

    // Attesting a missing binary path fails cleanly with the configured
    // error mapping (AttestationFailed -> 401); importantly it must not
    // panic or register the agent.
    let resp = client
        .post(format!("{base}/api/attestation/attestate"))
        .header(auth_header.0, &auth_header.1)
        .json(&serde_json::json!({"agent_id": "att-agent-2", "binary_path": "/nonexistent/path/binary"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let resp = client
        .get(format!("{base}/api/attestation/agents"))
        .header(auth_header.0, &auth_header.1)
        .send()
        .await
        .unwrap();
    let agents: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        agents.as_array().unwrap().len(),
        1,
        "failed registration must not create an attested row"
    );

    tx.send(()).unwrap();
    handle.await.unwrap();
}

/// Load smoke (#8): 500 sequential checks must complete in under one second.
/// Catches regressions where per-check locking serializes worse than the
/// intended short critical sections.
#[tokio::test]
async fn load_smoke_500_sequential_checks_under_one_second() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle, state) = common::spawn_app_with_state(&config, Some(TOKEN)).await;
    let client = client();

    state
        .db
        .add_egress_policy("smoke-agent", "*", "allow")
        .unwrap();

    let start = Instant::now();
    for i in 0..500 {
        let resp = client
            .post(format!("{base}/api/egress/check"))
            .json(&serde_json::json!({
                "agent_id": "smoke-agent",
                "destination": format!("https://host-{i}.example.com")
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "check {i} must be allowed");
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "500 sequential checks took {elapsed:?}, budget is 1s"
    );

    // Audit rows for allowed-by-policy checks are currently NOT written
    // (EgressEngine::check returns early) — a #12 finding. The load
    // assertion here is the HTTP path completing 500 times.
    println!("500 sequential checks completed in {elapsed:?}");
    tx.send(()).unwrap();
    handle.await.unwrap();
}
