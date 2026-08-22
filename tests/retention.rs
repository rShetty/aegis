//! Egress-log retention pruning integration tests (#10).

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use aegis::server::{RetentionState, spawn_retention_task};

/// Insert one row `age_days` in the past through the shared DB handle.
fn seed_old(state: &aegis::server::AppState, agent: &str, destination: &str, age_days: u64) {
    let ts =
        (chrono::Utc::now() - chrono::Duration::try_days(age_days as i64).unwrap()).to_rfc3339();
    state
        .db
        .log_egress_at(
            Some(agent),
            "192.0.2.10",
            destination,
            "POST",
            "allowed",
            None,
            None,
            None,
            None,
            &ts,
        )
        .unwrap();
}

#[tokio::test]
async fn prune_endpoint_is_admin_only() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle) = common::spawn_app(&config, Some("tok-123")).await;
    let client = reqwest::Client::new();

    // No token -> rejected by the admin-plane middleware.
    let resp = client
        .post(format!("{base}/api/egress/prune"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Wrong token -> also rejected.
    let resp = client
        .post(format!("{base}/api/egress/prune"))
        .header("Authorization", "Bearer wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn manual_prune_removes_only_expired_rows_and_updates_stats() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle, state) = common::spawn_app_with_state(&config, Some("tok-123")).await;
    let client = reqwest::Client::new();
    let auth = ("Authorization", "Bearer tok-123");

    // Two expired rows (40d / 365d) and one fresh row (0d).
    seed_old(&state, "agent-1", "expired.example.com", 40);
    seed_old(&state, "agent-1", "ancient.example.com", 365);
    seed_old(&state, "agent-1", "fresh.example.com", 0);

    let resp = client
        .post(format!("{base}/api/egress/prune"))
        .header(auth.0, auth.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["pruned"], 2, "only the two old rows are deleted");
    assert_eq!(body["retention_days"], 30);
    assert_eq!(body["pruned_total"], 2);

    // Exactly the fresh row remains.
    let resp = client
        .get(format!("{base}/api/egress/log?limit=10"))
        .header(auth.0, auth.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let rows: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["destination"], "fresh.example.com");

    // Prune counts surface in /api/egress/stats.
    let resp = client
        .get(format!("{base}/api/egress/stats"))
        .header(auth.0, auth.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let stats: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(stats["total_requests"], 1);
    assert_eq!(stats["retention"]["retention_days"], 30);
    assert_eq!(stats["retention"]["pruned_total"], 2);
    assert_eq!(stats["retention"]["last_pruned"], 2);
    assert!(
        stats["retention"]["last_prune_at"].as_str().is_some(),
        "last_prune_at must be set after a prune: {stats}"
    );

    // Shared counters agree with what the API surfaced.
    assert_eq!(state.retention.pruned_total.load(Ordering::Relaxed), 2);

    // A second prune is a no-op but still bookkeeps.
    let resp = client
        .post(format!("{base}/api/egress/prune"))
        .header(auth.0, auth.1)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["pruned"], 0);
    assert_eq!(body["pruned_total"], 2, "cumulative total is preserved");

    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn background_retention_task_prunes_old_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (_base, tx, handle, state) = common::spawn_app_with_state(&config, None).await;

    seed_old(&state, "agent-1", "stale.example.com", 60);
    seed_old(&state, "agent-1", "recent.example.com", 0);

    // Short period so the test exercises the periodic loop; the first tick
    // of a tokio interval fires immediately.
    let task = spawn_retention_task(&state, Duration::from_millis(50));
    tokio::time::sleep(Duration::from_millis(250)).await;

    let stats = state.db.egress_stats().unwrap();
    assert_eq!(stats["total_requests"], 1, "only the fresh row survives");
    assert_eq!(state.retention.pruned_total.load(Ordering::Relaxed), 1);
    assert_eq!(state.retention.last_pruned.load(Ordering::Relaxed), 1);
    assert!(state.retention.last_prune_at.lock().is_some());

    task.abort();
    tx.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn retention_counters_start_at_zero_before_any_prune() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (_base, tx, handle, state) = common::spawn_app_with_state(&config, None).await;

    let retention: &RetentionState = &state.retention;
    assert_eq!(retention.retention_days, 30);
    assert_eq!(retention.pruned_total.load(Ordering::Relaxed), 0);
    assert_eq!(retention.last_pruned.load(Ordering::Relaxed), 0);
    assert!(retention.last_prune_at.lock().is_none());

    tx.send(()).unwrap();
    handle.await.unwrap();
}
