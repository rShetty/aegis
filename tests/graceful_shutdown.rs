//! Graceful shutdown integration tests (#5).

mod common;

use std::time::Duration;

#[tokio::test]
async fn server_serves_then_shuts_down_cleanly_on_channel_close() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("aegis.db");
    let config = common::test_config(db_path.to_str().unwrap());

    let (base, tx, handle) = common::spawn_app(&config, None).await;

    // Server answers requests.
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/health"))
        .send()
        .await
        .expect("request to running server");
    assert_eq!(resp.status(), 200);

    // Trigger graceful shutdown via the shutdown channel.
    tx.send(()).expect("server still running");

    // The serve future must complete (drain + stop) within a grace period.
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("graceful shutdown timed out")
        .expect("serve task panicked");
}

#[tokio::test]
async fn shutdown_waits_for_in_flight_request() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("aegis.db");
    let config = common::test_config(db_path.to_str().unwrap());

    let (base, tx, handle) = common::spawn_app(&config, None).await;
    let client = reqwest::Client::new();

    // Fire a check request and close the shutdown channel concurrently; the
    // in-flight request must still complete successfully.
    let req_task = tokio::spawn(async move {
        client
            .post(format!("{base}/api/egress/check"))
            .json(&serde_json::json!({"agent_id": "agent-1", "destination": "https://api.github.com"}))
            .send()
            .await
            .expect("in-flight request must complete")
    });

    // Small yield so the request is dispatched before shutdown begins.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = tx.send(());

    let resp = req_task.await.expect("request task panicked");
    assert_eq!(resp.status(), 403); // default-deny for unknown agent

    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("graceful shutdown timed out")
        .expect("serve task panicked");
}
