//! HTTP-level adversarial suite (#8): replays the destination-matching
//! bypass classes from issue #2 against the real axum app over the wire.
//!
//! The unit tests in `src/destination.rs` and `src/egress/mod.rs` cover the
//! engine; these tests prove the *server* upholds the same verdicts end to
//! end — routing, JSON decoding, spawn_blocking, and the audit trail included.

mod common;

const TOKEN: &str = "adv-admin-token";

/// One adversarial check request: `(label, destination, must_block)`.
struct Case(&'static str, &'static str, bool);

fn cases() -> Vec<Case> {
    vec![
        Case(
            "userinfo trick must not inherit an allow rule",
            "https://api.github.com@evil.com/steal",
            true,
        ),
        Case(
            "userinfo with credentials",
            "https://user:pass@api.github.com@evil.com",
            true,
        ),
        Case(
            "case variants cannot defeat a deny",
            "https://EVIL.EXAMPLE.COM/x",
            true,
        ),
        Case("mixed case deny", "https://Evil.Example.Com", true),
        Case(
            "trailing dot cannot defeat a deny",
            "https://evil.example.com./x",
            true,
        ),
        Case("double trailing dot", "evil.example.com..", true),
        Case(
            "port + trailing dot + case",
            "https://EVIL.example.COM.:8443",
            true,
        ),
        Case(
            "bracketed IPv6 hits the deny",
            "http://[::1]:8080/admin",
            true,
        ),
        Case("bare bracketed IPv6", "[::1]", true),
        Case(
            "wildcard must not cover the apex github.com",
            "https://github.com",
            true,
        ),
        Case(
            "suffix trick: evil-github.com",
            "https://evil-github.com",
            true,
        ),
        Case(
            "suffix trick: github.com.evil.io",
            "https://github.com.evil.io",
            true,
        ),
        // The trailing-star policy is LITERAL (matches nothing useful), and
        // no other policy covers evil-github.com, so it falls through to
        // default-deny (#2). api.github.com itself IS covered by the
        // legitimate `*.github.com` allow and stays allowed.
        Case(
            "trailing-star pattern is literal; evil-github.com falls to default-deny",
            "https://evil-github.com",
            true,
        ),
        Case("degenerate empty destination", "", true),
        Case("degenerate dot destination", ".", true),
        Case("degenerate scheme-only destination", "https://", true),
        Case(
            "raw unicode IDN fails closed",
            "https://bücher.example.com",
            true,
        ),
        Case(
            "punycode form matches the allow policy",
            "https://xn--bcher-kva.example.com",
            false,
        ),
        Case("plain allowed host", "https://gist.github.com", false),
    ]
}

#[tokio::test]
async fn adversarial_destinations_over_http() {
    let tmp = tempfile::tempdir().unwrap();
    let config = common::test_config(tmp.path().join("aegis.db").to_str().unwrap());
    let (base, tx, handle) = common::spawn_app(&config, Some(TOKEN)).await;
    let client = reqwest::Client::new();
    let auth = ("Authorization".to_string(), format!("Bearer {TOKEN}"));

    // Policies for agent-adv (the only agent with policies):
    // - allow *.github.com            (subdomains only)
    // - deny  evil.example.com        (case / trailing-dot target)
    // - deny  ::1                     (IPv6 literal)
    // - allow xn--bcher-kva.example.com (punycode)
    // - allow api.github.com*         (trailing star: LITERAL, matches nothing)
    for (dest, action) in [
        ("*.github.com", "allow"),
        ("evil.example.com", "deny"),
        ("::1", "deny"),
        ("xn--bcher-kva.example.com", "allow"),
        ("api.github.com*", "allow"),
    ] {
        let resp = client
            .post(format!("{base}/api/egress/policies/agent-adv"))
            .header(&auth.0, &auth.1)
            .json(&serde_json::json!({"destination": dest, "action": action}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "seed policy {dest} {action}");
    }

    for Case(label, destination, must_block) in cases() {
        let resp = client
            .post(format!("{base}/api/egress/check"))
            .json(&serde_json::json!({"agent_id": "agent-adv", "destination": destination}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status() == 403,
            must_block,
            "{label}: destination {destination:?} -> status {}",
            resp.status()
        );
    }

    // The audit trail recorded every blocked attempt. NOTE (#8 audit
    // observation): checks allowed by an explicit policy currently return
    // early from EgressEngine::check WITHOUT an audit row — 2 of these 19
    // cases were allowed, so 17 rows appear. The README promises "every
    // check (allowed or blocked)" is logged; this gap is tracked as a
    // finding of the #12 deep-audit pass.
    let resp = client
        .get(format!("{base}/api/egress/log?limit=100"))
        .header(&auth.0, &auth.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let rows: serde_json::Value = resp.json().await.unwrap();
    let rows = rows.as_array().unwrap();
    let blocked = cases().iter().filter(|c| c.2).count();
    assert_eq!(rows.len(), blocked);
    assert!(rows.iter().all(|r| r["status"] == "blocked"));

    tx.send(()).unwrap();
    handle.await.unwrap();
}
