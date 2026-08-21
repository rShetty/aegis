//! Destination parsing, normalization, and policy-pattern matching.
//!
//! Security notes (#2):
//! - Hosts are normalized: lowercased, trailing dot stripped, userinfo
//!   (`user@host`) removed entirely, IPv6 brackets parsed correctly.
//! - Wildcard semantics: `*.suffix` matches **subdomains only** — never the
//!   apex domain itself, never unrelated domains that merely end with the
//!   suffix (e.g. `evil-example.com`). A leading `*.` is the only wildcard
//!   form; embedded or trailing `*` are treated as literal characters.
//! - The catch-all pattern `*` matches any destination (explicit admin intent).
//! - Matching operates on ASCII (punycode) hosts. Unicode/IDN hosts must be
//!   sent by agents in punycode form; a raw-Unicode host simply will not match
//!   an ASCII policy entry (fail closed). We deliberately do NOT perform IDNA
//!   mapping, because homoglyph normalization without a full IDNA stack can
//!   widen matches; see THREAT-MODEL.md.

/// Normalize a host string: lowercase + strip trailing dot.
fn normalize_host(host: &str) -> String {
    let mut h = host.trim().to_ascii_lowercase();
    while h.ends_with('.') {
        h.pop();
    }
    if h.is_empty() {
        // Degenerate input ("." or "") normalizes to empty; callers treat
        // empty as unmatched.
        return h;
    }
    h
}

/// Extract and normalize the host from a destination that may be a bare host,
/// a host:port, an authority with userinfo, or a URL.
///
/// Handles:
/// - scheme stripping (`https://`, `http://`, or any `scheme://`),
/// - path/query/fragment stripping,
/// - userinfo stripping (`api.github.com@evil.com` -> `evil.com`; we keep the
///   *actual* host component, which is what a connection would dial),
/// - IPv6 literals (`[::1]:8080` -> `::1`),
/// - port stripping for non-bracketed hosts.
pub fn extract_host(destination: &str) -> String {
    let rest = match destination.split_once("://") {
        Some((_, r)) => r,
        None => destination,
    };

    // Cut off path/query/fragment.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);

    let host = parse_authority_host(authority);
    normalize_host(&host)
}

/// Parse just the host portion of an authority, handling userinfo, IPv6
/// brackets, and ports.
fn parse_authority_host(authority: &str) -> String {
    if authority.starts_with('[') {
        // Bracketed IPv6 literal: [<addr>]:<port>
        if let Some(end) = authority.find(']') {
            return authority[1..end].to_string();
        }
        // Malformed (no closing bracket): treat everything as the host.
        return authority.trim_start_matches('[').to_string();
    }

    // Strip userinfo: everything up to and including the LAST '@'.
    // (Userinfo may not contain a raw '@' unencoded, so rsplit is correct.)
    let after_userinfo = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };

    // Strip port. For a plain host there is at most one ':'; multiple ':'
    // means an unbracketed IPv6 literal, which we leave intact.
    let colon_count = after_userinfo.matches(':').count();
    if colon_count == 1
        && let Some((host, port)) = after_userinfo.rsplit_once(':')
        && !host.is_empty()
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
    {
        return host.to_string();
    }
    after_userinfo.to_string()
}

/// Does `pattern` (a policy destination) match `destination` (a request)?
///
/// Both sides are normalized before comparison. Supported patterns:
/// - `*`            -> matches everything (catch-all)
/// - `*.example.com`-> subdomains of example.com ONLY (not the apex,
///   not `evil-example.com`, not `example.com.evil.io`)
/// - anything else  -> exact match after normalization
pub fn matches(pattern: &str, destination: &str) -> bool {
    let dest_host = extract_host(destination);
    if dest_host.is_empty() {
        return false;
    }
    let pattern = pattern.trim();
    if pattern == "*" {
        return true;
    }

    // IP literals (v4/v6) are matched by exact string equality only — never
    // by wildcard. This prevents e.g. `*.168.1.1` from treating the IP
    // literal `192.168.1.1` as a DNS subdomain of `168.1.1`.
    if dest_host.parse::<std::net::IpAddr>().is_ok() {
        return normalize_host(pattern) == dest_host;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        let suffix = normalize_host(suffix);
        if suffix.is_empty() {
            // Pattern was literally "*." — degenerate; require exact "*."
            // which cannot occur post-normalization, so no match.
            return false;
        }
        // Subdomains only: host must end with ".{suffix}" AND have a
        // non-empty label before it. This rejects the apex (no dot prefix)
        // and suffix tricks like "evil-example.com" (no dot boundary).
        return dest_host.len() > suffix.len() && dest_host.ends_with(&format!(".{suffix}"));
    }

    // Exact match otherwise (trailing '*' or embedded '*' are LITERAL
    // characters — no prefix-wildcard matching, which enabled userinfo-style
    // bypasses such as "api.github.com*" matching "api.github.com@evil.com").
    normalize_host(pattern) == dest_host
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- extract_host / normalization ----------

    #[test]
    fn extract_plain_hosts() {
        assert_eq!(extract_host("api.github.com"), "api.github.com");
        assert_eq!(
            extract_host("https://api.github.com/repos"),
            "api.github.com"
        );
        assert_eq!(extract_host("http://localhost:8080/path"), "localhost");
        assert_eq!(extract_host("ftp://files.example.com"), "files.example.com");
    }

    #[test]
    fn extract_strips_userinfo() {
        // The classic bypass: userinfo tricks.
        assert_eq!(extract_host("api.github.com@evil.com"), "evil.com");
        assert_eq!(
            extract_host("https://api.github.com@evil.com/x"),
            "evil.com"
        );
        assert_eq!(
            extract_host("https://user:pass@api.github.com/repos"),
            "api.github.com"
        );
        assert_eq!(extract_host("token@internal.corp"), "internal.corp");
    }

    #[test]
    fn extract_lowercases_and_strips_trailing_dot() {
        assert_eq!(extract_host("API.GitHub.COM"), "api.github.com");
        assert_eq!(extract_host("api.github.com."), "api.github.com");
        assert_eq!(extract_host("API.GitHub.COM.."), "api.github.com");
        assert_eq!(
            extract_host("https://Evil.Example.COM./x"),
            "evil.example.com"
        );
    }

    #[test]
    fn extract_ipv6_brackets() {
        assert_eq!(extract_host("[::1]:8080"), "::1");
        assert_eq!(extract_host("http://[2001:db8::1]:443/x"), "2001:db8::1");
        assert_eq!(extract_host("[::ffff:127.0.0.1]"), "::ffff:127.0.0.1");
        // Not bracketed but single-colon host:port
        assert_eq!(extract_host("example.com:993"), "example.com");
    }

    #[test]
    fn extract_malformed_inputs_fail_closed() {
        // Empty / degenerate destinations never match anything.
        assert_eq!(extract_host(""), "");
        assert_eq!(extract_host("."), "");
        assert_eq!(extract_host("https://"), "");
    }

    // ---------- matching semantics ----------

    #[test]
    fn exact_match_after_normalization() {
        assert!(matches("api.github.com", "api.github.com"));
        assert!(matches("api.github.com", "https://api.github.com/repos"));
        assert!(matches("api.github.com", "API.GITHUB.COM"));
        assert!(matches("api.github.com", "api.github.com.:443"));
        assert!(!matches("api.github.com", "other.github.com"));
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        assert!(matches("*.github.com", "api.github.com"));
        assert!(matches("*.github.com", "a.b.c.github.com"));
        assert!(matches("*.github.com", "https://Gist.GitHub.Com/x"));

        // NOT the apex.
        assert!(!matches("*.github.com", "github.com"));
        // NOT suffix tricks.
        assert!(!matches("*.github.com", "evil-github.com"));
        assert!(!matches("*.github.com", "github.com.evil.io"));
        assert!(!matches("*.github.com", "phishing-github.com.evil.io"));
        // NOT bare suffix.
        assert!(!matches("*.github.com", "com"));
    }

    #[test]
    fn catchall_and_degenerate_patterns() {
        assert!(matches("*", "anything.example.com"));
        assert!(matches("*", "https://evil.com@whatever"));
        // "*." is degenerate and matches nothing.
        assert!(!matches("*.", "anything.com"));
        // Embedded/trailing stars are literal, never prefix wildcards.
        assert!(!matches("api.github.com*", "api.github.com@evil.com"));
        assert!(!matches("api.*.com", "api.github.com"));
    }

    #[test]
    fn userinfo_tricks_never_bypass_deny() {
        // Deny rule on evil.com must catch userinfo-shaped destinations.
        assert!(matches("evil.com", "https://trusted.example@evil.com"));
        // And a deny on the visible-looking host does NOT leak into the real one.
        assert!(!matches("api.github.com", "api.github.com@evil.com"));
    }

    #[test]
    fn ip_literals_match_exactly_only() {
        assert!(matches("192.168.1.1", "192.168.1.1"));
        assert!(matches("192.168.1.1", "http://192.168.1.1:8080/"));
        assert!(!matches("192.168.1.1", "192.168.1.100"));
        assert!(!matches("*.168.1.1", "192.168.1.1")); // no partial wildcards on IPs
        assert!(matches("::1", "[::1]:8080"));
    }

    #[test]
    fn idn_punycode_note() {
        // Matching is ASCII/punycode-only by design. A punycode policy entry
        // matches punycode requests; raw-Unicode input fails closed (no match)
        // rather than being homoglyph-normalized.
        assert!(matches(
            "xn--bcher-kva.example.com",
            "xn--bcher-kva.example.com"
        ));
        assert!(!matches("bücher.example.com", "xn--bcher-kva.example.com"));
        assert!(!matches("xn--bcher-kva.example.com", "bücher.example.com"));
    }

    #[test]
    fn case_and_whitespace_in_pattern_normalized() {
        assert!(matches("  API.GitHub.COM ", "api.github.com"));
        assert!(matches("*.GitHub.COM", "api.github.com"));
    }
}
