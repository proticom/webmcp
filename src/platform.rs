//! Host facts: platform string, hardware id, default device name.

use sha2::{Digest, Sha256};

/// Daemon version from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `<os>-<arch>` as sent in `hello.platform` and the pair request, e.g.
/// `macos-aarch64` or `linux-x86_64`.
pub fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// `User-Agent` for HTTP and WebSocket requests.
pub fn user_agent() -> String {
    format!("webmcp-daemon/{VERSION} ({})", platform())
}

/// Hex sha256 of the stable machine id, if the platform provides one.
pub fn hardware_id() -> Option<String> {
    let id = machine_uid::get().ok()?;
    let id = id.trim();
    if id.is_empty() {
        return None;
    }
    Some(hex::encode(Sha256::digest(id.as_bytes())))
}

/// A random 64-hex-char id used when no machine id is available. The
/// caller persists it so it stays stable across runs.
pub fn random_hardware_id() -> String {
    use rand::rand_core::TryRng;
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng.try_fill_bytes(&mut bytes).unwrap();
    hex::encode(bytes)
}

/// Sanitize a free-form name into `[a-z0-9-]{1,32}` with no leading or
/// trailing dash. Anything not representable yields `device`.
pub fn sanitize_device_name(raw: &str) -> String {
    let short = raw.split('.').next().unwrap_or(raw);
    let mut out = String::with_capacity(short.len());
    let mut last_dash = true; // suppress leading dashes
    for ch in short.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    out.truncate(32);
    let trimmed = out.trim_end_matches('-');
    if trimmed.is_empty() {
        "device".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Default device name: the sanitized hostname.
pub fn default_device_name() -> String {
    let host = hostname::get()
        .ok()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default();
    sanitize_device_name(&host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_hostnames() {
        assert_eq!(
            sanitize_device_name("Alice's MacBook Pro.local"),
            "alice-s-macbook-pro"
        );
        assert_eq!(sanitize_device_name("dev-box-01"), "dev-box-01");
        assert_eq!(sanitize_device_name("--weird__name--"), "weird-name");
        assert_eq!(sanitize_device_name(""), "device");
        assert_eq!(sanitize_device_name("...!!!"), "device");
        let long = sanitize_device_name(&"a".repeat(50));
        assert_eq!(long.len(), 32);
        let dash_at_cut = sanitize_device_name(&format!("{}-{}", "a".repeat(31), "b".repeat(10)));
        assert_eq!(dash_at_cut, "a".repeat(31));
        assert!(crate::config::is_valid_alias(&sanitize_device_name(
            "Some Host"
        )));
    }

    #[test]
    fn platform_shape() {
        let p = platform();
        assert!(p.contains('-'));
        assert!(user_agent().starts_with("webmcp-daemon/0.1.0 ("));
        assert_eq!(random_hardware_id().len(), 64);
    }
}
