//! Device identity: an Ed25519 keypair stored as a raw 32-byte seed.

use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Name of the key file inside the config directory.
pub const KEY_FILE: &str = "device.key";

/// Generate a fresh keypair from the OS CSPRNG. The 32 secret bytes are drawn
/// directly rather than through `SigningKey::generate`, whose `CryptoRng`
/// bound ties us to one exact `rand_core` version.
pub fn generate() -> SigningKey {
    use rand::rand_core::TryRng;
    let mut secret = [0u8; 32];
    rand::rngs::SysRng.try_fill_bytes(&mut secret).unwrap();
    SigningKey::from_bytes(&secret)
}

/// Public key, base64 (standard, padded), as sent in the pair request.
pub fn public_key_b64(key: &SigningKey) -> String {
    B64.encode(key.verifying_key().as_bytes())
}

/// First 16 hex chars of sha256(public key). Safe to print.
pub fn fingerprint(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.as_bytes());
    hex::encode(digest)[..16].to_string()
}

/// Sign `msg` and return the base64 (standard, padded) 64-byte signature.
pub fn sign_b64(key: &SigningKey, msg: &[u8]) -> String {
    B64.encode(key.sign(msg).to_bytes())
}

/// Persist the seed as base64 in `dir/device.key`, mode 0600 on unix.
/// The file is written atomically via a temporary sibling.
pub fn save(dir: &Path, key: &SigningKey) -> Result<(), Error> {
    std::fs::create_dir_all(dir).map_err(|e| Error::io("create config dir", dir, e))?;
    let path = dir.join(KEY_FILE);
    let tmp = dir.join(format!("{KEY_FILE}.tmp"));
    let encoded = B64.encode(key.to_bytes());
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .map_err(|e| Error::io("create key file", &tmp, e))?;
        use std::io::Write;
        f.write_all(encoded.as_bytes())
            .and_then(|_| f.write_all(b"\n"))
            .and_then(|_| f.sync_all())
            .map_err(|e| Error::io("write key file", &tmp, e))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io("chmod key file", &tmp, e))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| Error::io("rename key file", &path, e))?;
    Ok(())
}

/// Load the seed from `dir/device.key`.
pub fn load(dir: &Path) -> Result<SigningKey, Error> {
    let path = dir.join(KEY_FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::NotPaired
        } else {
            Error::io("read key file", &path, e)
        }
    })?;
    let bytes = B64
        .decode(text.trim())
        .map_err(|e| Error::Corrupt(format!("{}: {e}", path.display())))?;
    let seed: [u8; SECRET_KEY_LENGTH] = bytes.try_into().map_err(|v: Vec<u8>| {
        Error::Corrupt(format!(
            "{}: expected 32-byte seed, got {} bytes",
            path.display(),
            v.len()
        ))
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn roundtrip_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate();
        save(dir.path(), &key).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded.to_bytes(), key.to_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn signature_verifies() {
        let key = generate();
        let sig = sign_b64(&key, b"hello");
        let raw = B64.decode(sig).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&raw).unwrap();
        key.verifying_key().verify(b"hello", &sig).unwrap();
        assert_eq!(fingerprint(&key.verifying_key()).len(), 16);
    }

    #[test]
    fn missing_key_is_not_paired() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(load(dir.path()), Err(Error::NotPaired)));
    }
}
