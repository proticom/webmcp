//! Device request signatures: HTTP Message Signatures (RFC 9421) with the
//! device's Ed25519 key, plus Content-Digest (RFC 9530) when there is a body.
//! The `httpsig` crate builds the signature base and headers; this module
//! only picks the covered components and parameters the gateway requires.

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use httpsig::prelude::message_component::{HttpMessageComponent, HttpMessageComponentId};
use httpsig::prelude::{AlgorithmName, HttpSignatureBase, HttpSignatureParams, SecretKey};
use sha2::{Digest, Sha256};

/// Must match the gateway (`apps/gateway/src/lib/device-signature.ts`).
pub const TAG: &str = "webmcp-device";
const NAME: &str = "webmcp";

/// Headers to add to one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub signature_input: String,
    pub signature: String,
    pub content_digest: Option<String>,
}

impl Signed {
    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![
            ("Signature-Input", self.signature_input.clone()),
            ("Signature", self.signature.clone()),
        ];
        if let Some(d) = &self.content_digest {
            out.push(("Content-Digest", d.clone()));
        }
        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("cannot sign a request to {0}")]
    Url(String),
    #[error("request signature: {0}")]
    Sign(String),
}

/// A fresh random nonce, 16 bytes as base64url.
pub fn nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Sign `method url` (and `body`, if any) as `device_id`. `created` is Unix
/// seconds. The URL is the one the gateway will see: for a WebSocket that is
/// the `https` form of the `wss` address, which has the same authority, path
/// and query.
pub fn sign(
    key: &SigningKey,
    device_id: &str,
    method: &str,
    url: &url::Url,
    body: Option<&[u8]>,
    created: u64,
    nonce: &str,
) -> Result<Signed, SignError> {
    let host = url
        .host_str()
        .ok_or_else(|| SignError::Url(url.to_string()))?;
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let query = match url.query() {
        Some(q) => format!("?{q}"),
        None => "?".to_string(),
    };
    let mut lines = vec![
        format!("\"@method\": {}", method.to_ascii_uppercase()),
        format!("\"@authority\": {}", authority.to_ascii_lowercase()),
        format!("\"@path\": {}", url.path()),
        format!("\"@query\": {query}"),
    ];
    let content_digest = body.filter(|b| !b.is_empty()).map(|b| {
        let digest = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(b));
        format!("sha-256=:{digest}:")
    });
    if let Some(d) = &content_digest {
        lines.push(format!("\"content-digest\": {d}"));
    }
    let err = |e: httpsig::prelude::HttpSigError| SignError::Sign(e.to_string());
    let components = lines
        .iter()
        .map(|l| HttpMessageComponent::try_from(l.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(err)?;
    let ids: Vec<HttpMessageComponentId> = components.iter().map(|c| c.id.clone()).collect();
    let mut params = HttpSignatureParams::try_new(&ids).map_err(err)?;
    params
        .set_created(created)
        .set_keyid(device_id)
        .set_alg(&AlgorithmName::Ed25519)
        .set_nonce(nonce)
        .set_tag(TAG);
    let secret = SecretKey::from_bytes(&AlgorithmName::Ed25519, &key.to_bytes()).map_err(err)?;
    let headers = HttpSignatureBase::try_new(&components, &params)
        .map_err(err)?
        .build_signature_headers(&secret, Some(NAME))
        .map_err(err)?;
    Ok(Signed {
        signature_input: headers.signature_input_header_value(),
        signature: headers.signature_header_value(),
        content_digest,
    })
}

/// Now, in Unix seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    fn fixed_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn headers_have_the_components_and_parameters_the_gateway_requires() {
        let url = url::Url::parse("https://webmcp.fast/api/v1/device/passkey-link").unwrap();
        let s = sign(
            &fixed_key(),
            "dev_1",
            "post",
            &url,
            Some(b"{}"),
            1_790_000_000,
            "abcdefghijklmnopqrstuv",
        )
        .unwrap();
        assert_eq!(
            s.signature_input,
            "webmcp=(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\");created=1790000000;nonce=\"abcdefghijklmnopqrstuv\";alg=\"ed25519\";keyid=\"dev_1\";tag=\"webmcp-device\""
        );
        assert_eq!(
            s.content_digest.as_deref(),
            Some("sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:")
        );
        // The signature verifies over the RFC 9421 base with the device's public key.
        let base = format!(
            "\"@method\": POST\n\"@authority\": webmcp.fast\n\"@path\": /api/v1/device/passkey-link\n\"@query\": ?\n\"content-digest\": sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:\n\"@signature-params\": {}",
            s.signature_input.trim_start_matches("webmcp=")
        );
        let b64 = s
            .signature
            .trim_start_matches("webmcp=:")
            .trim_end_matches(':');
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        let sig = Signature::from_slice(&raw).unwrap();
        assert!(fixed_key()
            .verifying_key()
            .verify(base.as_bytes(), &sig)
            .is_ok());
    }

    #[test]
    fn a_websocket_upgrade_signs_authority_path_and_query_without_a_body() {
        let url = url::Url::parse("http://localhost:8788/connect?device_id=dev_1").unwrap();
        let s = sign(
            &fixed_key(),
            "dev_1",
            "GET",
            &url,
            None,
            1,
            "abcdefghijklmnopqrstuv",
        )
        .unwrap();
        assert!(s
            .signature_input
            .starts_with("webmcp=(\"@method\" \"@authority\" \"@path\" \"@query\");"));
        assert_eq!(s.content_digest, None);
        assert_eq!(s.pairs().len(), 2);
    }
}
