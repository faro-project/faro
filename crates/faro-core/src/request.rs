//! Device request authentication (ARCHITECTURE.md §4.5: "a device token
//! **plus** an Ed25519 signature on every request").
//!
//! The bearer token alone would let anyone who copies it from the state
//! directory impersonate the device; the signature additionally proves
//! possession of the device key and binds the method, path, body and time,
//! so a captured request cannot be replayed outside the instance's skew window
//! (`faro_proto::api::REQUEST_MAX_SKEW_MS`) or retargeted.

use faro_crypto::SigningKey;
use faro_proto::api::{auth_headers, request_signing_bytes};
use faro_proto::DeviceId;

/// Build the `faro-device`, `faro-timestamp` and `faro-signature` headers for
/// one request. `path_and_query` must be exactly what goes on the request
/// line (e.g. `/v1/events:batch`), and `body` exactly the bytes sent.
/// `ts_ms` is the device's wall clock in Unix milliseconds.
pub fn sign_request(
    key: &SigningKey,
    device_id: &DeviceId,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    ts_ms: i64,
) -> Vec<(&'static str, String)> {
    let msg = request_signing_bytes(method, path_and_query, device_id, ts_ms, body);
    let sig = key.sign_raw(&msg);
    vec![
        (auth_headers::DEVICE, device_id.as_str().to_owned()),
        (auth_headers::TIMESTAMP, ts_ms.to_string()),
        (auth_headers::SIGNATURE, sig.to_b64()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_crypto::verify;
    use faro_proto::Signature;

    fn header<'a>(h: &'a [(&'static str, String)], name: &str) -> &'a str {
        &h.iter().find(|(n, _)| *n == name).unwrap().1
    }

    #[test]
    fn server_side_verification_succeeds() {
        let k = SigningKey::generate();
        let d = DeviceId::new("dev_abc");
        let body = br#"{"events":[]}"#;
        let h = sign_request(&k, &d, "post", "/v1/events:batch", body, 1_800_000_000_123);
        assert_eq!(h.len(), 3);
        assert_eq!(header(&h, "faro-device"), "dev_abc");
        assert_eq!(header(&h, "faro-timestamp"), "1800000000123");
        let sig = Signature::from_b64(header(&h, "faro-signature")).unwrap();
        // Rebuild exactly as the server does from the received request.
        let ts: i64 = header(&h, "faro-timestamp").parse().unwrap();
        let msg = request_signing_bytes("POST", "/v1/events:batch", &d, ts, body);
        assert!(verify(&k.public(), &msg, &sig).is_ok());
        // base64url without padding.
        let s = header(&h, "faro-signature");
        assert!(!s.contains('=') && !s.contains('+') && !s.contains('/'));
    }

    #[test]
    fn signature_binds_every_input() {
        let k = SigningKey::generate();
        let d = DeviceId::new("dev_abc");
        let h = sign_request(&k, &d, "POST", "/v1/heartbeat", b"{}", 5);
        let sig = Signature::from_b64(header(&h, "faro-signature")).unwrap();
        let variants = [
            request_signing_bytes("GET", "/v1/heartbeat", &d, 5, b"{}"),
            request_signing_bytes("POST", "/v1/heartbeat?x=1", &d, 5, b"{}"),
            request_signing_bytes("POST", "/v1/heartbeat", &DeviceId::new("dev_x"), 5, b"{}"),
            request_signing_bytes("POST", "/v1/heartbeat", &d, 6, b"{}"),
            request_signing_bytes("POST", "/v1/heartbeat", &d, 5, b"{ }"),
        ];
        for m in variants {
            assert!(verify(&k.public(), &m, &sig).is_err());
        }
    }
}
