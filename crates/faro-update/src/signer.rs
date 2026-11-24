//! The signing side: project release tooling and tests.
//!
//! Clients and the server mirror never sign; they only verify. Signing lives
//! in the same crate so the exact bytes produced here are the bytes the
//! verifier is tested against.

use crate::envelope::Envelope;
use crate::error::UpdateError;
use crate::metadata::RoleMetadata;
use faro_crypto::SigningKey;

/// Produces signed envelopes from role metadata.
///
/// Refuses to sign metadata that fails [`RoleMetadata::validate`], so
/// release tooling can't publish a document every client would reject (for
/// example a root with an unsatisfiable threshold).
#[derive(Debug)]
pub struct MetadataSigner<'k> {
    keys: Vec<&'k SigningKey>,
}

impl<'k> MetadataSigner<'k> {
    pub fn new(keys: impl IntoIterator<Item = &'k SigningKey>) -> Self {
        MetadataSigner {
            keys: keys.into_iter().collect(),
        }
    }

    /// Validate, serialize and sign `meta` with every configured key.
    pub fn sign<T: RoleMetadata>(&self, meta: &T) -> Result<Envelope, UpdateError> {
        meta.validate()
            .map_err(|reason| UpdateError::InvalidMetadata {
                role: T::ROLE,
                reason,
            })?;
        let payload = serde_json::to_vec(meta).map_err(|e| UpdateError::InvalidMetadata {
            role: T::ROLE,
            reason: format!("serialization failed: {e}"),
        })?;
        Ok(Envelope::sign_raw(
            T::ROLE.payload_type(),
            &payload,
            &self.keys,
        ))
    }

    /// [`sign`](Self::sign) and serialize to the bytes that get published.
    pub fn sign_to_bytes<T: RoleMetadata>(&self, meta: &T) -> Result<Vec<u8>, UpdateError> {
        Ok(self.sign(meta)?.to_bytes())
    }
}
