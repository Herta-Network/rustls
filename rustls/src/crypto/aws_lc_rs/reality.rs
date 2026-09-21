//! Opt-in X25519 exchange supporting REALITY's non-consuming ECDH operation.
use crate::{
    Error, NamedGroup,
    crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup},
};
use alloc::{boxed::Box, vec::Vec};
use aws_lc_rs::agreement;

/// Select this group explicitly for REALITY clients. Standard provider defaults
/// are unaffected.
pub static X25519: &dyn SupportedKxGroup = &RealityX25519;

#[derive(Debug)]
struct RealityX25519;

impl SupportedKxGroup for RealityX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let private =
            agreement::PrivateKey::generate(&agreement::X25519).map_err(super::unspecified_err)?;
        let public = private
            .compute_public_key()
            .map_err(super::unspecified_err)?;
        Ok(Box::new(Active { private, public }))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
    fn ffdhe_group(&self) -> Option<crate::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
}
struct Active {
    private: agreement::PrivateKey,
    public: agreement::PublicKey,
}
impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        agreement::agree(
            &self.private,
            agreement::UnparsedPublicKey::new(&agreement::X25519, peer),
            (),
            |secret| Ok(SharedSecret::from(secret)),
        )
        .map_err(|_| Error::General("invalid X25519 key share".into()))
    }
    fn extract_reality_key(&self, peer: &[u8]) -> Option<Vec<u8>> {
        agreement::agree(
            &self.private,
            agreement::UnparsedPublicKey::new(&agreement::X25519, peer),
            (),
            |secret| Ok(secret.to_vec()),
        )
        .ok()
    }
    fn pub_key(&self) -> &[u8] {
        self.public.as_ref()
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extraction_does_not_consume_handshake_key() {
        let a = X25519.start().unwrap();
        let b = X25519.start().unwrap();
        let public_a = a.pub_key().to_vec();
        let public_b = b.pub_key().to_vec();
        let secret = a
            .extract_reality_key(&public_b)
            .unwrap();
        assert_eq!(
            secret,
            a.extract_reality_key(&public_b)
                .unwrap()
        );
        assert_eq!(
            secret,
            a.complete(&public_b)
                .unwrap()
                .secret_bytes()
        );
        assert_eq!(
            secret,
            b.complete(&public_a)
                .unwrap()
                .secret_bytes()
        );
        assert!(
            X25519
                .start()
                .unwrap()
                .extract_reality_key(&[0; 32])
                .is_none()
        );
    }
}
