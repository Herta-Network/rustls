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
/// X25519MLKEM768 with non-consuming REALITY authentication through X25519.
pub use super::pq::REALITY_X25519MLKEM768 as X25519MLKEM768;

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
    fn hybrid_authentication_and_tls_secret_use_the_same_classical_key() {
        let client = X25519MLKEM768.start().unwrap();
        let server_static = X25519.start().unwrap();
        let (_, classical) = client.hybrid_component().unwrap();
        assert_eq!(
            client
                .extract_reality_key(server_static.pub_key())
                .unwrap(),
            server_static
                .extract_reality_key(classical)
                .unwrap()
        );
        let server = X25519MLKEM768
            .start_and_complete(client.pub_key())
            .unwrap();
        assert_eq!(
            client
                .complete(&server.pub_key)
                .unwrap()
                .secret_bytes(),
            server.secret.secret_bytes()
        );
        let client = X25519MLKEM768.start().unwrap();
        let expected = client
            .extract_reality_key(server_static.pub_key())
            .unwrap();
        assert_eq!(
            client
                .complete_hybrid_component(server_static.pub_key())
                .unwrap()
                .secret_bytes(),
            expected
        );
    }
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
