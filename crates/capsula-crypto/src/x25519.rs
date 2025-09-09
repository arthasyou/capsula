//! X25519 key exchange implementation
//!
//! Simple, direct functions for X25519 Diffie-Hellman operations.

use x25519_dalek::{PublicKey, StaticSecret};

/// Generate a new X25519 keypair for key exchange
///
/// Returns (private_key, public_key) as 32-byte arrays
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut private_key = [0u8; 32];
    getrandom::fill(&mut private_key).expect("failed to generate random bytes");

    let secret = StaticSecret::from(private_key);
    let public_key = PublicKey::from(&secret);

    (private_key, public_key.to_bytes())
}

/// Compute shared secret using X25519
///
/// # Arguments
/// * `private_key` - Our 32-byte private key
/// * `their_public_key` - Their 32-byte public key
///
/// # Returns
/// 32-byte shared secret
pub fn compute_shared_secret(private_key: &[u8; 32], their_public_key: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private_key);
    let their_public = PublicKey::from(*their_public_key);

    secret.diffie_hellman(&their_public).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        // Alice generates keypair
        let (alice_private, alice_public) = generate_keypair();

        // Bob generates keypair
        let (bob_private, bob_public) = generate_keypair();

        // Alice computes shared secret
        let alice_shared = compute_shared_secret(&alice_private, &bob_public);

        // Bob computes shared secret
        let bob_shared = compute_shared_secret(&bob_private, &alice_public);

        // Both should have the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_different_keys_different_secrets() {
        let (alice_private, _alice_public) = generate_keypair();
        let (_bob_private, bob_public) = generate_keypair();
        let (_carol_private, carol_public) = generate_keypair();

        let alice_bob = compute_shared_secret(&alice_private, &bob_public);
        let alice_carol = compute_shared_secret(&alice_private, &carol_public);

        // Different partners should produce different shared secrets
        assert_ne!(alice_bob, alice_carol);
    }
}
