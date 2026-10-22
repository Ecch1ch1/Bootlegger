use crate::error::{BootlegError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Derived session keys from password + salt
pub struct DerivedKeys {
    pub enc_key: [u8; 32],
    pub prng_seed: [u8; 32],
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.prng_seed.zeroize();
    }
}

pub struct CryptoEngine;

impl CryptoEngine {
    /// Derives encryption key and PRNG dispersion seed using Argon2id + HKDF
    pub fn derive_keys(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<DerivedKeys> {
        let params = Params::new(32 * 1024, 3, 1, Some(64))
            .map_err(|e| BootlegError::KeyDerivation(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut master = [0u8; 64];
        argon
            .hash_password_into(password, salt, &mut master)
            .map_err(|e| BootlegError::KeyDerivation(e.to_string()))?;

        let hk = Hkdf::<Sha256>::new(None, &master);
        master.zeroize();

        let mut enc_key = [0u8; 32];
        let mut prng_seed = [0u8; 32];

        hk.expand(b"bootlegger-encryption-key-v1", &mut enc_key)
            .map_err(|e| BootlegError::KeyDerivation(e.to_string()))?;
        hk.expand(b"bootlegger-dispersion-seed-v1", &mut prng_seed)
            .map_err(|e| BootlegError::KeyDerivation(e.to_string()))?;

        Ok(DerivedKeys { enc_key, prng_seed })
    }

    /// Build Additional Authenticated Data (AAD) for ChaCha20-Poly1305
    pub fn build_aad(tripwire_digest: Option<&[u8; 32]>) -> Vec<u8> {
        let mut aad = Vec::with_capacity(33);
        match tripwire_digest {
            Some(digest) => {
                aad.push(0x01); // Tripwire active
                aad.extend_from_slice(digest);
            }
            None => {
                aad.push(0x00); // Tripwire disabled
            }
        }
        aad
    }

    /// Encrypts plaintext using provided derived keys. Output format: Nonce (12B) | Ciphertext + Tag
    pub fn encrypt_with_keys(
        plaintext: &[u8],
        keys: &DerivedKeys,
        tripwire_digest: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.enc_key));
        let nonce = Nonce::from_slice(&nonce_bytes);

        let aad = Self::build_aad(tripwire_digest);
        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| BootlegError::AuthenticationFailed)?;

        let mut bundle = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        bundle.extend_from_slice(&nonce_bytes);
        bundle.extend_from_slice(&ciphertext);

        Ok(bundle)
    }

    /// Decrypts ciphertext bundle (Nonce | Ciphertext + Tag) using provided derived keys
    pub fn decrypt_with_keys(
        bundle: &[u8],
        keys: &DerivedKeys,
        candidate_tripwire_digest: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>> {
        if bundle.len() < NONCE_LEN + TAG_LEN {
            return Err(BootlegError::AuthenticationFailed);
        }

        let nonce_bytes: &[u8; NONCE_LEN] = bundle[..NONCE_LEN].try_into().unwrap();
        let ciphertext = &bundle[NONCE_LEN..];

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.enc_key));
        let nonce = Nonce::from_slice(nonce_bytes);

        let aad = Self::build_aad(candidate_tripwire_digest);
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };

        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| BootlegError::AuthenticationFailed)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = b"correct-horse-battery-staple";
        let secret = b"TOP SECRET MISSION DIRECTIVE 007";
        let salt = [12u8; SALT_LEN];
        let tripwire_digest = [42u8; 32];

        let keys = CryptoEngine::derive_keys(password, &salt).unwrap();
        let bundle = CryptoEngine::encrypt_with_keys(secret, &keys, Some(&tripwire_digest)).unwrap();

        let decrypted = CryptoEngine::decrypt_with_keys(&bundle, &keys, Some(&tripwire_digest)).unwrap();
        assert_eq!(decrypted, secret);

        // Wrong tripwire fails
        let tampered_digest = [99u8; 32];
        assert!(CryptoEngine::decrypt_with_keys(&bundle, &keys, Some(&tampered_digest)).is_err());
    }
}
