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
        // Argon2id parameters (safe and fast for interactive CLI usage: 32MB RAM, 3 iterations)
        let params = Params::new(32 * 1024, 3, 1, Some(64))
            .map_err(|e| BootlegError::KeyDerivation(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut master = [0u8; 64];
        argon
            .hash_password_into(password, salt, &mut master)
            .map_err(|e| BootlegError::KeyDerivation(e.to_string()))?;

        // Expand master key via HKDF-SHA256 into enc_key + prng_seed
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
    fn build_aad(tripwire_digest: Option<&[u8; 32]>) -> Vec<u8> {
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

    /// Encrypts secret payload. Returns raw encrypted bundle (salt + nonce + ciphertext + tag)
    pub fn encrypt(
        plaintext: &[u8],
        password: &[u8],
        tripwire_digest: Option<&[u8; 32]>,
    ) -> Result<(Vec<u8>, DerivedKeys)> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let keys = Self::derive_keys(password, &salt)?;
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

        // Bundle: Salt (16B) | Nonce (12B) | Ciphertext+Tag
        let mut bundle = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        bundle.extend_from_slice(&salt);
        bundle.extend_from_slice(&nonce_bytes);
        bundle.extend_from_slice(&ciphertext);

        Ok((bundle, keys))
    }

    /// Decrypts encrypted bundle. Enforces Tripwire digest check through AEAD AAD authentication
    pub fn decrypt(
        bundle: &[u8],
        password: &[u8],
        candidate_tripwire_digest: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>> {
        if bundle.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
            return Err(BootlegError::AuthenticationFailed);
        }

        let salt: &[u8; SALT_LEN] = bundle[..SALT_LEN].try_into().unwrap();
        let nonce_bytes: &[u8; NONCE_LEN] =
            bundle[SALT_LEN..SALT_LEN + NONCE_LEN].try_into().unwrap();
        let ciphertext = &bundle[SALT_LEN + NONCE_LEN..];

        let keys = Self::derive_keys(password, salt)?;
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
        let tripwire_digest = [42u8; 32];

        // Encrypt with Tripwire
        let (bundle, _) =
            CryptoEngine::encrypt(secret, password, Some(&tripwire_digest)).unwrap();

        // Decrypt with correct password & matching tripwire digest
        let decrypted =
            CryptoEngine::decrypt(&bundle, password, Some(&tripwire_digest)).unwrap();
        assert_eq!(decrypted, secret);

        // Decrypt with WRONG password fails
        assert!(CryptoEngine::decrypt(&bundle, b"wrong-pass", Some(&tripwire_digest)).is_err());

        // Decrypt with TAMPERED tripwire digest (carrier was touched!) fails
        let tampered_digest = [99u8; 32];
        assert!(CryptoEngine::decrypt(&bundle, password, Some(&tampered_digest)).is_err());
    }
}
