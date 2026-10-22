use crate::error::{BootlegError, Result};
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Represents an available slack slot in the carrier archive
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackSlot {
    /// Identifier or index of the carrier file
    pub file_index: usize,
    /// Offset in the archive where slack begins
    pub archive_offset: u64,
    /// Capacity of this slack slot in bytes
    pub capacity: usize,
}

/// Description of the serialized payload before encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPayload {
    /// Original filename (e.g., "document.pdf")
    pub filename: String,
    /// Raw secret content bytes
    pub data: Vec<u8>,
}

impl SecretPayload {
    pub fn new(filename: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            filename: filename.into(),
            data,
        }
    }

    /// Canonical binary serialization: [2-byte name_len | name | 8-byte data_len | data]
    pub fn to_bytes(&self) -> Vec<u8> {
        let name_bytes = self.filename.as_bytes();
        let name_len = name_bytes.len() as u16;
        let data_len = self.data.len() as u64;

        let mut out = Vec::with_capacity(2 + name_bytes.len() + 8 + self.data.len());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&data_len.to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Deserialization from canonical binary
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 10 {
            return Err(BootlegError::Serialization("Payload too short".into()));
        }

        let name_len = u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as usize;
        if bytes.len() < 2 + name_len + 8 {
            return Err(BootlegError::Serialization("Truncated filename".into()));
        }

        let filename = String::from_utf8(bytes[2..2 + name_len].to_vec())
            .map_err(|e| BootlegError::Serialization(e.to_string()))?;

        let data_offset = 2 + name_len;
        let data_len = u64::from_le_bytes(
            bytes[data_offset..data_offset + 8].try_into().unwrap(),
        ) as usize;

        if bytes.len() < data_offset + 8 + data_len {
            return Err(BootlegError::Serialization("Truncated payload data".into()));
        }

        let data = bytes[data_offset + 8..data_offset + 8 + data_len].to_vec();

        Ok(Self { filename, data })
    }
}

/// Dispersion scheduler that assigns micro-shards to slack slots deterministically
pub struct DispersionScheduler;

impl DispersionScheduler {
    /// Injects secret ciphertext into available slack slots using PRNG stream
    pub fn disperse(
        ciphertext: &[u8],
        slots: &[SlackSlot],
        prng_seed: &[u8; 32],
    ) -> Result<Vec<(SlackSlot, Vec<u8>)>> {
        let total_capacity: usize = slots.iter().map(|s| s.capacity).sum();
        let payload_len = ciphertext.len();

        // 4 bytes for length prefix + ciphertext
        let total_needed = 4 + payload_len;
        if total_needed > total_capacity {
            return Err(BootlegError::InsufficientCapacity {
                needed_bytes: total_needed,
                available_bytes: total_capacity,
                additional_files_needed: (total_needed - total_capacity).div_ceil(256),
            });
        }

        let mut rng = ChaCha20Rng::from_seed(*prng_seed);

        // Frame: [4-byte length ^ PRNG_mask | ciphertext]
        let mut stream = Vec::with_capacity(total_needed);
        let len_bytes = (payload_len as u32).to_le_bytes();
        let mut masked_len = [0u8; 4];
        let mut mask = [0u8; 4];
        rng.fill_bytes(&mut mask);
        for i in 0..4 {
            masked_len[i] = len_bytes[i] ^ mask[i];
        }
        stream.extend_from_slice(&masked_len);
        stream.extend_from_slice(ciphertext);

        // Distribute stream across slots
        let mut result = Vec::new();
        let mut stream_offset = 0;

        for slot in slots {
            if slot.capacity == 0 {
                continue;
            }

            let mut slot_data = vec![0u8; slot.capacity];
            let chunk_size = (slot.capacity).min(stream.len() - stream_offset);

            if chunk_size > 0 {
                slot_data[..chunk_size]
                    .copy_from_slice(&stream[stream_offset..stream_offset + chunk_size]);
                stream_offset += chunk_size;
            }

            // Fill any remaining bytes in slot with pseudo-random noise or zeroes to match cover
            if chunk_size < slot.capacity {
                rng.fill_bytes(&mut slot_data[chunk_size..]);
            }

            result.push((slot.clone(), slot_data));
        }

        Ok(result)
    }

    /// Reassembles ciphertext from carrier slack slots using PRNG stream
    pub fn assemble(
        slots_data: &[(SlackSlot, Vec<u8>)],
        prng_seed: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let mut rng = ChaCha20Rng::from_seed(*prng_seed);

        // Concatenate all slot data
        let mut combined = Vec::new();
        for (_, data) in slots_data {
            combined.extend_from_slice(data);
        }

        if combined.len() < 4 {
            return Err(BootlegError::AuthenticationFailed);
        }

        // Unmask length prefix
        let mut mask = [0u8; 4];
        rng.fill_bytes(&mut mask);
        let mut len_bytes = [0u8; 4];
        for i in 0..4 {
            len_bytes[i] = combined[i] ^ mask[i];
        }
        let payload_len = u32::from_le_bytes(len_bytes) as usize;

        // Sanity check length
        if payload_len == 0 || 4 + payload_len > combined.len() {
            return Err(BootlegError::AuthenticationFailed);
        }

        let ciphertext = combined[4..4 + payload_len].to_vec();
        Ok(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_payload_serialization() {
        let payload = SecretPayload::new("top_secret.txt", b"classified data content".to_vec());
        let bytes = payload.to_bytes();
        let decoded = SecretPayload::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.filename, "top_secret.txt");
        assert_eq!(decoded.data, b"classified data content");
    }

    #[test]
    fn test_disperse_and_assemble() {
        let secret_bytes = b"my encrypted super secret payload 1234567890";
        let slots = vec![
            SlackSlot {
                file_index: 0,
                archive_offset: 500,
                capacity: 32,
            },
            SlackSlot {
                file_index: 1,
                archive_offset: 1200,
                capacity: 64,
            },
        ];
        let seed = [77u8; 32];

        let dispersed = DispersionScheduler::disperse(secret_bytes, &slots, &seed).unwrap();
        assert_eq!(dispersed.len(), 2);

        let recovered = DispersionScheduler::assemble(&dispersed, &seed).unwrap();
        assert_eq!(recovered, secret_bytes);

        // Wrong seed fails
        let wrong_seed = [88u8; 32];
        assert!(DispersionScheduler::assemble(&dispersed, &wrong_seed).is_err());
    }
}
