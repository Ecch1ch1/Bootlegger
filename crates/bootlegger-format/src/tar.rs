use bootlegger_core::{
    accountant::DilutionAccountant,
    crypto::{CryptoEngine, NONCE_LEN, SALT_LEN, TAG_LEN},
    dispersion::{DispersionScheduler, SecretPayload, SlackSlot},
    error::{BootlegError, Result},
    tripwire::{CarrierEntry, Tripwire},
};
use std::io::{Cursor, Read, Write};

pub const TAR_BLOCK_SIZE: usize = 512;

/// A decoy file to be included in the carrier archive
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoyFile {
    pub path: String,
    pub content: Vec<u8>,
    pub mtime: u64,
    pub mode: u32,
}

impl DecoyFile {
    pub fn new(path: impl Into<String>, content: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            content,
            mtime: 1700000000,
            mode: 0o644,
        }
    }

    pub fn to_carrier_entry(&self) -> CarrierEntry {
        CarrierEntry::new(self.path.clone(), self.content.len() as u64, &self.content, self.mtime)
    }
}

/// Computes deterministic carrier salt from decoy metadata
pub fn compute_carrier_salt(entries: &[CarrierEntry]) -> [u8; SALT_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"BOOTLEGGER-CARRIER-SALT-V1\n");
    for entry in entries {
        hasher.update(entry.path.as_bytes());
        hasher.update(&entry.size.to_le_bytes());
        hasher.update(&entry.mtime.to_le_bytes());
    }
    let full = hasher.finalize();
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&full.as_bytes()[..SALT_LEN]);
    salt
}

/// Formats an octal field in a TAR header
fn write_octal(field: &mut [u8], value: u64) {
    let width = field.len().saturating_sub(1);
    let s = format!("{:0width$o}", value, width = width);
    let bytes = s.as_bytes();
    let flen = field.len();
    if bytes.len() >= flen {
        field[..flen - 1].copy_from_slice(&bytes[bytes.len() - (flen - 1)..]);
        field[flen - 1] = 0;
    } else {
        field[..bytes.len()].copy_from_slice(bytes);
        field[bytes.len()] = 0;
    }
}

/// Parses an octal field from a TAR header
fn read_octal(field: &[u8]) -> u64 {
    let s = String::from_utf8_lossy(field);
    let trimmed = s.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    if trimmed.is_empty() {
        return 0;
    }
    u64::from_str_radix(trimmed, 8).unwrap_or(0)
}

/// Builds a 512-byte POSIX USTAR header
fn create_tar_header(file: &DecoyFile) -> [u8; TAR_BLOCK_SIZE] {
    let mut block = [0u8; TAR_BLOCK_SIZE];

    // Name (0..100)
    let name_bytes = file.path.as_bytes();
    let name_len = name_bytes.len().min(100);
    block[..name_len].copy_from_slice(&name_bytes[..name_len]);

    // Mode (100..108)
    write_octal(&mut block[100..108], file.mode as u64);

    // UID (108..116)
    write_octal(&mut block[108..116], 1000);

    // GID (116..124)
    write_octal(&mut block[116..124], 1000);

    // Size (124..136)
    write_octal(&mut block[124..136], file.content.len() as u64);

    // Mtime (136..144)
    write_octal(&mut block[136..148], file.mtime);

    // Typeflag (156) - '0' = regular file
    block[156] = b'0';

    // Magic: "ustar\0" (257..263)
    block[257..263].copy_from_slice(b"ustar\0");

    // Version: "00" (263..265)
    block[263..265].copy_from_slice(b"00");

    // Uname: "user" (265..269)
    block[265..269].copy_from_slice(b"user");

    // Gname: "user" (297..301)
    block[297..301].copy_from_slice(b"user");

    // Checksum calculation: sum of all bytes in block with chksum field treated as ASCII spaces (0x20)
    block[148..156].fill(b' ');
    let checksum: u32 = block.iter().map(|&b| b as u32).sum();
    let chksum_str = format!("{:06o}\0 ", checksum);
    block[148..148 + chksum_str.len()].copy_from_slice(chksum_str.as_bytes());

    block
}

pub struct TarEngine;

impl TarEngine {
    /// Packs decoy files and injects encrypted secret into block slack spaces
    pub fn pack(
        decoys: &[DecoyFile],
        secret: &SecretPayload,
        password: &[u8],
        enable_tripwire: bool,
        max_dilution_ratio: Option<f64>,
    ) -> Result<Vec<u8>> {
        if decoys.is_empty() {
            return Err(BootlegError::InsufficientCapacity {
                needed_bytes: secret.data.len(),
                available_bytes: 0,
                additional_files_needed: 10,
            });
        }

        // 1. Build carrier entries and compute tripwire
        let entries: Vec<CarrierEntry> = decoys.iter().map(|d| d.to_carrier_entry()).collect();
        let tripwire = if enable_tripwire {
            Some(Tripwire::compute(&entries))
        } else {
            None
        };
        let tripwire_digest = tripwire.as_ref().map(|t| &t.digest);

        // 2. Compute carrier salt and derive keys
        let carrier_salt = compute_carrier_salt(&entries);
        let keys = CryptoEngine::derive_keys(password, &carrier_salt)?;

        // 3. Serialize secret message and check dilution budget
        let secret_bytes = secret.to_bytes();
        let needed_overhead = NONCE_LEN + TAG_LEN + 4; // Nonce + Tag + 4-byte length prefix
        let total_needed = secret_bytes.len() + needed_overhead;

        DilutionAccountant::assess(&entries, total_needed, max_dilution_ratio)?;

        // 4. Encrypt secret payload using derived keys
        let encrypted_bundle = CryptoEngine::encrypt_with_keys(
            &secret_bytes,
            &keys,
            tripwire_digest,
        )?;

        // 5. Compute slack slots for each file
        let mut slots = Vec::new();
        let mut running_offset: u64 = 0;

        for (idx, decoy) in decoys.iter().enumerate() {
            // Header block
            running_offset += TAR_BLOCK_SIZE as u64;

            let file_len = decoy.content.len();
            let remainder = file_len % TAR_BLOCK_SIZE;
            let slack_capacity = if remainder == 0 {
                0
            } else {
                TAR_BLOCK_SIZE - remainder
            };

            let slack_offset = running_offset + file_len as u64;
            slots.push(SlackSlot {
                file_index: idx,
                archive_offset: slack_offset,
                capacity: slack_capacity,
            });

            let total_file_blocks = file_len.div_ceil(TAR_BLOCK_SIZE);
            running_offset += (total_file_blocks * TAR_BLOCK_SIZE) as u64;
        }

        // 6. Disperse encrypted stream across slots
        let dispersed = DispersionScheduler::disperse(&encrypted_bundle, &slots, &keys.prng_seed)?;

        // 7. Write TAR archive
        let mut archive = Vec::with_capacity(running_offset as usize + 2 * TAR_BLOCK_SIZE);

        for (idx, decoy) in decoys.iter().enumerate() {
            // Write 512B header
            let header = create_tar_header(decoy);
            archive.write_all(&header)?;

            // Write content
            archive.write_all(&decoy.content)?;

            // Write slack (assigned shard + noise)
            let remainder = decoy.content.len() % TAR_BLOCK_SIZE;
            if remainder != 0 {
                let slack_len = TAR_BLOCK_SIZE - remainder;
                let slot_data = dispersed
                    .iter()
                    .find(|(s, _)| s.file_index == idx)
                    .map(|(_, d)| d.as_slice())
                    .unwrap_or(&[]);

                if slot_data.len() == slack_len {
                    archive.write_all(slot_data)?;
                } else {
                    // Fallback to zeroes
                    archive.write_all(&vec![0u8; slack_len])?;
                }
            }
        }

        // Write End-of-Archive (two 512B zero blocks = 1024 bytes)
        archive.write_all(&[0u8; 2 * TAR_BLOCK_SIZE])?;

        Ok(archive)
    }

    /// Unpacks and recovers secret payload from a Bootlegger TAR archive
    pub fn unpack_secret(
        archive_bytes: &[u8],
        password: &[u8],
    ) -> Result<(SecretPayload, Option<Tripwire>)> {
        if archive_bytes.len() < TAR_BLOCK_SIZE * 3 {
            return Err(BootlegError::AuthenticationFailed);
        }

        // 1. Scan TAR blocks and extract decoy file metadata and slack data
        let mut cursor = Cursor::new(archive_bytes);
        let mut entries = Vec::new();
        let mut slots_data = Vec::new();
        let mut file_index = 0;

        let total_len = archive_bytes.len();

        loop {
            let current_pos = cursor.position() as usize;
            if current_pos + TAR_BLOCK_SIZE > total_len {
                break;
            }

            let mut header = [0u8; TAR_BLOCK_SIZE];
            if cursor.read_exact(&mut header).is_err() {
                break;
            }

            // Check if end of archive (all zeroes)
            if header.iter().all(|&b| b == 0) {
                break;
            }

            // Parse header
            let name = String::from_utf8_lossy(&header[0..100])
                .trim_matches('\0')
                .to_string();
            let size = read_octal(&header[124..136]) as usize;
            let mtime = read_octal(&header[136..148]);

            // Read file content
            let mut content = vec![0u8; size];
            if cursor.read_exact(&mut content).is_err() {
                return Err(BootlegError::AuthenticationFailed);
            }

            // Record carrier entry
            entries.push(CarrierEntry::new(name, size as u64, &content, mtime));

            // Read slack padding up to next 512B boundary
            let remainder = size % TAR_BLOCK_SIZE;
            if remainder != 0 {
                let slack_capacity = TAR_BLOCK_SIZE - remainder;
                let mut slack_buf = vec![0u8; slack_capacity];
                let slack_offset = cursor.position();

                if cursor.read_exact(&mut slack_buf).is_err() {
                    return Err(BootlegError::AuthenticationFailed);
                }

                let slot = SlackSlot {
                    file_index,
                    archive_offset: slack_offset,
                    capacity: slack_capacity,
                };
                slots_data.push((slot, slack_buf));
            }

            file_index += 1;
        }

        if entries.is_empty() {
            return Err(BootlegError::AuthenticationFailed);
        }

        // 2. Compute carrier salt and derive keys
        let carrier_salt = compute_carrier_salt(&entries);
        let keys = CryptoEngine::derive_keys(password, &carrier_salt)?;

        // 3. Reassemble ciphertext bundle
        let bundle = DispersionScheduler::assemble(&slots_data, &keys.prng_seed)?;

        // 4. Decrypt with candidate Tripwire
        let candidate_tripwire = Tripwire::compute(&entries);

        // Try decrypt with Tripwire active first
        let (decrypted_bytes, tripwire_info) = match CryptoEngine::decrypt_with_keys(
            &bundle,
            &keys,
            Some(&candidate_tripwire.digest),
        ) {
            Ok(bytes) => (bytes, Some(candidate_tripwire)),
            Err(_) => {
                // Try without Tripwire
                match CryptoEngine::decrypt_with_keys(&bundle, &keys, None) {
                    Ok(bytes) => (bytes, None),
                    Err(_) => {
                        return Err(BootlegError::AuthenticationFailed);
                    }
                }
            }
        };

        let secret = SecretPayload::from_bytes(&decrypted_bytes)?;
        Ok((secret, tripwire_info))
    }

    /// Normal extraction of all decoy files from the archive (standard tar extraction)
    pub fn extract_decoys(archive_bytes: &[u8]) -> Result<Vec<DecoyFile>> {
        let mut cursor = Cursor::new(archive_bytes);
        let mut decoys = Vec::new();
        let total_len = archive_bytes.len();

        loop {
            let current_pos = cursor.position() as usize;
            if current_pos + TAR_BLOCK_SIZE > total_len {
                break;
            }

            let mut header = [0u8; TAR_BLOCK_SIZE];
            if cursor.read_exact(&mut header).is_err() {
                break;
            }

            if header.iter().all(|&b| b == 0) {
                break;
            }

            let path = String::from_utf8_lossy(&header[0..100])
                .trim_matches('\0')
                .to_string();
            let mode = read_octal(&header[100..108]) as u32;
            let size = read_octal(&header[124..136]) as usize;
            let mtime = read_octal(&header[136..148]);

            let mut content = vec![0u8; size];
            cursor.read_exact(&mut content)?;

            let remainder = size % TAR_BLOCK_SIZE;
            if remainder != 0 {
                let pad = TAR_BLOCK_SIZE - remainder;
                let mut dummy = vec![0u8; pad];
                cursor.read_exact(&mut dummy)?;
            }

            decoys.push(DecoyFile {
                path,
                content,
                mtime,
                mode,
            });
        }

        Ok(decoys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tar_pack_and_unpack_roundtrip() {
        let mut decoys = Vec::new();
        for i in 0..10 {
            let size = 1500 + i * 173;
            let content = vec![(i as u8) + 65; size];
            decoys.push(DecoyFile::new(format!("doc_{}.txt", i), content));
        }

        let secret = SecretPayload::new("confidential_budget.pdf", b"TOP SECRET FINANCIAL BUDGET 2027".to_vec());
        let password = b"ultra-secure-passphrase-2027";

        // Pack with Tripwire active
        let tar_archive = TarEngine::pack(&decoys, &secret, password, true, Some(0.10)).unwrap();
        assert!(tar_archive.len() > 0);

        // Unpack secret
        let (recovered_secret, tripwire) = TarEngine::unpack_secret(&tar_archive, password).unwrap();
        assert_eq!(recovered_secret.filename, "confidential_budget.pdf");
        assert_eq!(recovered_secret.data, b"TOP SECRET FINANCIAL BUDGET 2027");
        assert!(tripwire.is_some());

        // Extract decoys normally (guaranteeing bit-for-bit integrity of cover files)
        let extracted_decoys = TarEngine::extract_decoys(&tar_archive).unwrap();
        assert_eq!(extracted_decoys.len(), decoys.len());
        for (orig, ext) in decoys.iter().zip(extracted_decoys.iter()) {
            assert_eq!(orig.path, ext.path);
            assert_eq!(orig.content, ext.content);
        }

        // Wrong password fails
        assert!(TarEngine::unpack_secret(&tar_archive, b"wrong-pass").is_err());
    }

    #[test]
    fn test_tar_tripwire_tamper_fails_decryption() {
        let mut decoys = Vec::new();
        for i in 0..8 {
            decoys.push(DecoyFile::new(format!("file_{}.dat", i), vec![0x42; 1000 + i * 50]));
        }

        let secret = SecretPayload::new("secret.key", b"SUPER_SECRET_KEY".to_vec());
        let password = b"tripwire-guard-pass";

        let mut archive = TarEngine::pack(&decoys, &secret, password, true, Some(0.10)).unwrap();

        // Tamper with one byte inside the first file's content
        archive[512] ^= 0xFF;

        // Unpack must fail because Tripwire detects tamper!
        let res = TarEngine::unpack_secret(&archive, password);
        assert!(res.is_err());
    }
}
