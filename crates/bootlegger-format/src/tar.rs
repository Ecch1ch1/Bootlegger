use bootlegger_core::{
    accountant::DilutionAccountant,
    crypto::{CryptoEngine, DerivedKeys, NONCE_LEN, SALT_LEN, TAG_LEN},
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

    // Mtime (136..148)
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
    /// Packs decoy files and injects single encrypted secret into block slack spaces
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

        let entries: Vec<CarrierEntry> = decoys.iter().map(|d| d.to_carrier_entry()).collect();
        let tripwire = if enable_tripwire {
            Some(Tripwire::compute(&entries))
        } else {
            None
        };
        let tripwire_digest = tripwire.as_ref().map(|t| &t.digest);

        let carrier_salt = compute_carrier_salt(&entries);
        let keys = CryptoEngine::derive_keys(password, &carrier_salt)?;

        let secret_bytes = secret.to_bytes();
        let needed_overhead = NONCE_LEN + TAG_LEN + 4;
        let total_needed = secret_bytes.len() + needed_overhead;

        DilutionAccountant::assess(&entries, total_needed, max_dilution_ratio)?;

        let encrypted_bundle = CryptoEngine::encrypt_with_keys(
            &secret_bytes,
            &keys,
            tripwire_digest,
        )?;

        let mut slots = Vec::new();
        let mut running_offset: u64 = 0;

        for (idx, decoy) in decoys.iter().enumerate() {
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

            running_offset += file_len.div_ceil(TAR_BLOCK_SIZE) as u64 * TAR_BLOCK_SIZE as u64;
        }

        let dispersed = DispersionScheduler::disperse(&encrypted_bundle, &slots, &keys.prng_seed)?;

        let mut archive = Vec::with_capacity(running_offset as usize + 2 * TAR_BLOCK_SIZE);

        for (idx, decoy) in decoys.iter().enumerate() {
            let header = create_tar_header(decoy);
            archive.write_all(&header)?;
            archive.write_all(&decoy.content)?;

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
                    archive.write_all(&vec![0u8; slack_len])?;
                }
            }
        }

        // Two 512B zero blocks (EOA)
        archive.write_all(&[0u8; 2 * TAR_BLOCK_SIZE])?;

        Ok(archive)
    }

    /// Packs decoy files with two layers of secrets: Primary (Master) and Duress (Coercion)
    pub fn pack_dual(
        decoys: &[DecoyFile],
        primary_secret: &SecretPayload,
        primary_password: &[u8],
        duress_secret: &SecretPayload,
        duress_password: &[u8],
        enable_tripwire: bool,
        max_dilution_ratio: Option<f64>,
    ) -> Result<Vec<u8>> {
        if decoys.is_empty() {
            return Err(BootlegError::InsufficientCapacity {
                needed_bytes: primary_secret.data.len() + duress_secret.data.len(),
                available_bytes: 0,
                additional_files_needed: 10,
            });
        }

        let entries: Vec<CarrierEntry> = decoys.iter().map(|d| d.to_carrier_entry()).collect();
        let tripwire = if enable_tripwire {
            Some(Tripwire::compute(&entries))
        } else {
            None
        };
        let tripwire_digest = tripwire.as_ref().map(|t| &t.digest);

        let carrier_salt = compute_carrier_salt(&entries);
        let keys_prim = CryptoEngine::derive_keys(primary_password, &carrier_salt)?;
        let keys_duress = CryptoEngine::derive_keys(duress_password, &carrier_salt)?;

        let prim_bytes = primary_secret.to_bytes();
        let duress_bytes = duress_secret.to_bytes();
        let overhead = NONCE_LEN + TAG_LEN + 4;
        let total_combined = prim_bytes.len() + duress_bytes.len() + 2 * overhead;

        DilutionAccountant::assess(&entries, total_combined, max_dilution_ratio)?;

        let bundle_prim = CryptoEngine::encrypt_with_keys(&prim_bytes, &keys_prim, tripwire_digest)?;
        let bundle_duress = CryptoEngine::encrypt_with_keys(&duress_bytes, &keys_duress, tripwire_digest)?;

        let mut slots_a = Vec::new();
        let mut slots_b = Vec::new();
        let mut running_offset: u64 = 0;

        for (idx, decoy) in decoys.iter().enumerate() {
            running_offset += TAR_BLOCK_SIZE as u64;

            let file_len = decoy.content.len();
            let remainder = file_len % TAR_BLOCK_SIZE;
            let slack_capacity = if remainder == 0 { 0 } else { TAR_BLOCK_SIZE - remainder };

            let cap_a = slack_capacity / 2;
            let cap_b = slack_capacity - cap_a;

            let slack_offset = running_offset + file_len as u64;
            slots_a.push(SlackSlot {
                file_index: idx,
                archive_offset: slack_offset,
                capacity: cap_a,
            });
            slots_b.push(SlackSlot {
                file_index: idx,
                archive_offset: slack_offset + cap_a as u64,
                capacity: cap_b,
            });

            running_offset += file_len.div_ceil(TAR_BLOCK_SIZE) as u64 * TAR_BLOCK_SIZE as u64;
        }

        let dispersed_a = DispersionScheduler::disperse(&bundle_prim, &slots_a, &keys_prim.prng_seed)?;
        let dispersed_b = DispersionScheduler::disperse(&bundle_duress, &slots_b, &keys_duress.prng_seed)?;

        let mut archive = Vec::with_capacity(running_offset as usize + 2 * TAR_BLOCK_SIZE);

        for (idx, decoy) in decoys.iter().enumerate() {
            let header = create_tar_header(decoy);
            archive.write_all(&header)?;
            archive.write_all(&decoy.content)?;

            let remainder = decoy.content.len() % TAR_BLOCK_SIZE;
            if remainder != 0 {
                let part_a = dispersed_a
                    .iter()
                    .find(|(s, _)| s.file_index == idx)
                    .map(|(_, d)| d.as_slice())
                    .unwrap_or(&[]);
                let part_b = dispersed_b
                    .iter()
                    .find(|(s, _)| s.file_index == idx)
                    .map(|(_, d)| d.as_slice())
                    .unwrap_or(&[]);

                archive.write_all(part_a)?;
                archive.write_all(part_b)?;
            }
        }

        archive.write_all(&[0u8; 2 * TAR_BLOCK_SIZE])?;
        Ok(archive)
    }

    /// Helper to attempt decrypting candidate slot data with Tripwire options
    fn try_decrypt_candidate(
        slots_data: &[(SlackSlot, Vec<u8>)],
        keys: &DerivedKeys,
        candidate_tripwire: &Tripwire,
    ) -> Option<(SecretPayload, Option<Tripwire>)> {
        let bundle = DispersionScheduler::assemble(slots_data, &keys.prng_seed).ok()?;

        // 1. Try with Tripwire AAD active
        if let Ok(decrypted) = CryptoEngine::decrypt_with_keys(
            &bundle,
            keys,
            Some(&candidate_tripwire.digest),
        ) {
            if let Ok(secret) = SecretPayload::from_bytes(&decrypted) {
                return Some((secret, Some(candidate_tripwire.clone())));
            }
        }

        // 2. Try without Tripwire AAD
        if let Ok(decrypted) = CryptoEngine::decrypt_with_keys(&bundle, keys, None) {
            if let Ok(secret) = SecretPayload::from_bytes(&decrypted) {
                return Some((secret, None));
            }
        }

        None
    }

    /// Unpacks and recovers secret payload from a Bootlegger TAR archive.
    /// Transparently resolves Single, Primary, or Duress secret tiers.
    pub fn unpack_secret(
        archive_bytes: &[u8],
        password: &[u8],
    ) -> Result<(SecretPayload, Option<Tripwire>)> {
        if archive_bytes.len() < TAR_BLOCK_SIZE * 3 {
            return Err(BootlegError::AuthenticationFailed);
        }

        let mut cursor = Cursor::new(archive_bytes);
        let mut entries = Vec::new();
        let mut full_slots_data = Vec::new();
        let mut part_a_slots_data = Vec::new();
        let mut part_b_slots_data = Vec::new();
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

            if header.iter().all(|&b| b == 0) {
                break;
            }

            let name = String::from_utf8_lossy(&header[0..100])
                .trim_matches('\0')
                .to_string();
            let size = read_octal(&header[124..136]) as usize;
            let mtime = read_octal(&header[136..148]);

            let mut content = vec![0u8; size];
            if cursor.read_exact(&mut content).is_err() {
                return Err(BootlegError::AuthenticationFailed);
            }

            entries.push(CarrierEntry::new(name, size as u64, &content, mtime));

            let remainder = size % TAR_BLOCK_SIZE;
            if remainder != 0 {
                let slack_capacity = TAR_BLOCK_SIZE - remainder;
                let mut slack_buf = vec![0u8; slack_capacity];
                let slack_offset = cursor.position();

                if cursor.read_exact(&mut slack_buf).is_err() {
                    return Err(BootlegError::AuthenticationFailed);
                }

                // Full slot (for Single secret mode)
                full_slots_data.push((
                    SlackSlot {
                        file_index,
                        archive_offset: slack_offset,
                        capacity: slack_capacity,
                    },
                    slack_buf.clone(),
                ));

                // Partitioned sub-slots A & B (for Dual / Duress mode)
                let cap_a = slack_capacity / 2;
                let cap_b = slack_capacity - cap_a;

                part_a_slots_data.push((
                    SlackSlot {
                        file_index,
                        archive_offset: slack_offset,
                        capacity: cap_a,
                    },
                    slack_buf[..cap_a].to_vec(),
                ));

                part_b_slots_data.push((
                    SlackSlot {
                        file_index,
                        archive_offset: slack_offset + cap_a as u64,
                        capacity: cap_b,
                    },
                    slack_buf[cap_a..].to_vec(),
                ));
            }

            file_index += 1;
        }

        if entries.is_empty() {
            return Err(BootlegError::AuthenticationFailed);
        }

        let carrier_salt = compute_carrier_salt(&entries);
        let keys = CryptoEngine::derive_keys(password, &carrier_salt)?;
        let candidate_tripwire = Tripwire::compute(&entries);

        // Candidate 1: Full slack allocation (Single secret mode)
        if let Some(res) = Self::try_decrypt_candidate(&full_slots_data, &keys, &candidate_tripwire) {
            return Ok(res);
        }

        // Candidate 2: Partition A (Primary secret in Dual mode)
        if let Some(res) = Self::try_decrypt_candidate(&part_a_slots_data, &keys, &candidate_tripwire) {
            return Ok(res);
        }

        // Candidate 3: Partition B (Duress secret in Dual mode)
        if let Some(res) = Self::try_decrypt_candidate(&part_b_slots_data, &keys, &candidate_tripwire) {
            return Ok(res);
        }

        Err(BootlegError::AuthenticationFailed)
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

        let tar_archive = TarEngine::pack(&decoys, &secret, password, true, Some(0.10)).unwrap();
        assert!(tar_archive.len() > 0);

        let (recovered_secret, tripwire) = TarEngine::unpack_secret(&tar_archive, password).unwrap();
        assert_eq!(recovered_secret.filename, "confidential_budget.pdf");
        assert_eq!(recovered_secret.data, b"TOP SECRET FINANCIAL BUDGET 2027");
        assert!(tripwire.is_some());

        let extracted_decoys = TarEngine::extract_decoys(&tar_archive).unwrap();
        assert_eq!(extracted_decoys.len(), decoys.len());
        for (orig, ext) in decoys.iter().zip(extracted_decoys.iter()) {
            assert_eq!(orig.path, ext.path);
            assert_eq!(orig.content, ext.content);
        }

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

        archive[512] ^= 0xFF;

        let res = TarEngine::unpack_secret(&archive, password);
        assert!(res.is_err());
    }

    #[test]
    fn test_tar_duress_dual_secret_mode() {
        let mut decoys = Vec::new();
        for i in 0..12 {
            let size = 1400 + i * 111;
            decoys.push(DecoyFile::new(format!("project_file_{}.rs", i), vec![0x33; size]));
        }

        let real_secret = SecretPayload::new("real_master_key.pem", b"REAL_PRIVATE_KEY_DATA_00112233".to_vec());
        let real_pass = b"MasterPasswordSuperSecret";

        let duress_secret = SecretPayload::new("innocent_draft.txt", b"Harmless meeting notes for the boss".to_vec());
        let duress_pass = b"CoercedDuressPassword";

        let archive = TarEngine::pack_dual(
            &decoys,
            &real_secret,
            real_pass,
            &duress_secret,
            duress_pass,
            true,
            Some(0.15),
        ).unwrap();

        // 1. Unpack with Master password -> recovers REAL secret
        let (rec_real, tw1) = TarEngine::unpack_secret(&archive, real_pass).unwrap();
        assert_eq!(rec_real.filename, "real_master_key.pem");
        assert_eq!(rec_real.data, b"REAL_PRIVATE_KEY_DATA_00112233");
        assert!(tw1.is_some());

        // 2. Unpack with Duress password -> recovers DURESS secret seamlessly!
        let (rec_duress, tw2) = TarEngine::unpack_secret(&archive, duress_pass).unwrap();
        assert_eq!(rec_duress.filename, "innocent_draft.txt");
        assert_eq!(rec_duress.data, b"Harmless meeting notes for the boss");
        assert!(tw2.is_some());

        // 3. Wrong password -> fails
        assert!(TarEngine::unpack_secret(&archive, b"completely_wrong_pass").is_err());
    }
}
