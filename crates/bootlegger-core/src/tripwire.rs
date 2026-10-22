use crate::error::{BootlegError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Metadata and cryptographic fingerprint of a carrier file
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarrierEntry {
    /// Relative normalized path within carrier (e.g. "docs/report.pdf")
    pub path: String,
    /// Exact file length in bytes
    pub size: u64,
    /// BLAKE3 bitwise hash of file content
    pub content_hash: [u8; 32],
    /// Modification timestamp (Unix epoch seconds)
    pub mtime: u64,
}

impl CarrierEntry {
    pub fn new(path: String, size: u64, content: &[u8], mtime: u64) -> Self {
        let content_hash = *blake3::hash(content).as_bytes();
        Self {
            path,
            size,
            content_hash,
            mtime,
        }
    }
}

/// Tripwire Anti-Tamper engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tripwire {
    /// Canonical 32-byte digest of entire carrier structure
    pub digest: [u8; 32],
    /// Number of carrier files verified
    pub file_count: usize,
}

impl Tripwire {
    /// Computes tripwire digest from a set of carrier entries
    pub fn compute(entries: &[CarrierEntry]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"BOOTLEGGER-TRIPWIRE-V1\n");
        hasher.update(&(entries.len() as u64).to_le_bytes());

        // Sort entries deterministically by path for canonical order
        let mut sorted = entries.to_vec();
        sorted.sort_by(|a, b| a.path.cmp(&b.path));

        for entry in &sorted {
            hasher.update(entry.path.as_bytes());
            hasher.update(b"\0");
            hasher.update(&entry.size.to_le_bytes());
            hasher.update(&entry.content_hash);
            hasher.update(&entry.mtime.to_le_bytes());
        }

        let digest = *hasher.finalize().as_bytes();
        Self {
            digest,
            file_count: entries.len(),
        }
    }

    /// Verifies current entries against recorded tripwire digest
    pub fn verify(
        expected_digest: &[u8; 32],
        original_entries: Option<&[CarrierEntry]>,
        current_entries: &[CarrierEntry],
    ) -> Result<()> {
        let current_tripwire = Self::compute(current_entries);

        if &current_tripwire.digest == expected_digest {
            return Ok(());
        }

        // Detailed tamper forensics if original entries are available
        let reason = if let Some(originals) = original_entries {
            let orig_map: BTreeMap<&str, &CarrierEntry> =
                originals.iter().map(|e| (e.path.as_str(), e)).collect();
            let curr_map: BTreeMap<&str, &CarrierEntry> =
                current_entries.iter().map(|e| (e.path.as_str(), e)).collect();

            let mut diffs = Vec::new();

            for (path, orig) in &orig_map {
                match curr_map.get(path) {
                    None => diffs.push(format!("File deleted: '{}'", path)),
                    Some(curr) => {
                        if orig.size != curr.size {
                            diffs.push(format!(
                                "File size modified: '{}' (was {} bytes, now {} bytes)",
                                path, orig.size, curr.size
                            ));
                        } else if orig.content_hash != curr.content_hash {
                            diffs.push(format!("Content tampered: '{}' (hash mismatch)", path));
                        } else if orig.mtime != curr.mtime {
                            diffs.push(format!(
                                "Timestamp altered: '{}' (was {}, now {})",
                                path, orig.mtime, curr.mtime
                            ));
                        }
                    }
                }
            }

            for path in curr_map.keys() {
                if !orig_map.contains_key(path) {
                    diffs.push(format!("Unauthorized file added: '{}'", path));
                }
            }

            if diffs.is_empty() {
                "Archive structure or file ordering altered".to_string()
            } else {
                diffs.join("; ")
            }
        } else {
            "Carrier hash mismatch: carrier archive was modified, re-packed, or inspected"
                .to_string()
        };

        Err(BootlegError::TamperDetected(reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tripwire_tamper_detection() {
        let entry1 = CarrierEntry::new("doc1.txt".into(), 10, b"hello text", 1000);
        let entry2 = CarrierEntry::new("doc2.txt".into(), 12, b"carrier file", 1001);

        let tripwire = Tripwire::compute(&[entry1.clone(), entry2.clone()]);

        // Unmodified check passes
        assert!(Tripwire::verify(
            &tripwire.digest,
            Some(&[entry1.clone(), entry2.clone()]),
            &[entry1.clone(), entry2.clone()]
        )
        .is_ok());

        // Altering one byte in content triggers tripwire
        let tampered_entry1 = CarrierEntry::new("doc1.txt".into(), 10, b"hello test", 1000);
        let res = Tripwire::verify(
            &tripwire.digest,
            Some(&[entry1.clone(), entry2.clone()]),
            &[tampered_entry1, entry2.clone()],
        );
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Content tampered"));

        // Deleting a file triggers tripwire
        let res_del = Tripwire::verify(
            &tripwire.digest,
            Some(&[entry1.clone(), entry2.clone()]),
            &[entry2.clone()],
        );
        assert!(res_del.is_err());
        assert!(res_del.unwrap_err().to_string().contains("File deleted"));
    }
}
