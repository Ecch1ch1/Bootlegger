use crate::error::{BootlegError, Result};
use crate::tripwire::CarrierEntry;
use serde::{Deserialize, Serialize};

/// Default maximum safe dilution ratio (secret cannot exceed 3% of total carrier payload size)
pub const DEFAULT_MAX_DILUTION_RATIO: f64 = 0.03;

/// Evaluated metrics of a carrier archive / file set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrierCapacity {
    /// Total number of decoy files in the carrier
    pub file_count: usize,
    /// Total byte size of all decoy files
    pub total_decoy_bytes: usize,
    /// Estimated safe slack / capacity in bytes
    pub safe_capacity_bytes: usize,
    /// Secret payload size requested to conceal
    pub secret_payload_bytes: usize,
    /// Actual dilution ratio for this secret (secret / total_decoy)
    pub effective_dilution_ratio: f64,
}

/// Dilution and capacity accountant enforcing strict stealth budgets
pub struct DilutionAccountant;

impl DilutionAccountant {
    /// Assesses whether carrier files provide sufficient cover volume to conceal the secret.
    ///
    /// Principle: The decoy media must be large enough to dilute the secret so that
    /// the relative change in size and entropy is statistically negligible.
    /// "Just enough or more, but never less."
    pub fn assess(
        entries: &[CarrierEntry],
        secret_bytes: usize,
        max_ratio: Option<f64>,
    ) -> Result<CarrierCapacity> {
        let max_dilution = max_ratio.unwrap_or(DEFAULT_MAX_DILUTION_RATIO);
        let file_count = entries.len();

        if file_count == 0 {
            return Err(BootlegError::InsufficientCapacity {
                needed_bytes: secret_bytes,
                available_bytes: 0,
                additional_files_needed: 10,
            });
        }

        let total_decoy_bytes: usize = entries.iter().map(|e| e.size as usize).sum();

        // Safe capacity is determined by dilution ratio budget
        // plus natural block slack (TAR pads to 512-byte blocks)
        let natural_slack: usize = entries
            .iter()
            .map(|e| {
                let s = e.size as usize;
                let remainder = s % 512;
                if remainder == 0 {
                    0
                } else {
                    512 - remainder
                }
            })
            .sum();

        // Safe capacity is the maximum safe stealth dilution budget (e.g. 3% of total cover volume)
        // or the natural block slack, whichever is larger.
        let ratio_budget = (total_decoy_bytes as f64 * max_dilution) as usize;
        let safe_capacity_bytes = natural_slack.max(ratio_budget);

        if secret_bytes > safe_capacity_bytes {
            let deficit = secret_bytes - safe_capacity_bytes;
            let avg_file_size = (total_decoy_bytes / file_count).max(1024);
            let safe_per_file = ((avg_file_size as f64 * max_dilution) as usize).max(64);
            let additional_files = deficit.div_ceil(safe_per_file);

            return Err(BootlegError::InsufficientCapacity {
                needed_bytes: secret_bytes,
                available_bytes: safe_capacity_bytes,
                additional_files_needed: additional_files.max(1),
            });
        }

        let effective_dilution_ratio = if total_decoy_bytes > 0 {
            secret_bytes as f64 / total_decoy_bytes as f64
        } else {
            1.0
        };

        Ok(CarrierCapacity {
            file_count,
            total_decoy_bytes,
            safe_capacity_bytes,
            secret_payload_bytes: secret_bytes,
            effective_dilution_ratio,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilution_capacity_sufficient() {
        let entries = vec![
            CarrierEntry::new("a.pdf".into(), 100_000, &vec![0u8; 100_000], 100),
            CarrierEntry::new("b.pdf".into(), 200_000, &vec![0u8; 200_000], 101),
        ];

        // Secret of 2KB in 300KB carrier (~0.6% ratio) should comfortably pass
        let res = DilutionAccountant::assess(&entries, 2048, Some(0.03));
        assert!(res.is_ok());
        let cap = res.unwrap();
        assert_eq!(cap.secret_payload_bytes, 2048);
        assert!(cap.effective_dilution_ratio < 0.03);
    }

    #[test]
    fn test_dilution_capacity_insufficient_refuses() {
        let entries = vec![
            CarrierEntry::new("small.txt".into(), 500, &vec![0u8; 500], 100),
        ];

        // 50KB secret in a 500-byte carrier is impossible and dangerous
        let res = DilutionAccountant::assess(&entries, 50_000, Some(0.03));
        assert!(res.is_err());
        match res.unwrap_err() {
            BootlegError::InsufficientCapacity { needed_bytes, available_bytes, additional_files_needed } => {
                assert_eq!(needed_bytes, 50_000);
                assert!(available_bytes < 50_000);
                assert!(additional_files_needed > 0);
            }
            _ => panic!("Expected InsufficientCapacity error"),
        }
    }
}
