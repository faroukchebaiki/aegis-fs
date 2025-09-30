use anyhow::{Context, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

#[derive(Debug)]
pub struct Erasure {
    inner: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
}

impl Erasure {
    /// Creates a new Reed–Solomon encoder/decoder with `k` data and `m` parity shards.
    ///
    /// # Errors
    /// Returns an error if the encoder cannot be constructed.
    pub fn new(k: u8, m: u8) -> Result<Self> {
        let data_shards = k as usize;
        let parity_shards = m as usize;
        anyhow::ensure!(data_shards > 0, "k must be > 0");
        anyhow::ensure!(parity_shards > 0, "m must be > 0");
        let inner = ReedSolomon::new(data_shards, parity_shards)
            .context("constructing Reed-Solomon encoder")?;
        Ok(Self {
            inner,
            data_shards,
            parity_shards,
        })
    }

    /// Splits ciphertext into evenly sized shards and computes parity shards.
    ///
    /// # Errors
    /// Returns an error if the encoding operation fails.
    pub fn encode(&self, ciphertext: &[u8]) -> Result<(Vec<Vec<u8>>, usize)> {
        let shard_len = ciphertext.len().div_ceil(self.data_shards);
        let shard_len = shard_len.max(1);
        let total_shards = self.data_shards + self.parity_shards;
        let mut shards: Vec<Vec<u8>> = (0..total_shards).map(|_| vec![0_u8; shard_len]).collect();

        for (i, chunk) in ciphertext.chunks(shard_len).enumerate() {
            shards[i][..chunk.len()].copy_from_slice(chunk);
        }

        self.inner
            .encode(&mut shards)
            .context("encoding data shards")?;
        Ok((shards, shard_len))
    }

    /// Reconstructs ciphertext using the available shards, interpolating missing data when parity is present.
    ///
    /// # Errors
    /// Returns an error if shard reconstruction fails.
    ///
    /// # Panics
    /// Panics if reconstruction succeeds yet returns missing data shards, which should be impossible.
    pub fn reconstruct(
        &self,
        mut shards: Vec<Option<Vec<u8>>>,
        original_len: usize,
    ) -> Result<Vec<u8>> {
        anyhow::ensure!(
            shards.len() == self.data_shards + self.parity_shards,
            "unexpected shard count"
        );

        self.inner
            .reconstruct(&mut shards)
            .context("reconstructing shards")?;

        let mut ciphertext = Vec::with_capacity(original_len);
        for shard in shards.into_iter().take(self.data_shards) {
            let shard = shard.expect("reconstruction to fill shards");
            let remaining = original_len.saturating_sub(ciphertext.len());
            let take = remaining.min(shard.len());
            ciphertext.extend_from_slice(&shard[..take]);
            if ciphertext.len() >= original_len {
                break;
            }
        }
        ciphertext.truncate(original_len);
        Ok(ciphertext)
    }

    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let erasure = Erasure::new(4, 2).expect("coder");
        let data = b"hello erasure".to_vec();
        let (mut shards, _) = erasure.encode(&data).expect("encode");

        // Drop one parity shard and ensure reconstruction succeeds
        shards[4].fill(0);
        shards[5].fill(0);
        let shard_options: Vec<Option<Vec<u8>>> = shards
            .into_iter()
            .enumerate()
            .map(|(idx, shard)| if idx == 4 { None } else { Some(shard) })
            .collect();
        let reconstructed = erasure
            .reconstruct(shard_options, data.len())
            .expect("reconstruct");
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn fails_when_too_many_shards_missing() {
        let erasure = Erasure::new(3, 2).expect("coder");
        let data = b"payload".to_vec();
        let (shards, _) = erasure.encode(&data).expect("encode");
        let shard_options: Vec<Option<Vec<u8>>> = shards
            .into_iter()
            .enumerate()
            .map(|(idx, shard)| if idx < 3 { None } else { Some(shard) })
            .collect();
        let err = erasure.reconstruct(shard_options, data.len()).unwrap_err();
        assert!(format!("{err}").contains("reconstructing"));
    }
}
