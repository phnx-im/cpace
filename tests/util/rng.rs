//! Deterministic RNG for driving the protocol with fixed test scalars.

/// Replays a fixed byte sequence, so protocol runs can be driven with the
/// draft's `ya`/`yb` scalars. The vectors' scalars already have their top
/// four bits clear, so the sampling mask leaves them unchanged.
pub struct FixedRng(pub Vec<u8>);

impl rand_core::TryRng for FixedRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let taken: Vec<u8> = self.0.drain(..dst.len()).collect();
        dst.copy_from_slice(&taken);
        Ok(())
    }
}

// CryptoRng follows from the blanket impl for TryCryptoRng<Error = Infallible>.
impl rand_core::TryCryptoRng for FixedRng {}
