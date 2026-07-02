//! Error types for protocol and message-parsing failures.

/// Failure of a CPace protocol step.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The peer's public element failed to decode, or the shared point K
    /// would be the neutral element. The draft (section 9) requires an
    /// abort in both cases; we deliberately do not distinguish them.
    #[error("invalid peer public element")]
    InvalidPeerElement,
    /// The peer's wire message is malformed.
    #[error("malformed message: {0}")]
    Message(#[from] MsgError),
}

/// Failure to parse a CPace wire message.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MsgError {
    /// The input ended before a complete field was read.
    #[error("truncated input")]
    Truncated,
    /// A length prefix used a redundant, non-minimal LEB128 encoding.
    #[error("non-minimal length encoding")]
    NonMinimalLength,
    /// A length prefix does not fit in `usize`.
    #[error("length exceeds limit")]
    LengthOverflow,
    /// The group element field is not exactly 32 bytes.
    #[error("group element must be 32 bytes")]
    BadElementLength,
    /// Extra bytes followed the associated-data field.
    #[error("trailing bytes after message")]
    TrailingBytes,
}
