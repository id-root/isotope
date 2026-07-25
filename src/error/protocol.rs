use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Payload size {0} exceeds PLAINTEXT_SIZE limit of {1}")]
    PayloadTooLarge(usize, usize),

    #[error("Serialized packet size {0} exceeds PLAINTEXT_SIZE limit of {1}")]
    PacketOverflow(usize, usize),

    #[error("Packet deserialization failed: {0}")]
    DeserializationFailed(String),

    #[error("Unsupported protocol version: {0}.{1}")]
    UnsupportedVersion(u8, u8),
}
