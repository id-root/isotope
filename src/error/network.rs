use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Failed to connect to SOCKS5 proxy: {0}")]
    ProxyConnectionFailed(String),

    #[error("SOCKS5 authentication rejected")]
    Socks5AuthRejected,

    #[error("SOCKS5 connection failed with error code 0x{0:02x}")]
    Socks5Error(u8),

    #[error("Unknown SOCKS5 ATYP: 0x{0:02x}")]
    UnknownAtyp(u8),

    #[error("Multi-hop requires at least one proxy")]
    EmptyProxyChain,

    #[error("Address format must be hostname.onion:port (got: {0})")]
    InvalidOnionAddress(String),

    #[error("HTTP header parsing failed: {0}")]
    HttpHeaderError(&'static str),

    #[error("Missing or invalid Content-Length header")]
    InvalidContentLength,
}
