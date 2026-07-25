use anyhow::{Result, bail, Context};

pub fn parse_onion_address(addr: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        bail!("Address format must be hostname.onion:port");
    }
    let host = parts[0];
    let port = parts[1].parse::<u16>().context("Invalid port number")?;

    if !host.ends_with(".onion") {
        bail!("Host must be a .onion address");
    }
    Ok((host.to_string(), port))
}
