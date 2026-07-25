use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use anyhow::{Result, bail, Context};

pub async fn connect_socks5(proxy: SocketAddr, target_host: &str, target_port: u16) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await
        .context("Failed to connect to SOCKS5 proxy")?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf != [0x05, 0x00] { bail!("SOCKS5 auth rejected"); }

    let mut req = vec![0x05, 0x01, 0x00, 0x03, target_host.len() as u8];
    req.extend(target_host.as_bytes());
    req.extend(&target_port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;

    if head[1] != 0x00 {
        bail!("SOCKS5 connection failed. Error code: 0x{:02x}", head[1]);
    }

    match head[3] {
        0x01 => {
            let mut addr = [0u8; 6];
            stream.read_exact(&mut addr).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut addr = [0u8; 18];
            stream.read_exact(&mut addr).await?;
        }
        _ => bail!("Unknown SOCKS5 ATYP: 0x{:02x}", head[3]),
    }

    Ok(stream)
}

pub async fn connect_multi_hop(
    proxies: &[SocketAddr],
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    if proxies.is_empty() {
        bail!("At least one proxy required for multi-hop");
    }

    if proxies.len() == 1 {
        return connect_socks5(proxies[0], target_host, target_port).await;
    }

    let first_proxy = proxies[0];
    let mut stream = TcpStream::connect(first_proxy).await
        .context("Failed to connect to first hop")?;

    for (i, next_proxy) in proxies.iter().enumerate().skip(1) {
        let _next_host = next_proxy.ip().to_string();
        let next_port = next_proxy.port();

        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        if buf != [0x05, 0x00] {
            bail!("SOCKS5 auth rejected at hop {}", i);
        }

        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        match next_proxy.ip() {
            std::net::IpAddr::V4(ipv4) => {
                req.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                req[3] = 0x04;
                req.extend_from_slice(&ipv6.octets());
            }
        }
        req.extend(&next_port.to_be_bytes());
        stream.write_all(&req).await?;

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        if head[1] != 0x00 {
            bail!("SOCKS5 connection failed at hop {}. Error: 0x{:02x}", i, head[1]);
        }

        match head[3] {
            0x01 => { let mut addr = [0u8; 6]; stream.read_exact(&mut addr).await?; }
            0x04 => { let mut addr = [0u8; 18]; stream.read_exact(&mut addr).await?; }
            _ => bail!("Unexpected ATYP at hop {}", i),
        }
    }

    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf != [0x05, 0x00] {
        bail!("SOCKS5 auth rejected at final hop");
    }

    let mut req = vec![0x05, 0x01, 0x00, 0x03, target_host.len() as u8];
    req.extend(target_host.as_bytes());
    req.extend(&target_port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        bail!("Final connection failed. Error: 0x{:02x}", head[1]);
    }

    match head[3] {
        0x01 => { let mut addr = [0u8; 6]; stream.read_exact(&mut addr).await?; }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => { let mut addr = [0u8; 18]; stream.read_exact(&mut addr).await?; }
        _ => bail!("Unknown ATYP in final response"),
    }

    Ok(stream)
}
