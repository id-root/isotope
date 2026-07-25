use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::{Result, bail, Context};
use crate::protocol::HttpWrapper;

pub async fn write_http_request<W>(stream: &mut W, data: &[u8]) -> Result<()>
where W: AsyncWriteExt + Unpin
{
    let packet = HttpWrapper::wrap_request(data);
    stream.write_all(&packet).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn write_http_response<W>(stream: &mut W, data: &[u8]) -> Result<()>
where W: AsyncWriteExt + Unpin
{
    let packet = HttpWrapper::wrap_response(data);
    stream.write_all(&packet).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_http_message<R>(stream: &mut R) -> Result<Vec<u8>>
where R: AsyncReadExt + Unpin
{
    let mut header_buf = Vec::new();
    let mut byte = [0u8; 1];
    let max_header_size = 2048;

    loop {
        if stream.read_exact(&mut byte).await.is_err() {
            bail!("Connection closed while reading headers");
        }
        header_buf.push(byte[0]);

        if header_buf.len() > max_header_size {
            bail!("HTTP Headers too large");
        }

        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let header_str = String::from_utf8_lossy(&header_buf);

    let content_length = header_str.lines()
        .find(|line| line.to_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|val| val.trim().parse::<usize>().ok())
        .context("Missing or Invalid Content-Length")?;

    let mut body = vec![0u8; content_length];
    stream.read_exact(&mut body).await?;

    Ok(body)
}
