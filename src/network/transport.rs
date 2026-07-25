use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Duration;
use anyhow::Result;
use rand::Rng;
use super::http::{write_http_request, write_http_response, read_http_message};

pub async fn write_packet_as_client<W>(stream: &mut W, data: &[u8]) -> Result<()>
where W: AsyncWriteExt + Unpin
{
    let jitter_ms = rand::thread_rng().gen_range(0..30);
    tokio::time::sleep(Duration::from_millis(jitter_ms)).await;

    write_http_request(stream, data).await
}

pub async fn write_packet_as_server<W>(stream: &mut W, data: &[u8]) -> Result<()>
where W: AsyncWriteExt + Unpin
{
    let jitter_ms = rand::thread_rng().gen_range(0..30);
    tokio::time::sleep(Duration::from_millis(jitter_ms)).await;

    write_http_response(stream, data).await
}

pub async fn read_packet<R>(stream: &mut R) -> Result<Vec<u8>>
where R: AsyncReadExt + Unpin
{
    read_http_message(stream).await
}
