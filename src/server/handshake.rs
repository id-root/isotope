use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;
use anyhow::{Result, anyhow};
use snow::Builder;
use base64::prelude::*;
use blake3::Hasher;
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{PublicKey, Ciphertext, SharedSecret};

use crate::crypto::{Identity, NoiseSession};
use crate::protocol::{IsotopePacket, WireMessage};
use crate::network::{read_packet, write_packet_as_server};
use crate::config::defaults::{HANDSHAKE_TIMEOUT_SEC, READ_TIMEOUT_SEC};

pub async fn perform_server_handshake(
    stream: &mut TcpStream,
    id: &Identity,
    _addr: SocketAddr,
) -> Result<(Arc<Mutex<NoiseSession>>, String)> {
    let builder = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse()?);
    let mut handshake = builder.local_private_key(&id.keypair.private).build_responder()?;
    let mut buf = vec![0u8; 65535];

    let msg = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_packet(stream)).await??;
    handshake.read_message(&msg, &mut buf)?;

    let len = handshake.write_message(&[], &mut buf)?;
    write_packet_as_server(stream, &buf[..len]).await?;

    let msg = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_packet(stream)).await??;
    handshake.read_message(&msg, &mut buf)?;

    let session = Arc::new(Mutex::new(NoiseSession::new(handshake)?));

    let remote_static = session
        .lock()
        .map_err(|e| anyhow!("Lock poisoned: {}", e))?
        .transport
        .get_remote_static()
        .ok_or_else(|| anyhow!("Missing remote static key"))?
        .to_vec();

    let mut h = Hasher::new();
    h.update(&remote_static);
    let fp = BASE64_STANDARD.encode(h.finalize().as_bytes());

    // PQ KEM
    let (pk, sk) = keypair();
    let pq_init = WireMessage::PQInit {
        public_key: pk.as_bytes().to_vec(),
    };
    let data = bincode::serialize(&pq_init)?;
    let pkt = IsotopePacket::new(&data)?;
    let bytes = pkt.to_bytes()?;
    let enc = session
        .lock()
        .map_err(|e| anyhow!("Lock poisoned: {}", e))?
        .encrypt(&bytes)?;

    write_packet_as_server(stream, &enc).await?;

    let wire_buf = timeout(Duration::from_secs(READ_TIMEOUT_SEC), read_packet(stream)).await??;
    let decrypted = session
        .lock()
        .map_err(|e| anyhow!("Lock poisoned: {}", e))?
        .decrypt(&wire_buf)?;
    let packet = IsotopePacket::from_bytes(&decrypted)?;

    if let Ok(WireMessage::PQFinish { ciphertext }) = bincode::deserialize(&packet.payload) {
        let ct = Ciphertext::from_bytes(&ciphertext)
            .map_err(|_| anyhow!("Invalid Kyber ciphertext"))?;
        let ss = decapsulate(&ct, &sk);
        session
            .lock()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?
            .upgrade_to_pq(ss.as_bytes(), false);
    } else {
        anyhow::bail!("Expected PQFinish");
    }

    Ok((session, fp))
}
