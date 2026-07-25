use blake3::Hasher;
use rand::RngCore;

pub fn ring_sign(
    message: &[u8],
    my_private: &[u8],
    ring_public_keys: &[Vec<u8>],
) -> Vec<u8> {
    if ring_public_keys.is_empty() || my_private.is_empty() {
        return vec![];
    }

    let my_secret = if my_private.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&my_private[..32]);
        x25519_dalek::StaticSecret::from(arr)
    } else {
        let mut hasher = Hasher::new();
        hasher.update(my_private);
        let hash = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash.as_bytes()[..32]);
        x25519_dalek::StaticSecret::from(arr)
    };
    let my_public = x25519_dalek::PublicKey::from(&my_secret);

    let n = ring_public_keys.len();

    let my_idx = ring_public_keys.iter()
        .position(|pk| pk.as_slice() == my_public.as_bytes())
        .unwrap_or(0);

    let mut hasher = Hasher::new();
    hasher.update(b"ISOTOPE_RING_SIG_V2");
    hasher.update(message);
    for pk in ring_public_keys {
        hasher.update(pk);
    }
    let ring_hash = hasher.finalize();

    let mut responses = vec![[0u8; 32]; n];
    let mut challenges = vec![[0u8; 32]; n];

    // Bind secret key and random nonce to derive inner seed X
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut h_x = Hasher::new();
    h_x.update(ring_hash.as_bytes());
    h_x.update(my_private);
    h_x.update(&nonce);
    let x_val = h_x.finalize();

    // c_{my_idx + 1} = H(ring_hash, my_idx, X, PK_{my_idx})
    let mut h_init = Hasher::new();
    h_init.update(b"ISOTOPE_CHALLENGE");
    h_init.update(ring_hash.as_bytes());
    h_init.update(&(my_idx as u32).to_be_bytes());
    h_init.update(x_val.as_bytes());
    h_init.update(&ring_public_keys[my_idx]);
    let c_next = h_init.finalize();

    let next_idx = (my_idx + 1) % n;
    challenges[next_idx].copy_from_slice(&c_next.as_bytes()[..32]);

    // Step through remaining ring nodes
    let mut i = next_idx;
    while i != my_idx {
        rand::rngs::OsRng.fill_bytes(&mut responses[i]);

        let mut xor_input = [0u8; 32];
        for j in 0..32 {
            xor_input[j] = challenges[i][j] ^ responses[i][j];
        }

        let mut h = Hasher::new();
        h.update(b"ISOTOPE_CHALLENGE");
        h.update(ring_hash.as_bytes());
        h.update(&(i as u32).to_be_bytes());
        h.update(&xor_input);
        h.update(&ring_public_keys[i]);
        let next_c = h.finalize();

        let step_next = (i + 1) % n;
        challenges[step_next].copy_from_slice(&next_c.as_bytes()[..32]);
        i = step_next;
    }

    // Solve for responses[my_idx] so that challenges[my_idx] ^ responses[my_idx] == X
    for j in 0..32 {
        responses[my_idx][j] = challenges[my_idx][j] ^ x_val.as_bytes()[j];
    }

    let mut sig = Vec::with_capacity(32 + 32 + n * 32);
    sig.extend_from_slice(ring_hash.as_bytes());
    sig.extend_from_slice(&challenges[0]);
    for res in &responses {
        sig.extend_from_slice(res);
    }
    sig
}

pub fn ring_verify(
    message: &[u8],
    signature: &[u8],
    ring_public_keys: &[Vec<u8>],
) -> bool {
    let n = ring_public_keys.len();
    if n == 0 || signature.len() < 64 + n * 32 {
        return false;
    }

    let ring_hash = &signature[..32];
    let c_initial = &signature[32..64];

    let mut hasher = Hasher::new();
    hasher.update(b"ISOTOPE_RING_SIG_V2");
    hasher.update(message);
    for pk in ring_public_keys {
        hasher.update(pk);
    }
    let expected_ring_hash = hasher.finalize();

    if ring_hash != expected_ring_hash.as_bytes() {
        return false;
    }

    let mut curr_challenge = [0u8; 32];
    curr_challenge.copy_from_slice(c_initial);

    for i in 0..n {
        let offset = 64 + i * 32;
        let response = &signature[offset..offset + 32];

        let mut xor_input = [0u8; 32];
        for j in 0..32 {
            xor_input[j] = curr_challenge[j] ^ response[j];
        }

        let mut h = Hasher::new();
        h.update(b"ISOTOPE_CHALLENGE");
        h.update(ring_hash);
        h.update(&(i as u32).to_be_bytes());
        h.update(&xor_input);
        h.update(&ring_public_keys[i]);
        let next_c = h.finalize();

        curr_challenge.copy_from_slice(&next_c.as_bytes()[..32]);
    }

    curr_challenge == c_initial
}

