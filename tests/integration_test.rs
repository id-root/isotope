use isotope::crypto::Identity;
use isotope::protocol::{IsotopePacket, WireMessage};
use isotope::vault::Vault;
use isotope::{PLAINTEXT_SIZE};
use std::fs;
use chrono::Utc;

#[test]
fn test_identity_dual_slot() {
    let path = format!("test_identity_{}.id", rand::random::<u32>());
    if std::path::Path::new(&path).exists() {
        fs::remove_file(&path).unwrap();
    }

    let pass_ops = "ops_password";
    let pass_casual = "casual_password";

    // Setup
    Identity::setup_dual(&path, pass_ops, pass_casual).expect("Setup failed");

    // Load Ops
    let id_ops = Identity::load(&path, pass_ops).expect("Failed to load Ops");
    assert_eq!(id_ops.profile_type, "ops");

    // Load Casual
    let id_casual = Identity::load(&path, pass_casual).expect("Failed to load Casual");
    assert_eq!(id_casual.profile_type, "casual");

    // Invalid Password
    let err = Identity::load(&path, "wrong").err();
    assert!(err.is_some());

    fs::remove_file(&path).unwrap();
}

#[test]
fn test_packet_serialization() {
    let msg = WireMessage::Chat {
        sender: "Alice".to_string(),
        content: "Hello World".to_string(),
        timestamp: Utc::now(),
    };

    let data = bincode::serialize(&msg).unwrap();
    let packet = IsotopePacket::new(&data).unwrap();
    
    // Wire format check
    let wire_bytes = packet.to_bytes().unwrap();
    assert_eq!(wire_bytes.len(), PLAINTEXT_SIZE); // Should be padded

    // Roundtrip
    let restored = IsotopePacket::from_bytes(&wire_bytes).unwrap();
    let restored_msg: WireMessage = bincode::deserialize(&restored.payload).unwrap();

    if let WireMessage::Chat { sender, content, .. } = restored_msg {
        assert_eq!(sender, "Alice");
        assert_eq!(content, "Hello World");
    } else {
        panic!("Wrong message type");
    }
}

#[test]
fn test_vault_operations() {
    let path = "test_vault.vault";
    let pass = "VaultSecret1";
    if std::path::Path::new(path).exists() {
        fs::remove_file(path).unwrap();
    }

    // Create & Write
    {
        let mut v = Vault::open(path, pass).expect("Create failed");
        v.write_file("secret.txt", b"Top Secret Data").expect("Write failed");
    }

    // Read
    {
        let mut v = Vault::open(path, pass).expect("Open failed");
        let data = v.read_file("secret.txt").expect("Read failed");
        assert_eq!(data, b"Top Secret Data");
    }

    fs::remove_file(path).unwrap();
}

#[test]
fn test_all_wire_message_variants_roundtrip() {
    use isotope::protocol::WireMessage;
    
    let variants: Vec<WireMessage> = vec![
        WireMessage::Heartbeat,
        WireMessage::Dummy { noise: vec![1, 2, 3] },
        WireMessage::Version { major: 4, minor: 0 },
        WireMessage::Chat {
            sender: "Alice".into(),
            content: "Hello".into(),
            timestamp: Utc::now(),
        },
        WireMessage::System { content: "test".into() },
        WireMessage::Join {
            username: "Bob".into(),
            did: "did:key:z123".into(),
            group: "public".into(),
        },
        WireMessage::PeerList { peers: vec!["Alice".into(), "Bob".into()] },
        WireMessage::DirectMessage {
            sender: "Alice".into(),
            target: "Bob".into(),
            content: "secret".into(),
            timestamp: Utc::now(),
            ttl: Some(60),
        },
        WireMessage::FileOffer {
            sender: "Alice".into(),
            file_name: "test.txt".into(),
            file_size: 1024,
            id: 1,
        },
        WireMessage::Reaction {
            message_id: 42,
            emoji: "👍".into(),
            sender: "Bob".into(),
        },
        WireMessage::Typing {
            user: "Alice".into(),
            is_typing: true,
        },
        WireMessage::ReadReceipt {
            message_id: 42,
            reader: "Bob".into(),
        },
    ];
    
    for msg in variants {
        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: WireMessage = bincode::deserialize(&encoded).unwrap();
        // Just verify it doesn't panic — we can't easily compare enums without PartialEq
        let re_encoded = bincode::serialize(&decoded).unwrap();
        assert_eq!(encoded, re_encoded, "Round-trip failed for a WireMessage variant");
    }
}

#[test]
fn test_packet_oversized_payload_rejected() {
    let huge = vec![0u8; PLAINTEXT_SIZE + 1000];
    let result = IsotopePacket::new(&huge);
    assert!(result.is_err(), "Oversized payload should be rejected");
}

#[test]
fn test_parse_onion_address_valid() {
    use isotope::network::parse_onion_address;
    let (host, port) = parse_onion_address("abc123.onion:7878").unwrap();
    assert_eq!(host, "abc123.onion");
    assert_eq!(port, 7878);
}

#[test]
fn test_parse_onion_address_missing_port() {
    use isotope::network::parse_onion_address;
    let result = parse_onion_address("abc123.onion");
    assert!(result.is_err());
}

#[test]
fn test_parse_onion_address_non_onion() {
    use isotope::network::parse_onion_address;
    let result = parse_onion_address("example.com:7878");
    assert!(result.is_err());
}

#[test]
fn test_vault_wrong_password() {
    let path = "test_vault_wrongpass.vault";
    let pass = "CorrectPass1";
    let wrong = "WrongPass1";
    if std::path::Path::new(path).exists() {
        fs::remove_file(path).unwrap();
    }
    
    // Create vault
    {
        let mut v = Vault::open(path, pass).expect("Create failed");
        v.write_file("secret.txt", b"data").expect("Write failed");
    }
    
    // Wrong password should fail
    let result = Vault::open(path, wrong);
    assert!(result.is_err(), "Wrong password should fail to open vault");
    
    fs::remove_file(path).unwrap();
}

#[test]
fn test_vault_multiple_files() {
    let path = "test_vault_multi.vault";
    let pass = "MultiPass1";
    if std::path::Path::new(path).exists() {
        fs::remove_file(path).unwrap();
    }
    
    {
        let mut v = Vault::open(path, pass).expect("Create failed");
        v.write_file("file1.txt", b"Data One").unwrap();
        v.write_file("file2.txt", b"Data Two").unwrap();
        v.write_file("file3.bin", &[0xFF; 8000]).unwrap(); // Multi-block file
    }
    
    {
        let mut v = Vault::open(path, pass).expect("Open failed");
        assert_eq!(v.read_file("file1.txt").unwrap(), b"Data One");
        assert_eq!(v.read_file("file2.txt").unwrap(), b"Data Two");
        assert_eq!(v.read_file("file3.bin").unwrap(), vec![0xFF; 8000]);
        
        let files = v.list_files();
        assert_eq!(files.len(), 3);
    }
    
    fs::remove_file(path).unwrap();
}

#[test]
fn test_identity_fingerprint_and_did() {
    let id = isotope::crypto::Identity::generate("test").unwrap();
    
    let fp = id.fingerprint();
    assert!(!fp.is_empty(), "Fingerprint should not be empty");
    
    let did = id.did();
    assert!(did.starts_with("did:key:z"), "DID should start with did:key:z");
}

#[test]
fn test_ring_signature() {
    use isotope::crypto::ring_sig::{ring_sign, ring_verify};

    let id1 = isotope::crypto::Identity::generate("member1").unwrap();
    let id2 = isotope::crypto::Identity::generate("member2").unwrap();
    let id3 = isotope::crypto::Identity::generate("member3").unwrap();

    let ring = vec![
        id1.keypair.public.clone(),
        id2.keypair.public.clone(),
        id3.keypair.public.clone(),
    ];

    let message = b"Anonymous group statement";
    let sig = ring_sign(message, &id1.keypair.private, &ring);

    assert!(!sig.is_empty(), "Signature should not be empty");
    assert!(ring_verify(message, &sig, &ring), "Signature verification failed");
    assert!(!ring_verify(b"Tampered message", &sig, &ring), "Tampered message should fail verification");
}

