use std::io::{self, Cursor, Write};

use rustls::internal::msgs::{
    codec::Codec,
    enums::Compression,
    handshake::{ClientExtension, Random, SessionID},
};
use rustls::{CipherSuite, ProtocolVersion};

use tls_client_hello_parser::{ClientHelloPayload, ParseOutput, Parser, TLSError};

#[test]
fn test_parse() -> io::Result<()> {
    let mut parser = Parser::new();
    let mut cursor = Cursor::new(vec![]);

    match parser.parse(&mut cursor)? {
        ParseOutput::Partial => (),
        _ => assert!(true, "should ParseOutput::Partial"),
    }

    cursor.write(b"foo")?;
    match parser.parse(&mut cursor)? {
        ParseOutput::Invalid(e) => match e {
            TLSError::CorruptMessage => (),
            _ => assert!(true, "should TLSError::CorruptMessage"),
        },
        _ => assert!(true, "should ParseOutput::Invalid"),
    }

    let payload = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_3,
        random: Random::from_slice(b"12345678901234567890123456789012"),
        session_id: SessionID::new(b"1"),
        cipher_suites: vec![CipherSuite::TLS13_CHACHA20_POLY1305_SHA256],
        compression_methods: vec![Compression::Deflate],
        extensions: vec![ClientExtension::EarlyData],
    };
    let mut payload_bytes = vec![];
    payload.encode(&mut payload_bytes);
    let payload_last_byte = payload_bytes.pop().expect("");

    for sub_bytes in payload_bytes.chunks(3) {
        cursor.write(sub_bytes)?;
        match parser.parse(&mut cursor)? {
            ParseOutput::Partial => (),
            _ => assert!(true, "should ParseOutput::Partial"),
        }
    }

    cursor.write(&[payload_last_byte, 1, 2])?;
    match parser.parse(&mut cursor)? {
        ParseOutput::Done(payload_output) => {
            assert_eq!(payload_output.client_version, payload.client_version);
            assert_eq!(payload_output.random, payload.random);
            assert_eq!(payload_output.session_id, payload.session_id);
            assert_eq!(payload_output.cipher_suites, payload.cipher_suites);
            assert_eq!(
                payload_output.compression_methods,
                payload.compression_methods
            );
            assert_eq!(payload_output.extensions.len(), 1);
            match payload_output.extensions.first().unwrap() {
                ClientExtension::EarlyData => (),
                _ => assert!(true, "should ClientExtension::EarlyData"),
            }
        }
        _ => assert!(true, "should ParseOutput::Done"),
    }

    Ok(())
}
