use std::{
    io::{Cursor, ErrorKind as IoErrorKind, Write as _},
    sync::Arc,
};

use rustls::{
    cipher_suite::TLS13_CHACHA20_POLY1305_SHA256, version::TLS13, ClientConfig, ClientConnection,
    ProtocolVersion, RootCertStore,
};

use tls_client_hello_parser::{ParseError, Parser};

#[test]
fn test_parse() -> Result<(), Box<dyn std::error::Error>> {
    {
        let mut parser = Parser::new();

        match parser.parse(&mut Cursor::new(b"")) {
            Err(ParseError::IoError(err)) if err.kind() == IoErrorKind::UnexpectedEof => {}
            x => panic!("{x:?}"),
        }
    }

    {
        let mut parser = Parser::new();

        let mut cursor = Cursor::new(b"foo");
        match parser.parse(&mut cursor) {
            Ok(None) => {}
            x => panic!("{x:?}"),
        }
        match parser.parse(&mut cursor) {
            Err(ParseError::IoError(err)) if err.kind() == IoErrorKind::UnexpectedEof => {}
            x => panic!("{x:?}"),
        }
    }

    {
        // https://github.com/rustls/rustls/blob/v/0.20.8/rustls/tests/api.rs#L4035
        let mut parser = Parser::new();

        let root_store = RootCertStore::empty();
        let client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client_config = Arc::new(client_config);
        let mut client = ClientConnection::new(client_config, "example.com".try_into()?)?;
        let mut buf = Vec::new();
        client.write_tls(&mut buf)?;

        let mut cursor = Cursor::new(Vec::<u8>::new());
        let buf_last_byte = buf.pop().expect("");
        for bytes in buf.chunks(10) {
            let cursor_position = cursor.position();
            cursor.write_all(bytes)?;
            cursor.set_position(cursor_position);

            match parser.parse(&mut cursor) {
                Ok(None) => {}
                x => panic!("{x:?}"),
            }
        }

        let cursor_position = cursor.position();
        cursor.write_all(&[buf_last_byte])?;
        cursor.set_position(cursor_position);

        match parser.parse(&mut cursor) {
            Ok(Some(chp)) => {
                assert_eq!(chp.client_hello()?.server_name(), Some("example.com"));
            }
            x => panic!("{x:?}"),
        }
    }

    {
        let mut parser = Parser::new();

        let root_store = RootCertStore::empty();
        let client_config = ClientConfig::builder()
            .with_cipher_suites(&[TLS13_CHACHA20_POLY1305_SHA256])
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&TLS13])?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client_config = Arc::new(client_config);
        let mut client = ClientConnection::new(client_config, "xxx.com".try_into()?)?;
        let mut buf = Vec::new();
        client.write_tls(&mut buf)?;

        let mut cursor = Cursor::new(buf);

        match parser.parse(&mut cursor) {
            Ok(Some(chp)) => {
                assert_eq!(
                    chp.get_versions_extension(),
                    Some(&vec![ProtocolVersion::TLSv1_3])
                );
                assert_eq!(chp.client_hello()?.server_name(), Some("xxx.com"));
            }
            x => panic!("{x:?}"),
        }
    }

    Ok(())
}
