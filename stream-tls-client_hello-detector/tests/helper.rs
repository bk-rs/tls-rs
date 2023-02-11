use std::{io::Cursor, sync::Arc};

use rustls::{
    Certificate, ClientConfig, ClientConnection, PrivateKey, RootCertStore, ServerConfig,
    ServerConnection,
};
use rustls_pemfile::{certs, pkcs8_private_keys};

pub fn make_client_config() -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        certs(&mut Cursor::new(include_bytes!("mkcert/rootCA.pem")))?.as_ref(),
    );

    Ok(ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth())
}

pub fn make_client_connection() -> Result<ClientConnection, Box<dyn std::error::Error>> {
    Ok(ClientConnection::new(
        Arc::new(make_client_config()?),
        "tls.lvh.me".try_into()?,
    )?)
}

pub fn make_server_config() -> Result<ServerConfig, Box<dyn std::error::Error>> {
    Ok(ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            certs(&mut Cursor::new(include_bytes!("mkcert/tls.lvh.me.crt")))?
                .into_iter()
                .map(Certificate)
                .collect::<Vec<_>>(),
            PrivateKey(
                pkcs8_private_keys(&mut Cursor::new(include_bytes!(
                    "mkcert/tls.lvh.me-key.pem"
                )))?
                .first()
                .cloned()
                .ok_or("")?,
            ),
        )?)
}

pub fn make_server_connection() -> Result<ServerConnection, Box<dyn std::error::Error>> {
    Ok(ServerConnection::new(Arc::new(make_server_config()?))?)
}
