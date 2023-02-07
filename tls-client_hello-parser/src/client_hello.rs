// Copy from https://github.com/rustls/rustls/blob/v/0.20.8/rustls/src/server/server_conn.rs#L112-L185

use rustls::{internal::msgs::base::PayloadU8, CipherSuite, SignatureScheme};

//
pub struct ClientHello<'a> {
    server_name: Option<webpki::DnsName>,
    signature_schemes: &'a [SignatureScheme],
    alpn: Option<&'a Vec<PayloadU8>>,
    cipher_suites: &'a [CipherSuite],
}

impl<'a> ClientHello<'a> {
    pub fn new(
        server_name: Option<webpki::DnsName>,
        signature_schemes: &'a [SignatureScheme],
        alpn: Option<&'a Vec<PayloadU8>>,
        cipher_suites: &'a [CipherSuite],
    ) -> Self {
        ClientHello {
            server_name,
            signature_schemes,
            alpn,
            cipher_suites,
        }
    }

    pub fn server_name(&self) -> Option<&str> {
        self.server_name
            .as_ref()
            .map(<webpki::DnsName as AsRef<str>>::as_ref)
    }

    pub fn signature_schemes(&self) -> &[SignatureScheme] {
        self.signature_schemes
    }

    pub fn alpn(&self) -> Option<impl Iterator<Item = &'a [u8]>> {
        self.alpn
            .map(|protocols| protocols.iter().map(|proto| proto.0.as_slice()))
    }

    pub fn cipher_suites(&self) -> &[CipherSuite] {
        self.cipher_suites
    }
}
