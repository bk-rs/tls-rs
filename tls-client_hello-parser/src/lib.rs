pub use rustls;

use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read};

use rustls::{
    internal::msgs::{
        deframer::MessageDeframer,
        handshake::{ClientHelloPayload as ClientHelloPayloadInner, HandshakePayload},
        message::{Message, MessagePayload},
    },
    ContentType, Error as RustlsError, HandshakeType,
};

//
//
//
pub mod client_hello;
pub use client_hello::ClientHello;

//
//
//
pub struct Parser {
    message_deframer: MessageDeframer,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    pub fn new() -> Self {
        Self {
            message_deframer: MessageDeframer::new(),
        }
    }

    pub fn parse(&mut self, rd: &mut dyn Read) -> Result<Option<ClientHelloPayload>, ParseError> {
        let n = self
            .message_deframer
            .read(rd)
            .map_err(ParseError::IoError)?;

        match self
            .message_deframer
            .pop()
            .map_err(ParseError::RustlsError)?
        {
            Some(opaque_message) => {
                let plain_message = opaque_message.into_plain_message();
                let plain_message_typ = plain_message.typ.to_owned();
                let message = Message::try_from(plain_message).map_err(ParseError::RustlsError)?;
                match &message.payload {
                    MessagePayload::Handshake { parsed, encoded: _ } => match &parsed.payload {
                        HandshakePayload::ClientHello(chp) => {
                            let inner = ClientHelloPayloadInner {
                                client_version: chp.client_version,
                                random: chp.random.to_owned(),
                                session_id: chp.session_id,
                                cipher_suites: chp.cipher_suites.to_owned(),
                                compression_methods: chp.compression_methods.to_owned(),
                                extensions: chp.extensions.to_owned(),
                            };
                            Ok(Some(ClientHelloPayload(inner)))
                        }
                        _ => Err(ParseError::RustlsError(
                            RustlsError::InappropriateHandshakeMessage {
                                expect_types: vec![HandshakeType::ClientHello],
                                got_type: parsed.typ,
                            },
                        )),
                    },
                    _ => Err(ParseError::RustlsError(RustlsError::InappropriateMessage {
                        expect_types: vec![ContentType::Handshake],
                        got_type: plain_message_typ,
                    })),
                }
            }
            None => {
                if n == 0 {
                    Err(ParseError::IoError(IoErrorKind::UnexpectedEof.into()))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum ParseError {
    IoError(IoError),
    RustlsError(RustlsError),
}
impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ParseError {}

//
//
//
#[derive(Debug)]
pub struct ClientHelloPayload(pub ClientHelloPayloadInner);

impl core::ops::Deref for ClientHelloPayload {
    type Target = ClientHelloPayloadInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for ClientHelloPayload {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ClientHelloPayload {
    pub fn client_hello(&self) -> Result<ClientHello<'_>, RustlsError> {
        use rustls::internal::msgs::handshake::ConvertServerNameList as _;

        Ok(ClientHello::new(
            self.get_sni_extension()
                .and_then(|x| x.get_single_hostname())
                .map(|x| x.to_owned()),
            self.get_sigalgs_extension().ok_or_else(|| {
                // https://github.com/rustls/rustls/blob/v/0.20.8/rustls/src/server/hs.rs#L512
                RustlsError::PeerIncompatibleError(
                    "client didn't describe signature schemes".into(),
                )
            })?,
            self.get_alpn_extension(),
            self.cipher_suites.as_ref(),
        ))
    }
}
