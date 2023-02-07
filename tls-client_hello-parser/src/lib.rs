use std::io::{self, ErrorKind};

pub use rustls::internal::msgs::handshake::ClientHelloPayload;
use rustls::internal::msgs::{
    deframer::MessageDeframer,
    enums::{ContentType, HandshakeType},
    handshake::HandshakePayload,
    message::MessagePayload,
};
pub use rustls::TLSError;

pub struct Parser {
    message_deframer: MessageDeframer,
}

pub enum ParseOutput {
    Done(ClientHelloPayload),
    Partial,
    Invalid(TLSError),
}

impl Parser {
    pub fn new() -> Self {
        Self {
            message_deframer: MessageDeframer::new(),
        }
    }

    // ref https://github.com/ctz/rustls/blob/v/0.18.0/rustls/src/msgs/deframer.rs#L54-L79
    pub fn parse(&mut self, buf: &mut impl io::Read) -> io::Result<ParseOutput> {
        self.message_deframer
            .read(buf)
            .or_else(|e| match e.kind() {
                ErrorKind::Interrupted => Ok(0),
                _ => Err(e),
            })?;

        match self.message_deframer.frames.pop_front() {
            Some(mut msg) => {
                // https://github.com/ctz/rustls/blob/v/0.18.0/rustls/src/client/mod.rs#L486-L489
                if !msg.decode_payload() {
                    return Ok(ParseOutput::Invalid(TLSError::CorruptMessagePayload(
                        msg.typ,
                    )));
                }

                match msg.payload {
                    MessagePayload::Handshake(ref hsp) => match hsp.payload {
                        HandshakePayload::ClientHello(ref chp) => {
                            let payload = ClientHelloPayload {
                                client_version: chp.client_version,
                                random: chp.random.to_owned(),
                                session_id: chp.session_id,
                                cipher_suites: chp.cipher_suites.to_owned(),
                                compression_methods: chp.compression_methods.to_owned(),
                                extensions: chp.extensions.to_owned(),
                            };

                            Ok(ParseOutput::Done(payload))
                        }
                        _ => {
                            // ref https://github.com/ctz/rustls/blob/v/0.18.0/rustls/src/check.rs#L7-L25
                            Ok(ParseOutput::Invalid(
                                TLSError::InappropriateHandshakeMessage {
                                    expect_types: vec![HandshakeType::ClientHello],
                                    got_type: hsp.typ,
                                },
                            ))
                        }
                    },
                    _ => {
                        // ref https://github.com/ctz/rustls/blob/v/0.18.0/rustls/src/check.rs#L7-L25
                        Ok(ParseOutput::Invalid(TLSError::InappropriateMessage {
                            expect_types: vec![ContentType::Handshake],
                            got_type: msg.typ,
                        }))
                    }
                }
            }
            None => {
                if self.message_deframer.desynced {
                    // ref https://github.com/ctz/rustls/blob/v/0.18.0/rustls/src/server/mod.rs#L457-L459
                    Ok(ParseOutput::Invalid(TLSError::CorruptMessage))
                } else {
                    Ok(ParseOutput::Partial)
                }
            }
        }
    }
}
