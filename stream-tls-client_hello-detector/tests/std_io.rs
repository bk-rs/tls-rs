#[cfg(feature = "std_io")]
mod std_io_tests {
    use std::fs::File;
    use std::io::{self, BufReader};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::{mpsc, Arc};

    use async_io::Async;
    use async_tls::{TlsAcceptor, TlsConnector};
    use futures_executor::{block_on, ThreadPool};
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use futures_util::task::SpawnExt;
    use rustls::{internal::pemfile, ClientConfig, NoClientAuth, ServerConfig};

    use stream_tls_client_hello_detector::Detector;

    // ref https://github.com/vkill/rust-io-peek/blob/master/std-io-peek/tests/tcp_stream.rs
    // ref https://github.com/async-rs/async-tls/blob/master/examples/server/src/main.rs
    // ref https://github.com/async-rs/async-tls/blob/master/examples/client/src/main.rs
    #[test]
    fn tcp_stream() -> io::Result<()> {
        block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let addr = listener.local_addr()?;

            let mkcert_path = PathBuf::new().join("tests/mkcert");

            let client_config = {
                let mut client_config = ClientConfig::new();

                client_config
                    .root_store
                    .add_pem_file(&mut BufReader::new(File::open(
                        mkcert_path.join("rootCA.pem"),
                    )?))
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;

                client_config
            };
            let tls_connector = TlsConnector::from(Arc::new(client_config));

            let server_config = {
                let mut server_config = ServerConfig::new(NoClientAuth::new());
                let certs = pemfile::certs(&mut BufReader::new(File::open(
                    mkcert_path.join("tls.lvh.me.crt"),
                )?))
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;
                let key = pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(
                    mkcert_path.join("tls.lvh.me-key.pem"),
                )?))
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?
                .first()
                .expect("invalid key")
                .to_owned();
                server_config
                    .set_single_cert(certs, key)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

                server_config
            };
            let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

            let tcp_stream_c = Async::<TcpStream>::connect(addr).await?;
            let mut tcp_stream_s = listener
                .incoming()
                .next()
                .expect("Get next incoming failed")?;

            println!(
                "addr {:?}, tcp_stream_c {:?} tcp_stream_s {:?}",
                addr, tcp_stream_c, tcp_stream_s
            );

            let (sender_s, receiver) = mpsc::channel::<String>();
            let sender_c = sender_s.clone();

            let executor = ThreadPool::new()?;

            executor
                .spawn(async move {
                    let mut detector = Detector::new();
                    let client_hello_payload = detector.detect(&mut tcp_stream_s).expect(
                        "detector
                        .detect_async failed",
                    );
                    println!("{:?}", client_hello_payload);

                    let tcp_stream_s = Async::new(tcp_stream_s).expect("convert to Async failed");

                    let mut tls_stream_s = tls_acceptor.accept(tcp_stream_s).await.expect(
                        "tls_acceptor
                        .accept failed",
                    );

                    println!("tls_stream_s {:?}", tls_stream_s);

                    let mut buf = [0; 5];
                    tls_stream_s.read(&mut buf).await.expect("read failed");
                    assert_eq!(&buf, b"foo\0\0");
                    println!("tls_stream_s read done");

                    tls_stream_s.write(b"bar").await.expect("write failed");
                    println!("tls_stream_s write done");

                    let mut buf = [0; 5];
                    tls_stream_s.read(&mut buf).await.expect("read failed");
                    assert_eq!(&buf, b"\0\0\0\0\0");

                    sender_s
                        .send("server done".to_owned())
                        .expect("sender_s.send failed");
                })
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            executor
                .spawn(async move {
                    let mut tls_stream_c = tls_connector
                        .connect("tls.lvh.me", tcp_stream_c)
                        .await
                        .expect(
                            "tls_connector
                        .connect failed",
                        );

                    println!("tls_stream_c {:?}", tls_stream_c);

                    tls_stream_c.write(b"foo").await.expect("write failed");
                    println!("tls_stream_c write done");

                    let mut buf = [0; 5];
                    tls_stream_c.read(&mut buf).await.expect("read failed");
                    assert_eq!(&buf, b"bar\0\0");
                    println!("tls_stream_c read done");

                    tls_stream_c
                        .get_mut()
                        .get_mut()
                        .shutdown(Shutdown::Both)
                        .expect("shutdown call failed");

                    println!("tls_stream_c shutdown done");

                    sender_c
                        .send("client done".to_owned())
                        .expect("sender_c.send failed");
                })
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let msg_1 = receiver.recv().unwrap();
            println!("receiver.recv {}", msg_1);
            assert_eq!(msg_1, "client done");

            let msg_2 = receiver.recv().unwrap();
            println!("receiver.recv {}", msg_2);
            assert_eq!(msg_2, "server done");

            Ok(())
        })
    }
}
