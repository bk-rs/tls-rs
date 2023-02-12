#![allow(clippy::unused_io_amount)]
#![cfg(feature = "std_io")]

use std::{
    io::ErrorKind as IoErrorKind,
    net::{Shutdown, TcpListener, TcpStream},
    sync::{mpsc, Arc},
};

use async_io::Async;
use async_tls::{TlsAcceptor, TlsConnector};
use futures_executor::{block_on, ThreadPool};
use futures_util::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    task::SpawnExt as _,
};
use tls_mkcert_test::{
    rustls::{make_client_config, make_server_config},
    SNI,
};

use stream_tls_client_hello_detector::Detector;

// ref https://github.com/bk-rs/rust-io-peek/blob/master/std-io-peek/tests/tcp_stream.rs
// ref https://github.com/async-rs/async-tls/blob/master/examples/server/src/main.rs
// ref https://github.com/async-rs/async-tls/blob/master/examples/client/src/main.rs
#[test]
fn tcp_stream() -> Result<(), Box<dyn std::error::Error>> {
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let tcp_stream_c = Async::<TcpStream>::connect(addr).await?;
        let mut tcp_stream_s = listener.incoming().next().ok_or("incoming next none")??;

        println!("addr:{addr:?}, tcp_stream_c:{tcp_stream_c:?} tcp_stream_s:{tcp_stream_s:?}");

        let (sender_s, receiver) = mpsc::channel::<String>();
        let sender_c = sender_s.clone();

        let executor = ThreadPool::new()?;

        let tls_connector = TlsConnector::from(Arc::new(make_client_config()?));
        let tls_acceptor = TlsAcceptor::from(Arc::new(make_server_config()?));

        executor.spawn(async move {
            let mut detector = Detector::new();
            let client_hello_payload = detector.detect(&mut tcp_stream_s).expect("detector.detect");
            println!("{client_hello_payload:?}");
            assert_eq!(
                client_hello_payload
                    .client_hello()
                    .expect("client_hello_payload.client_hello")
                    .server_name(),
                Some(SNI)
            );

            let tcp_stream_s = Async::new(tcp_stream_s).expect("Async::new");

            let mut tls_stream_s = tls_acceptor
                .accept(tcp_stream_s)
                .await
                .expect("tls_acceptor.accept");

            println!("tls_stream_s:{tls_stream_s:?}");

            let mut buf = [0; 5];
            tls_stream_s
                .read(&mut buf)
                .await
                .expect("tls_stream_s.read");
            assert_eq!(&buf, b"foo\0\0");
            println!("tls_stream_s read done");

            tls_stream_s
                .write_all(b"bar")
                .await
                .expect("tls_stream_s.write_all");
            println!("tls_stream_s write done");

            let mut buf = [0; 5];
            match tls_stream_s.read(&mut buf).await {
                Ok(_) => {}
                Err(err) => assert_eq!(err.kind(), IoErrorKind::UnexpectedEof),
            }
            assert_eq!(&buf, b"\0\0\0\0\0");

            sender_s
                .send("server done".to_owned())
                .expect("sender_s.send");
        })?;

        executor.spawn(async move {
            let mut tls_stream_c = tls_connector
                .connect(SNI, tcp_stream_c)
                .await
                .expect("tls_connector.connect");

            println!("tls_stream_c:{tls_stream_c:?}");

            tls_stream_c
                .write_all(b"foo")
                .await
                .expect("tls_stream_c.write_all");
            println!("tls_stream_c write done");

            let mut buf = [0; 5];
            tls_stream_c
                .read(&mut buf)
                .await
                .expect("tls_stream_c.read");
            assert_eq!(&buf, b"bar\0\0");
            println!("tls_stream_c read done");

            tls_stream_c
                .get_mut()
                .get_mut()
                .shutdown(Shutdown::Both)
                .expect("tls_stream_c.shutdown");

            println!("tls_stream_c shutdown done");

            sender_c
                .send("client done".to_owned())
                .expect("sender_c.send");
        })?;

        let msg_1 = receiver.recv().unwrap();
        println!("receiver.recv {msg_1}");
        assert_eq!(msg_1, "client done");

        let msg_2 = receiver.recv().unwrap();
        println!("receiver.recv {msg_2}");
        assert_eq!(msg_2, "server done");

        Ok(())
    })
}
