//! Hello-world HTTP backend for `bench/run.sh`: answers every bodiless request with a fixed response.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nServer: hello\r\n\r\nHello World\n";
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:9000")
        .await
        .unwrap();
    loop {
        let (mut s, _) = l.accept().await.unwrap();
        s.set_nodelay(true).ok();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let mut have = 0usize;
            loop {
                match s.read(&mut buf[have..]).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => have += n,
                }
                // answer each complete header block (GETs without bodies only)
                while let Some(p) = buf[..have].windows(4).position(|w| w == b"\r\n\r\n") {
                    if s.write_all(RESP).await.is_err() {
                        return;
                    }
                    buf.copy_within(p + 4..have, 0);
                    have -= p + 4;
                }
                if have == buf.len() {
                    return;
                }
            }
        });
    }
}
