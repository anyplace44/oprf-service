//! Bidirectional byte relay between two stream sockets.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};

pub(crate) trait Stream: Read + Write + Send + Sized + 'static {
    fn try_clone(&self) -> io::Result<Self>;
    fn shutdown_write(&self) -> io::Result<()>;
}

impl Stream for TcpStream {
    fn try_clone(&self) -> io::Result<Self> {
        TcpStream::try_clone(self)
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

/// Copies both directions until each side has sent EOF, propagating each EOF
/// as a write shutdown to the other side.
pub(crate) fn relay<A: Stream, B: Stream>(mut a: A, mut b: B) -> io::Result<()> {
    let mut a_rx = a.try_clone()?;
    let mut b_tx = b.try_clone()?;
    let a_to_b = std::thread::spawn(move || -> io::Result<()> {
        io::copy(&mut a_rx, &mut b_tx)?;
        b_tx.shutdown_write()
    });
    let b_to_a = io::copy(&mut b, &mut a).and_then(|_| a.shutdown_write());
    let a_to_b = a_to_b
        .join()
        .map_err(|_| io::Error::other("relay thread panicked"))?;
    b_to_a.and(a_to_b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn relays_both_directions_and_propagates_eof() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("bind echo");
        let echo_addr = echo.local_addr().expect("echo addr");
        thread::spawn(move || {
            let (mut s, _) = echo.accept().expect("accept echo");
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).expect("echo read");
            s.write_all(&buf).expect("echo write");
        });

        let front = TcpListener::bind("127.0.0.1:0").expect("bind front");
        let front_addr = front.local_addr().expect("front addr");
        let relayed = thread::spawn(move || {
            let (client_side, _) = front.accept().expect("accept front");
            let upstream = TcpStream::connect(echo_addr).expect("connect echo");
            relay(client_side, upstream)
        });

        let mut client = TcpStream::connect(front_addr).expect("connect front");
        // A lost EOF shows up as a hang; turn it into a failure.
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");
        client.write_all(b"hello").expect("client write");
        client.shutdown(Shutdown::Write).expect("client shutdown");
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).expect("client read");

        assert_eq!(
            reply, b"hello",
            "echo only answers after the client's EOF reached it"
        );
        relayed.join().expect("relay thread").expect("relay result");
    }
}
