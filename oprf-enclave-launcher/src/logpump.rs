//! Best-effort log pump: drains a pipe into a network sink without ever
//! letting the sink slow the pipe's writer down.

use std::io::{self, BufRead, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(crate) struct PumpOpts {
    pub queue: usize,
    pub retry: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PumpStats {
    pub delivered: u64,
    pub dropped: u64,
}

#[derive(Default)]
struct Counters {
    delivered: AtomicU64,
    dropped: AtomicU64,
    reader_done: AtomicBool,
}

pub(crate) struct PumpHandle {
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
    counters: Arc<Counters>,
}

impl PumpHandle {
    /// Returns once the reader hit EOF and the writer drained or gave up.
    pub(crate) fn join(self) -> PumpStats {
        self.reader.join().expect("log pump reader panicked");
        self.writer.join().expect("log pump writer panicked");
        PumpStats {
            delivered: self.counters.delivered.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
        }
    }
}

/// Reads lines from `lines` into a bounded queue (dropping on overflow) while a
/// second thread writes them to whatever `connect` returns. The reader never
/// waits on the sink. `connect` must bound its writes with a timeout.
pub(crate) fn spawn_pump<R, C, W>(mut lines: R, mut connect: C, opts: PumpOpts) -> PumpHandle
where
    R: BufRead + Send + 'static,
    C: FnMut() -> io::Result<W> + Send + 'static,
    W: Write,
{
    let counters = Arc::new(Counters::default());
    let (tx, rx) = mpsc::sync_channel::<String>(opts.queue);

    let c = Arc::clone(&counters);
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match lines.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let mut line = String::from_utf8_lossy(&buf).into_owned();
            if !line.ends_with('\n') {
                line.push('\n');
            }
            match tx.try_send(line) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    c.dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => break,
            }
        }
        c.reader_done.store(true, Ordering::Release);
    });

    let c = Arc::clone(&counters);
    let writer = thread::spawn(move || {
        let mut conn: Option<W> = None;
        let mut last_fail: Option<Instant> = None;
        for line in &rx {
            if conn.is_none() {
                if last_fail.is_some_and(|t| t.elapsed() < opts.retry) {
                    c.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if let Ok(w) = connect() {
                    conn = Some(w);
                } else {
                    last_fail = Some(Instant::now());
                    c.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
            let sent = conn.as_mut().is_some_and(|w| {
                w.write_all(line.as_bytes())
                    .and_then(|()| w.flush())
                    .is_ok()
            });
            if sent {
                c.delivered.fetch_add(1, Ordering::Relaxed);
            } else {
                conn = None;
                last_fail = Some(Instant::now());
                c.dropped.fetch_add(1, Ordering::Relaxed);
                // Input is finished: don't spend one write timeout per queued line.
                if c.reader_done.load(Ordering::Acquire) {
                    for _ in rx.try_iter() {
                        c.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    return;
                }
            }
        }
    });

    PumpHandle {
        reader,
        writer,
        counters,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    const WRITE_TIMEOUT: Duration = Duration::from_millis(200);

    /// Runs `body` on its own thread; a hang fails the test instead of the suite.
    fn with_deadline(body: impl FnOnce() + Send + 'static) {
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            body();
            done_tx.send(()).unwrap_or_default();
        });
        match done_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(()) => worker.join().expect("test body"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                worker.join().expect("test body panicked");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("test body exceeded 10 s deadline"),
        }
    }

    fn connector(addr: std::net::SocketAddr) -> impl FnMut() -> io::Result<TcpStream> + Send {
        move || {
            let s = TcpStream::connect(addr)?;
            s.set_write_timeout(Some(WRITE_TIMEOUT))?;
            Ok(s)
        }
    }

    fn opts(retry: Duration) -> PumpOpts {
        PumpOpts { queue: 1024, retry }
    }

    #[test]
    fn delivers_lines_when_sink_up() {
        with_deadline(|| {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("addr");
            let sink = thread::spawn(move || {
                let (mut s, _) = listener.accept().expect("accept");
                let mut got = String::new();
                s.read_to_string(&mut got).expect("read");
                got
            });
            let input = Cursor::new(b"one\ntwo\nthree\n".to_vec());
            let stats = spawn_pump(input, connector(addr), opts(Duration::from_secs(1))).join();
            assert_eq!(stats.delivered, 3, "stats: {stats:?}");
            assert_eq!(stats.dropped, 0, "stats: {stats:?}");
            assert_eq!(sink.join().expect("sink"), "one\ntwo\nthree\n");
        });
    }

    #[test]
    fn drops_while_sink_down_and_keeps_reading() {
        with_deadline(|| {
            let input = Cursor::new("line\n".repeat(10_000).into_bytes());
            let connect =
                || -> io::Result<TcpStream> { Err(io::ErrorKind::ConnectionRefused.into()) };
            let stats = spawn_pump(input, connect, opts(Duration::from_secs(1))).join();
            assert_eq!(stats.dropped, 10_000, "stats: {stats:?}");
            assert_eq!(stats.delivered, 0, "stats: {stats:?}");
        });
    }

    #[test]
    fn stalled_sink_never_blocks_reader() {
        with_deadline(|| {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("addr");
            // Accepts, then never reads; the stream is kept open until the end.
            let sink = thread::spawn(move || listener.accept().expect("accept").0);
            let line = format!("{}\n", "x".repeat(1023));
            let lines = 50 * 1024;
            let input = Cursor::new(line.repeat(lines).into_bytes());
            let stats = spawn_pump(input, connector(addr), opts(Duration::from_millis(50))).join();
            assert_eq!(
                stats.delivered + stats.dropped,
                lines as u64,
                "every line is accounted for: {stats:?}"
            );
            assert!(
                stats.dropped > 0,
                "a stalled sink must cause drops: {stats:?}"
            );
            drop(sink.join().expect("sink"));
        });
    }

    #[test]
    fn reconnects_after_retry() {
        with_deadline(|| {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("addr");
            let sink = thread::spawn(move || {
                let (mut s, _) = listener.accept().expect("accept");
                let mut got = String::new();
                s.read_to_string(&mut got).expect("read");
                got
            });
            let mut inner = connector(addr);
            let mut first = true;
            let connect = move || {
                if std::mem::take(&mut first) {
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                }
                inner()
            };
            let input = Cursor::new(b"a\nb\nc\n".to_vec());
            let stats = spawn_pump(input, connect, opts(Duration::ZERO)).join();
            assert_eq!(
                stats.dropped, 1,
                "first line hits the failed connect: {stats:?}"
            );
            assert_eq!(stats.delivered, 2, "stats: {stats:?}");
            assert_eq!(sink.join().expect("sink"), "b\nc\n");
        });
    }
}
