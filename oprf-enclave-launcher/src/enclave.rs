//! Enclave-side runtime: log pump, KMS-delivered config, forwarders, the enclave app.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, PipeWriter, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::panic::{self, AssertUnwindSafe};
use std::process::{Command, ExitCode};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use vsock::{VMADDR_CID_ANY, VsockListener, VsockStream};

use crate::app;
use crate::kms::decrypt_config;
use crate::logpump::{PumpHandle, PumpOpts, spawn_pump};
use crate::nsm;
use crate::relay::{Stream, relay};
use taceo_oprf_enclave_attestation::{LAUNCHER_ADDR, serve, user_data};
use taceo_oprf_enclave_launcher::bootstrap::{
    BOOTSTRAP_PORT, Bootstrap, EnclaveConfig, LOG_PORT, check_key, combined_table, kms_forward_line,
};
use taceo_oprf_enclave_launcher::table::{Inbound, Outbound, Table};

/// Same user and workdir as the OCI images (`USER 65532:65532`, `/app`).
#[allow(
    clippy::decimal_literal_representation,
    reason = "must read the same as USER 65532:65532 in the Dockerfiles"
)]
const APP_ID: u32 = 65532;
const APP_DIR: &str = "/app";
/// Nitro's parent instance is CID 3 (nit's heartbeat dials it too), not
/// `VMADDR_CID_HOST` (2).
const PARENT_CID: u32 = 3;
const BOOTSTRAP_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// The real line is a few KiB: a ciphertext of at most 4 KiB plaintext, base64, plus STS
/// credentials.
const MAX_BOOTSTRAP_LINE: u64 = 64 * 1024;
const LOG_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long the last lines get to reach the parent before the launcher exits.
const LOG_FLUSH_WAIT: Duration = Duration::from_secs(2);

impl Stream for VsockStream {
    fn try_clone(&self) -> io::Result<Self> {
        VsockStream::try_clone(self)
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

pub(crate) fn log(msg: &str) {
    // Nowhere to report a failed write to.
    io::stderr()
        .write_all(format!("oprf-enclave-launcher: {msg}\n").as_bytes())
        .ok();
}

pub(crate) fn run() -> ExitCode {
    let (pump, logs) = match start_log_pump() {
        Ok(started) => started,
        Err(err) => {
            log(&format!("log pump: {err}"));
            return ExitCode::FAILURE;
        }
    };
    // A panic has already printed its message to the pipe; returning instead of unwinding
    // out of main lets the pump deliver it.
    let code = match panic::catch_unwind(AssertUnwindSafe(|| boot(&logs))) {
        Ok(Ok(code)) => code,
        Ok(Err(err)) => {
            log(&err);
            ExitCode::FAILURE
        }
        Err(_) => ExitCode::FAILURE,
    };
    drop(logs);
    flush_logs(pump);
    code
}

fn boot(logs: &PipeWriter) -> Result<ExitCode, String> {
    loopback_up().map_err(|e| format!("loopback: {e}"))?;

    let bootstrap = fetch_bootstrap()?;
    let key_arn = bootstrap.kms_key_arn.clone();
    let kms_port = bootstrap.kms_vsock_port;
    let kms_line = kms_forward_line(&key_arn, kms_port)?;
    let kms = Table::parse(&kms_line)?;
    write_hosts(&kms)?;
    for o in kms.outbound {
        start_outbound(o)?;
    }

    log(&format!(
        "bootstrap received, decrypting with {key_arn} via vsock port {kms_port}"
    ));
    let plaintext = decrypt_config(&bootstrap, &key_arn)?;
    drop(bootstrap);
    let config = EnclaveConfig::from_json(&plaintext)?;
    drop(plaintext);
    // Before any of the blob's forwards or the app start.
    check_key(&key_arn, &config)?;
    let table = combined_table(&kms_line, &config.public.forwards, kms_port)?;
    log(&format!(
        "config decrypted: {} public and {} secret environment keys, {} forwards",
        config.public.environment.len(),
        config.secret_environment.len(),
        table.outbound.len() - 1 + table.inbound.len()
    ));
    write_hosts(&table)?;
    // outbound[0] is the KMS forward started above.
    for o in table.outbound.into_iter().skip(1) {
        start_outbound(o)?;
    }
    for i in table.inbound {
        start_inbound(i)?;
    }
    log(&config.hash_line());
    start_attestation(&config)?;

    run_app(&app::path()?, &config.app_environment(), logs)
}

/// Binds before the app starts, so a taken address fails the boot; each request is answered by
/// a fresh NSM call binding the config's public hash and the caller's nonce.
fn start_attestation(config: &EnclaveConfig) -> Result<(), String> {
    let listener = TcpListener::bind(LAUNCHER_ADDR)
        .map_err(|e| format!("attestation {LAUNCHER_ADDR}: {e}"))?;
    let user_data = user_data(&config.public_sha256());
    log(&format!("attestation on {LAUNCHER_ADDR}"));
    thread::spawn(move || {
        serve(
            listener,
            move |nonce| nsm::attestation(Some(user_data.clone()), Some(nonce.to_vec()), None),
            log,
        );
    });
    Ok(())
}

/// Starts the pump's reader before fd 2 points at the pipe: a pipe nobody drains would block
/// the first `log()` once its buffer fills.
fn start_log_pump() -> io::Result<(PumpHandle, PipeWriter)> {
    let (reader, writer) = io::pipe()?;
    let pump = spawn_pump(
        BufReader::new(reader),
        connect_log_sink,
        PumpOpts {
            queue: 1024,
            retry: Duration::from_secs(1),
        },
    );
    // SAFETY: dup2(2) on two descriptors this process owns; fd 2 is replaced atomically.
    if unsafe { libc::dup2(writer.as_raw_fd(), libc::STDERR_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((pump, writer))
}

/// The connect itself has no timeout argument (vsock 0.5.4), but Linux bounds a blocking
/// vsock connect by the socket's connect timeout, 2 s by default
/// (`VSOCK_DEFAULT_CONNECT_TIMEOUT`, `net/vmw_vsock/af_vsock.c`, v7.2 as in the EIF); a parent
/// port without a listener answers with a reset at once. Only the pump's writer thread waits
/// here, never its reader.
fn connect_log_sink() -> io::Result<VsockStream> {
    let sink = VsockStream::connect_with_cid_port(PARENT_CID, LOG_PORT)?;
    sink.set_write_timeout(Some(LOG_WRITE_TIMEOUT))?;
    Ok(sink)
}

/// Lets the pump deliver what is still queued, for at most [`LOG_FLUSH_WAIT`]: in production
/// mode the parent's copy of these lines is the only diagnostic.
fn flush_logs(pump: PumpHandle) {
    // With the app gone and the launcher's writer dropped, fd 2 is the pipe's last writer;
    // pointing it elsewhere gives the pump's reader EOF.
    if let Ok(null) = File::options().write(true).open("/dev/null") {
        // SAFETY: dup2(2) on two descriptors this process owns.
        unsafe { libc::dup2(null.as_raw_fd(), libc::STDERR_FILENO) };
    }
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        pump.join();
        done_tx.send(()).ok();
    });
    done_rx.recv_timeout(LOG_FLUSH_WAIT).ok();
}

fn fetch_bootstrap() -> Result<Bootstrap, String> {
    let err = |e: io::Error| format!("bootstrap vsock {PARENT_CID}:{BOOTSTRAP_PORT}: {e}");
    let stream = VsockStream::connect_with_cid_port(PARENT_CID, BOOTSTRAP_PORT).map_err(err)?;
    stream
        .set_read_timeout(Some(BOOTSTRAP_READ_TIMEOUT))
        .map_err(err)?;
    let mut line = Vec::new();
    BufReader::new(stream.take(MAX_BOOTSTRAP_LINE + 1))
        .read_until(b'\n', &mut line)
        .map_err(err)?;
    if line.len() as u64 > MAX_BOOTSTRAP_LINE {
        return Err(format!(
            "bootstrap line longer than {MAX_BOOTSTRAP_LINE} bytes"
        ));
    }
    let line = String::from_utf8(line).map_err(|_| "bootstrap line is not UTF-8".to_owned())?;
    Bootstrap::from_line(&line)
}

fn write_hosts(table: &Table) -> Result<(), String> {
    std::fs::write("/etc/hosts", table.hosts()).map_err(|e| format!("/etc/hosts: {e}"))
}

fn run_app(
    app: &str,
    environment: &BTreeMap<String, String>,
    logs: &PipeWriter,
) -> Result<ExitCode, String> {
    let clone = || logs.try_clone().map_err(|e| format!("log pipe: {e}"));
    log(&format!("starting {app} as {APP_ID}:{APP_ID}"));
    // Setting the uid as root also clears supplementary groups (std calls setgroups(0)).
    let status = Command::new(app)
        .env_clear()
        .envs(environment)
        .uid(APP_ID)
        .gid(APP_ID)
        .current_dir(APP_DIR)
        .stdout(clone()?)
        .stderr(clone()?)
        .status()
        .map_err(|e| format!("cannot start {app}: {e}"))?;
    log(&format!("{app} exited: {status}"));
    Ok(status
        .code()
        .and_then(|c| u8::try_from(c).ok())
        .map_or(ExitCode::FAILURE, ExitCode::from))
}

fn start_outbound(o: Outbound) -> Result<(), String> {
    let listener = TcpListener::bind((o.ip, o.port))
        .map_err(|e| format!("outbound {}:{}: {e}", o.host, o.port))?;
    log(&format!(
        "outbound {}:{} ({}) -> vsock {}:{}",
        o.host, o.port, o.ip, PARENT_CID, o.vsock_port
    ));
    thread::spawn(move || serve_outbound(&listener, &o));
    Ok(())
}

fn start_inbound(i: Inbound) -> Result<(), String> {
    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, i.vsock_port)
        .map_err(|e| format!("inbound vsock :{}: {e}", i.vsock_port))?;
    log(&format!(
        "inbound vsock :{} -> 127.0.0.1:{}",
        i.vsock_port, i.tcp_port
    ));
    thread::spawn(move || serve_inbound(&listener, &i));
    Ok(())
}

fn serve_outbound(listener: &TcpListener, o: &Outbound) {
    for conn in listener.incoming() {
        let forwarded = conn.and_then(|tcp| {
            let vsock = VsockStream::connect_with_cid_port(PARENT_CID, o.vsock_port)?;
            thread::spawn(move || relay(tcp, vsock));
            Ok(())
        });
        if let Err(err) = forwarded {
            log(&format!("outbound {}:{}: {err}", o.host, o.port));
        }
    }
}

fn serve_inbound(listener: &VsockListener, i: &Inbound) {
    for conn in listener.incoming() {
        let forwarded = conn.and_then(|vsock| {
            let tcp = TcpStream::connect(("127.0.0.1", i.tcp_port))?;
            thread::spawn(move || relay(vsock, tcp));
            Ok(())
        });
        if let Err(err) = forwarded {
            log(&format!("inbound vsock :{}: {err}", i.vsock_port));
        }
    }
}

/// Sets `IFF_UP` on `lo`; the kernel then assigns 127.0.0.1/8.
fn loopback_up() -> io::Result<()> {
    // SAFETY: socket(2) with constant arguments; the result is checked below.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a valid descriptor that nothing else owns.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: ifreq is plain old data, for which all-zero bytes are valid.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in req.ifr_name.iter_mut().zip(b"lo") {
        *dst = libc::c_char::from_ne_bytes([*src]);
    }
    #[allow(
        clippy::unnecessary_fallible_conversions,
        reason = "Ioctl is c_int on musl but c_ulong, like the constants, on glibc"
    )]
    let (get, set) = (
        libc::Ioctl::try_from(libc::SIOCGIFFLAGS).expect("SIOCGIFFLAGS fits in Ioctl"),
        libc::Ioctl::try_from(libc::SIOCSIFFLAGS).expect("SIOCSIFFLAGS fits in Ioctl"),
    );
    // SAFETY: SIOCGIFFLAGS writes the interface flags into `req`, a valid ifreq.
    if unsafe { libc::ioctl(sock.as_raw_fd(), get, &raw mut req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let up = libc::c_short::try_from(libc::IFF_UP).expect("IFF_UP fits in c_short");
    // SAFETY: SIOCGIFFLAGS initialised the union's flags member.
    unsafe { req.ifr_ifru.ifru_flags |= up };
    // SAFETY: SIOCSIFFLAGS only reads `req`, a valid ifreq naming lo.
    if unsafe { libc::ioctl(sock.as_raw_fd(), set, &raw const req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
