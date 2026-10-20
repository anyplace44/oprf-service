//! Enclave-side runtime: loopback, forwarders, the enclave app.

use std::io::{self, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};
use std::thread;

use vsock::{VMADDR_CID_ANY, VsockListener, VsockStream};

use crate::app::parse_app;
use crate::relay::{Stream, relay};
use taceo_oprf_enclave_launcher::table::{Inbound, Outbound, Table};

const FORWARDS_PATH: &str = "/etc/enclave/forwards";
/// Absolute path of the program to run, written by the image's Dockerfile.
const APP_PATH: &str = "/etc/enclave/app";
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

impl Stream for VsockStream {
    fn try_clone(&self) -> io::Result<Self> {
        VsockStream::try_clone(self)
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

pub(crate) fn log(msg: &str) {
    // Nowhere to report a failed write to the console.
    io::stderr()
        .write_all(format!("oprf-enclave-launcher: {msg}\n").as_bytes())
        .ok();
}

pub(crate) fn run() -> ExitCode {
    let app = match read_app() {
        Ok(app) => app,
        Err(err) => {
            log(&format!("cannot read {APP_PATH}: {err}"));
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = start_forwarding() {
        log(&format!("setup failed: {err}"));
        return ExitCode::FAILURE;
    }
    log(&format!("starting {app} as {APP_ID}:{APP_ID}"));
    // The environment is the one nit read from /etc/environment. Setting the
    // uid as root also clears supplementary groups (std calls setgroups(0)).
    let status = Command::new(&app)
        .uid(APP_ID)
        .gid(APP_ID)
        .current_dir(APP_DIR)
        .status();
    match status {
        Ok(status) => {
            log(&format!("{app} exited: {status}"));
            status
                .code()
                .and_then(|c| u8::try_from(c).ok())
                .map_or(ExitCode::FAILURE, ExitCode::from)
        }
        Err(err) => {
            log(&format!("cannot start {app}: {err}"));
            ExitCode::FAILURE
        }
    }
}

fn read_app() -> io::Result<String> {
    parse_app(&std::fs::read_to_string(APP_PATH)?).map_err(io::Error::other)
}

fn start_forwarding() -> io::Result<()> {
    loopback_up()?;
    let table = Table::parse(&std::fs::read_to_string(FORWARDS_PATH)?).map_err(io::Error::other)?;
    std::fs::write("/etc/hosts", table.hosts())?;
    for o in table.outbound {
        let listener = TcpListener::bind((o.ip, o.port))?;
        log(&format!(
            "outbound {}:{} ({}) -> vsock {}:{}",
            o.host, o.port, o.ip, PARENT_CID, o.vsock_port
        ));
        thread::spawn(move || serve_outbound(&listener, &o));
    }
    for i in table.inbound {
        let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, i.vsock_port)?;
        log(&format!(
            "inbound vsock :{} -> 127.0.0.1:{}",
            i.vsock_port, i.tcp_port
        ));
        thread::spawn(move || serve_inbound(&listener, &i));
    }
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
