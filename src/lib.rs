#![forbid(unsafe_code)]

//! Streams that arrive as files on an SMB share. One file is one Stream,
//! its name kept beside it.
//!
//! SMB is the file share every Windows network already has, and a folder
//! on one is a drop box a partner writes into and an integrator reads out
//! of. What is spoken here is SMB2, dialect 2.0.2, over TCP on port 445
//! (`wire.rs`): `NEGOTIATE`, `SESSION_SETUP` with the `NTLMSSP` tokens
//! (`ntlm.rs`), `TREE_CONNECT` to one share, then `CREATE`, `WRITE`, `READ`,
//! `CLOSE` and `QUERY_DIRECTORY` over one file (`message.rs`). A Receive
//! Location lists the share and reads each file, removing it once it is
//! safely a Stream; a Send Location creates and writes. Either may instead
//! accept clients directly through [`Session`], one client's worth of
//! server over one share in memory.
//!
//! The `NTLMv2` response a real `SESSION_SETUP` carries is not computed here:
//! it is an `HMAC-MD5` over an MD4 of the password, one mechanism at one
//! gate that belongs to the identity capability (ADR-0044, ADR-0050),
//! which will lift `ntlm.rs`. Until it does the logon is taken as a guest,
//! the way TLS is the transport capability's (ADR-0033); message signing
//! is left off, so a server that requires it refuses, and this transport
//! says so.
//!
//! SMB has artefacts and its byte-range and share-mode locks, but a whole
//! file taken and removed needs none of them, so [`Transport::claims`]
//! answers [`NoNativeClaim`], ADR-0024 clause 5: a producer writes to a
//! temporary name and renames, or a Location waits for a listing to stop
//! changing.
//!
//! The origin URI carries what the server knew: `smb://server/share/name`.
//! A send target is `smb://host:445/share/name`, or a name alone on the
//! configured server and share.

pub mod client;
pub mod directory;
pub mod message;
pub mod ntlm;
pub mod session;
pub mod wire;

use std::net::TcpListener;
use std::time::Duration;

pub use client::Client;
pub use ntlm::Identity;
pub use session::{Event, Session};
use transport::error::{Result, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{Arrived, Directions, NoNativeClaim, ResourceClaim, Transport};

/// The one file the loopback pair puts on the share.
const LOOPBACK_FILE: &str = "probe.bin";

#[derive(Clone)]
pub struct SmbTransport {
    server: String,
    share: String,
    identity: Identity,
    delete_after_retrieve: bool,
    timeout: Option<Duration>,
}

impl SmbTransport {
    /// Speak to the server at `server` — `host:445` — about `share`, as a
    /// guest until [`Self::as_identity`].
    #[must_use]
    pub fn new(server: impl Into<String>, share: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            share: share.into(),
            identity: Identity {
                domain: "WORKGROUP".to_string(),
                user: "xmip".to_string(),
                workstation: "XMIP".to_string(),
            },
            delete_after_retrieve: true,
            timeout: None,
        }
    }

    /// Present this identity in the session setup.
    #[must_use]
    pub fn as_identity(mut self, identity: Identity) -> Self {
        self.identity = identity;
        self
    }

    /// Leave read files in place rather than removing them.
    #[must_use]
    pub const fn leaving_files(mut self) -> Self {
        self.delete_after_retrieve = false;
        self
    }

    /// Give up on a server that stops mid-answer.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The share path a tree connect names.
    fn share_path(server: &str, share: &str) -> String {
        let host = server.split(':').next().unwrap_or(server);
        format!(r"\\{host}\{share}")
    }

    /// Connect and connect the tree.
    ///
    /// # Errors
    /// Where the server could not be reached or refused.
    pub fn connect(&self) -> Result<Client> {
        self.connect_to(&self.server, &self.share)
    }

    fn connect_to(&self, server: &str, share: &str) -> Result<Client> {
        Client::connect(
            server,
            &Self::share_path(server, share),
            &self.identity,
            self.timeout,
        )
    }

    /// Bind as the far end clients connect to, and report the address.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.server)
    }

    /// Accept one client on an already-bound listener.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Session> {
        Session::accept(listener, self.timeout)
    }

    /// Where a target names the server, share and file itself —
    /// `smb://host:445/share/name` — or is a name alone on this
    /// transport's share.
    fn resolve<'a>(&'a self, target: &'a str) -> Result<(&'a str, &'a str, &'a str)> {
        match socket::target("smb", target) {
            Some((server, path)) => {
                let (share, name) = path
                    .split_once('/')
                    .filter(|(share, name)| !share.is_empty() && !name.is_empty())
                    .ok_or_else(|| {
                        protocol_error(format!("{target:?} is not smb://host/share/name"))
                    })?;
                Ok((server, share, name))
            }
            None if target.contains('/') || target.is_empty() => Err(protocol_error(format!(
                "{target:?} is not a name on {}",
                self.share
            ))),
            None => Ok((&self.server, &self.share, target)),
        }
    }
}

impl Transport for SmbTransport {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// Every file on the share, each removed once read unless the
    /// transport was told to leave them.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let mut client = self.connect()?;
        let mut arrived = Vec::new();
        for name in client.list("*")? {
            let (id, length) = client.open(&name)?;
            let bytes = client.read_all(id, length)?;
            client.close(id)?;
            if self.delete_after_retrieve {
                let handle = client.open_to_delete(&name)?;
                client.close(handle)?;
            }
            let origin = format!("smb://{}/{}/{name}", self.server, self.share);
            arrived.push(Arrived::new(origin, bytes));
        }
        client.logoff()?;
        Ok(arrived)
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (server, share, name) = self.resolve(target)?;
        let mut client = self.connect_to(server, share)?;
        let id = client.create(name)?;
        client.write_all(id, bytes)?;
        client.close(id)?;
        client.logoff()
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl SmbTransport {
    /// Both ends on this machine: an ephemeral local port, the share this
    /// crate's server serves, the loopback timeout on every read.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", session::SHARE).timing_out_after(LOOPBACK_TIMEOUT)
    }
}

/// A bound listener waiting for the one client that writes one file.
struct Listening {
    transport: SmbTransport,
    listener: TcpListener,
    address: String,
}

impl FarEnd for Listening {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let mut session = self.transport.accept_one(&self.listener)?;
        let arrived = session
            .next_store()?
            .ok_or_else(|| protocol_error("the client logged off without writing"))?;
        // Serve the logoff that follows, so the client's goodbye is
        // answered rather than met by a closed socket.
        while session.next_event()?.is_some() {}
        Ok(arrived)
    }
}

impl Loopback for SmbTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind()?;
        Ok(Box::new(Listening {
            transport: self.clone(),
            listener,
            address,
        }))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::new(address, &self.share)
            .timing_out_after(LOOPBACK_TIMEOUT)
            .send(LOOPBACK_FILE, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// The Playground's edge payloads, written here so the crate does not
    /// depend on it.
    fn edge_payloads() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
        ]
    }

    #[test]
    fn the_loopback_writes_one_file_and_takes_it() {
        let pair = SmbTransport::loopback();
        let arrived = pair.round(b"UNA:+.? '").expect("round");
        assert_eq!(arrived.bytes, b"UNA:+.? '");
        assert!(arrived.origin_uri.starts_with("smb://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/xmip/probe.bin"));
        let long: Vec<u8> = (0..2_000_000u32).map(|n| (n % 251) as u8).collect();
        assert_eq!(pair.round(&long).expect("chunks").bytes, long);
        assert_eq!(pair.name(), "smb");
        assert_eq!(pair.directions(), Directions::BOTH);
        assert!(pair.claims().is_some(), "files are artefacts");
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = SmbTransport::loopback();
        assert!(pair.ceiling().is_none());
        for (name, payload) in edge_payloads() {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }

    #[test]
    fn a_receive_lists_reads_and_removes_each_file() {
        let far_end = SmbTransport::new("127.0.0.1:0", session::SHARE).timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = SmbTransport::new(address.clone(), session::SHARE).timing_out_after(secs(2));
            let first = near.receive()?;
            let again = SmbTransport::new(address, session::SHARE)
                .leaving_files()
                .timing_out_after(secs(2))
                .receive()?;
            Ok::<_, transport::TransportError>((first, again))
        });
        let mut files = BTreeMap::new();
        files.insert("1.edi".to_string(), b"UNA:+.? '".to_vec());
        files.insert("2.bin".to_string(), vec![0xff, 0x00]);
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_files(files.clone());
        assert_eq!(session.tree(), session::SHARE);
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("event") {
            events.push(event);
        }
        assert!(events.contains(&Event::Read("1.edi".to_string())));
        assert!(events.contains(&Event::Removed("1.edi".to_string())));
        assert!(session.files().is_empty(), "removed after read");
        let mut session = far_end
            .accept_one(&listener)
            .expect("again")
            .with_files(files);
        while session.next_event().expect("event").is_some() {}
        assert_eq!(session.files().len(), 2, "left in place");
        let (first, again) = receiver.join().expect("thread").expect("receiving");
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].bytes, b"UNA:+.? '");
        assert!(first[0].origin_uri.ends_with("/xmip/1.edi"));
        assert_eq!(first[1].bytes, [0xff, 0x00]);
        assert_eq!(again.len(), 2);
    }

    #[test]
    fn the_wrong_share_a_missing_file_and_a_bad_target_are_refused() {
        let far_end = SmbTransport::new("127.0.0.1:0", session::SHARE).timing_out_after(secs(2));
        assert!(far_end.resolve("a/b").is_err(), "not a name");
        assert!(far_end.resolve("smb://h/only").is_err(), "no file");
        assert_eq!(
            far_end.resolve("smb://h:445/data/1.edi").expect("full"),
            ("h:445", "data", "1.edi")
        );
        assert_eq!(
            far_end.resolve("1.edi").expect("name"),
            ("127.0.0.1:0", session::SHARE, "1.edi")
        );
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            let wrong = SmbTransport::new(address.clone(), "nosuch")
                .timing_out_after(secs(2))
                .send("x.edi", b"x");
            let missing = SmbTransport::new(address, session::SHARE)
                .timing_out_after(secs(2))
                .receive();
            (wrong, missing)
        });
        let refused = far_end.accept_one(&listener).err().expect("bad share");
        assert!(refused.message.contains("nosuch"), "{refused}");
        let mut session = far_end.accept_one(&listener).expect("empty share");
        while session.next_event().expect("event").is_some() {}
        let (wrong, missing) = sender.join().expect("thread");
        assert!(
            wrong
                .expect_err("bad share")
                .message
                .contains("no such share")
        );
        assert!(missing.expect("empty receive").is_empty());
    }
}
