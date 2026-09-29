#![forbid(unsafe_code)]

//! Streams that arrive as files on an SMB share. One file is one Stream,
//! its name kept beside it.
//!
//! SMB is the file share every Windows network already has, and a folder
//! on one is a drop box a Party writes into and an integrator reads out
//! of. What is spoken here is SMB2, dialect 2.0.2, over TCP on port 445
//! (`wire.rs`): `NEGOTIATE`, `SESSION_SETUP` with the three `NTLMSSP`
//! messages as `xmip-core-library-ntlm` lays them out, `TREE_CONNECT` to one
//! share, then `CREATE`, `WRITE`, `READ`,
//! `CLOSE` and `QUERY_DIRECTORY` over one file (`message.rs`). A Receive
//! Location lists the share and reads each file, removing it once it is
//! safely a Stream; a Send Location creates and writes. Either may instead
//! accept clients directly through [`Session`], one client's worth of
//! server over one share in memory.
//!
//! The `NTLMv2` response a real `SESSION_SETUP` carries is not computed here:
//! it is an `HMAC-MD5` over an MD4 of the password, one mechanism at one
//! gate that belongs to the identity capability (ADR-0044, ADR-0050).
//! Until a node presents one the logon is taken as a guest,
//! the way TLS is `xmip-core-library-tls`'s (ADR-0033); message signing
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
pub mod session;
pub mod wire;

use std::net::TcpListener;
use std::time::Duration;

pub use client::{Client, Identity};
use net::Target;
pub use session::{Event, Session};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{Arrived, Configured, Directions, NoNativeClaim, Pool, ResourceClaim, Transport};
use xcore::settings::{Applies, Kind, Presence, Read, Setting, Settings};

/// The one file the loopback pair puts on the share.
const LOOPBACK_FILE: &str = "probe.bin";

#[derive(Clone)]
pub struct SmbTransport {
    server: String,
    share: String,
    identity: Identity,
    delete_after_retrieve: bool,
    timeout: Option<Duration>,
    /// The sessions a send writes on and a receive reads on, set up once per
    /// server and share and kept.
    sessions: Pool<Client>,
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
            sessions: Pool::new(),
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
        match Target::under(&["smb"], target).map(|named| (named.authority(), named.path())) {
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
    /// transport was told to leave them, on the session kept for the server
    /// and share: set up on the first receive.
    fn receive(&self) -> Result<Vec<Arrived>> {
        self.sessions.exchange(
            &format!("{}/{}", self.server, self.share),
            || self.connect(),
            |client| {
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
                Ok(arrived)
            },
        )
    }

    /// Create, write and close the file on the session kept for the server
    /// and share, set up on the first send to them.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (server, share, name) = self.resolve(target)?;
        self.sessions.exchange(
            &format!("{server}/{share}"),
            || self.connect_to(server, share),
            |client| {
                let id = client.create(name)?;
                client.write_all(id, bytes)?;
                client.close(id)
            },
        )
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl Configured for SmbTransport {
    /// The address is the server, `host:445`: where a Location connects.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "share",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The share a Receive Location lists and a Send Location writes into \
                          when a target names none.",
                applies: Applies::Both,
            },
            Setting {
                name: "domain",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The domain the session setup presents; `WORKGROUP` when left out.",
                applies: Applies::Both,
            },
            Setting {
                name: "user",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The user the session setup presents; `xmip` when left out.",
                applies: Applies::Both,
            },
            Setting {
                name: "workstation",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The workstation the session setup presents; `XMIP` when left out.",
                applies: Applies::Both,
            },
            Setting {
                name: "leave_files",
                kind: Kind::Boolean,
                presence: Presence::Optional,
                meaning: "Whether a Receive Location leaves the files it read in place; each is \
                          removed once read when left out.",
                applies: Applies::Receive,
            },
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a server that stops mid-answer is waited on; unbounded when \
                          left out.",
                applies: Applies::Both,
            },
        ],
    };

    /// A password, once the identity capability computes the `NTLMv2`
    /// response, comes through the Location's credentials, not a setting.
    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let mut transport = Self::new(address, settings.text("share"));
        let mut identity = transport.identity.clone();
        if let Some(domain) = settings.optional_text("domain") {
            identity.domain = domain.to_string();
        }
        if let Some(user) = settings.optional_text("user") {
            identity.user = user.to_string();
        }
        if let Some(workstation) = settings.optional_text("workstation") {
            identity.workstation = workstation.to_string();
        }
        transport = transport.as_identity(identity);
        if settings.optional_boolean("leave_files") == Some(true) {
            transport = transport.leaving_files();
        }
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        Ok(transport)
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

impl Accepting for SmbTransport {
    fn take_one(self, listener: &TcpListener) -> Result<Arrived> {
        // The client keeps its session for the next file.
        self.accept_one(listener)?
            .next_store()?
            .ok_or_else(|| protocol_error("the client logged off without writing"))
    }
}

impl Loopback for SmbTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
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
    use transport::payload::edge_payloads;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn smb_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(SmbTransport::SETTINGS.problems(), Vec::<String>::new());
        let given = [
            ("share".to_string(), Given::Text("inbox".to_string())),
            ("domain".to_string(), Given::Text("PARTY".to_string())),
            ("leave_files".to_string(), Given::Boolean(true)),
            ("timeout".to_string(), Given::Text("2s".to_string())),
        ];
        let built = SmbTransport::open("server:445", Applies::Receive, &given).expect("configured");
        assert_eq!(built.share, "inbox");
        assert_eq!(built.identity.domain, "PARTY");
        assert_eq!(built.identity.user, "xmip");
        assert!(!built.delete_after_retrieve);
        assert_eq!(built.timeout, Some(secs(2)));
        let Err(refused) = SmbTransport::open("server:445", Applies::Send, &given) else {
            panic!("a Send Location removes nothing");
        };
        assert!(refused.message.contains("\"leave_files\""), "{refused}");
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
            // Two transports, so two sessions: each keeps its own.
            let first = SmbTransport::new(address.clone(), session::SHARE)
                .timing_out_after(secs(2))
                .receive()?;
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
    fn a_thousand_files_set_up_once_and_a_session_the_server_closed_is_replaced() {
        const SENDS: usize = 1000;
        let far_end = SmbTransport::new("127.0.0.1:0", session::SHARE).timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = SmbTransport::new(address, session::SHARE).timing_out_after(secs(5));
        let sending = near.clone();
        let sender = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            for n in 0..SENDS {
                sending.send(&format!("{n}.edi"), n.to_string().as_bytes())?;
            }
            let took = began.elapsed();
            // Generous for a debug build under load: a millisecond a file.
            assert!(took < Duration::from_millis(SENDS as u64), "{took:?}");
            sending.send("last.edi", b"after the close")
        });
        // One negotiate, session setup and tree connect for every file.
        let mut session = far_end.accept_one(&listener).expect("accepting");
        for n in 0..SENDS {
            let stored = session.next_store().expect("store").expect("one");
            assert_eq!(stored.bytes, n.to_string().as_bytes());
        }
        drop(session);
        let mut again = far_end.accept_one(&listener).expect("a new session");
        let last = again.next_store().expect("store").expect("one");
        assert_eq!(last.bytes, b"after the close");
        sender.join().expect("thread").expect("sending");
        assert_eq!(near.sessions.opened(), 2);
    }

    #[test]
    fn a_thousand_receives_set_up_once_and_a_session_the_server_closed_is_replaced() {
        const RECEIVES: usize = 1000;
        let far_end = SmbTransport::new("127.0.0.1:0", session::SHARE).timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = SmbTransport::new(address, session::SHARE).timing_out_after(secs(5));
        let (go, going) = std::sync::mpsc::channel();
        let receiver = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            for _ in 0..RECEIVES {
                assert!(near.receive()?.is_empty());
            }
            let took = began.elapsed();
            // Generous for a debug build under load: a millisecond a receive.
            assert!(took < Duration::from_millis(RECEIVES as u64), "{took:?}");
            // A send on the same kept session says the receives are done.
            near.send("received.edi", b"received")?;
            going.recv().expect("go");
            Ok::<_, transport::TransportError>((near.receive()?, near.sessions.opened()))
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        let marker = session.next_store().expect("served").expect("the marker");
        assert_eq!(marker.bytes, b"received");
        drop(session);
        go.send(()).expect("went");
        let mut again = far_end.accept_one(&listener).expect("accepting");
        while again.next_event().expect("served").is_some() {}
        let (arrived, opened) = receiver.join().expect("thread").expect("received");
        assert!(arrived.is_empty());
        assert_eq!(opened, 2);
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
