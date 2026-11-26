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
//! Location lists the share and hands each file back unread, read a `READ`
//! at a time as the runtime asks and removed only when its receive cycle
//! accepted it ([`connection`]); a refused file is left where it lies and
//! not received again while it is unchanged. A Send Location creates and
//! writes. Either may instead
//! accept clients directly through [`Session`], one client's worth of
//! server over one share in memory.
//!
//! A Location that names a secret logs on with its password, the `NTLMv2`
//! response computed from it as the estate computes it once
//! (`ntlm::response`) and read as each session is set up ([`logon`]); one
//! that names none logs on as a guest. Message signing is left off, so a
//! server that requires it refuses, and this transport says so.
//!
//! SMB has artifacts and its byte-range and share-mode locks, but a whole
//! file taken and removed needs none of them, so [`Transport::claims`]
//! answers [`NoNativeClaim`], ADR-0024 clause 5: a producer writes to a
//! temporary name and renames, or a Location waits for a listing to stop
//! changing.
//!
//! The origin URI carries what the server knew: `smb://server/share/name`.
//! A send target is `smb://host:445/share/name`, or a name alone on the
//! configured server and share.
//!
//! **Built with its `declaration` feature alone** the crate is
//! [`declaration`], what a Location of it is configured with, and none of
//! the code above, which is behind the default feature: what the surfaces'
//! library carries (ADR-0064, amendment 2026-11-26).

#[cfg(feature = "default")]
pub mod client;
#[cfg(feature = "default")]
pub mod connection;
#[cfg(feature = "declaration")]
pub mod declaration;
#[cfg(feature = "default")]
pub mod directory;
#[cfg(feature = "default")]
pub mod logon;
#[cfg(feature = "default")]
pub mod message;
#[cfg(feature = "default")]
pub mod session;
#[cfg(feature = "default")]
pub mod wire;

#[cfg(feature = "default")]
use std::{net::TcpListener, sync::Arc, time::Duration};

#[cfg(feature = "default")]
pub use client::{Client, Identity};
#[cfg(feature = "default")]
pub use connection::Connection;
#[cfg(feature = "default")]
pub use directory::Stamp;
#[cfg(feature = "default")]
use net::Target;
#[cfg(feature = "default")]
pub use session::{Event, Session};
#[cfg(feature = "default")]
use transport::error::{Result, protocol_error};
#[cfg(feature = "default")]
use transport::listening::{Accepting, Listening};
#[cfg(feature = "default")]
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
#[cfg(feature = "default")]
use transport::{ArrivalIdentity, socket, taken::Taken};
#[cfg(feature = "default")]
use transport::{
    Arrived, Configured, Directions, NoNativeClaim, Pool, Refused, ResourceClaim, Transport,
};
#[cfg(feature = "default")]
use xcore::settings::{Read, Settings};

/// The one file the loopback pair puts on the share.
#[cfg(feature = "default")]
const LOOPBACK_FILE: &str = "probe.bin";

#[cfg(feature = "default")]
#[derive(Clone)]
pub struct SmbTransport {
    server: String,
    share: String,
    identity: Identity,
    /// The secret its Location names, whose password the logon presents.
    secret: Option<transport::Secured>,
    /// The one login a far end admits, where it is given one.
    admitted: Option<transport::Login>,
    /// The node's Clock, which the response's blob is made at.
    clock: Arc<dyn xcore::Clock>,
    delete_after_retrieve: bool,
    timeout: Option<Duration>,
    /// The sessions a send writes on and a receive reads on, set up once per
    /// server and share and kept, shared with what a receive handed back.
    sessions: Pool<Connection>,
    /// The files this Location refused and left where they lie, each with
    /// its stamp; the node process's, so a node started again receives
    /// them once more. Cloned, the transport shares it.
    refused: Refused<String, Stamp>,
}

#[cfg(feature = "default")]
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
            secret: None,
            admitted: None,
            clock: Arc::new(xcore::SystemClock),
            delete_after_retrieve: true,
            timeout: None,
            sessions: Pool::new(),
            refused: Refused::default(),
        }
    }

    /// Present this identity in the session setup.
    #[must_use]
    pub fn as_identity(mut self, identity: Identity) -> Self {
        self.identity = identity;
        self
    }

    /// As a far end, admit `login` alone, refusing any other logon.
    #[must_use]
    pub fn admitting(mut self, login: transport::Login) -> Self {
        self.admitted = Some(login);
        self
    }

    /// Leave accepted files in place rather than removing them.
    #[must_use]
    pub const fn leaving_files(mut self) -> Self {
        self.delete_after_retrieve = false;
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

    /// Connect to `share` on `server`, the Location's secret read now where
    /// it names one: each new session reads it, a kept one never again.
    fn connect_to(&self, server: &str, share: &str) -> Result<Client> {
        let now = u64::try_from(self.clock.unix_seconds()).unwrap_or_default();
        let logon = logon::Logon::presented(self.identity.clone(), self.secret.as_ref(), now)?;
        let path = Self::share_path(server, share);
        Client::connect(server, &path, &logon, self.timeout)
    }

    /// Bind as the far end clients connect to, and report the address.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.server)
    }

    /// Accept one client on an already-bound listener, admitting only the
    /// login [`Self::admitting`] gave, where it gave one.
    ///
    /// # Errors
    /// Where the connection could not be accepted, or the logon was refused.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Session> {
        Session::accept(listener, self.admitted.as_ref(), self.timeout)
    }

    /// Where a target names the server, share and file itself —
    /// `smb://host:445/share/name` — or is a name alone on this
    /// transport's share.
    fn resolve<'a>(&'a self, target: &'a str) -> Result<(&'a str, &'a str, &'a str)> {
        match Target::under(Self::SCHEMES, target).map(|named| (named.authority(), named.path())) {
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

#[cfg(feature = "default")]
impl Transport for SmbTransport {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a receive lists again what is not yet told")
    }

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Polled("a receive lists the share and returns")
    }

    /// Every file on the share, listed on the session kept for the server
    /// and share — set up on the first receive — and handed back unread:
    /// each body opens the file on its first read and reads it a `READ` at
    /// a time as the runtime asks; `Accepted` removes it (opened with
    /// delete-on-close, and closed) unless the transport was told to leave
    /// files, `Refused` leaves it and it is not listed again while its
    /// `EndOfFile` and `LastWriteTime` stay as they were, `Failed` leaves it
    /// for the next receive.
    fn receive_up_to(&self, most: usize) -> Result<Vec<Arrived>> {
        self.sessions.exchange(
            &format!("{}/{}", self.server, self.share),
            || self.connect().map(Connection::new),
            |connection| {
                let listed = connection.with(|client| client.list("*"))?;
                let listed = self
                    .refused
                    .sift(listed, |(name, _)| name, |(_, stamp)| Some(*stamp));
                Ok(listed
                    .into_iter()
                    .take(most)
                    .map(|listed| {
                        let origin = format!("smb://{}/{}/{}", self.server, self.share, listed.0);
                        let remove = self.delete_after_retrieve;
                        connection.arrival(origin, listed, remove, &self.refused)
                    })
                    .collect())
            },
        )
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Streamed("each WRITE carries the next piece of the body as it is read")
    }

    /// Create, write and close the file on the session kept for the server
    /// and share, set up on the first send to them.
    fn send_from(&self, target: &str, outgoing: transport::Outgoing<'_>) -> Result<()> {
        let (server, share, name) = self.resolve(target)?;
        self.sessions.exchange(
            &format!("{server}/{share}"),
            || self.connect_to(server, share).map(Connection::new),
            |connection| {
                connection.with(|client| {
                    let id = client.create(name)?;
                    client.write_all(id, &outgoing)?;
                    client.close(id)
                })
            },
        )
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

#[cfg(feature = "default")]
impl Configured for SmbTransport {
    const SETTINGS: &'static Settings = declaration::SETTINGS;
    const SCHEMES: &'static [&'static str] = declaration::SCHEMES;

    fn timeout_kept(&mut self) -> Option<&mut dyn transport::configured::TimeoutKept> {
        Some(&mut self.timeout)
    }

    /// The password is the secret the Location names, never a setting.
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
        Ok(transport)
    }

    /// The password the Location's secret holds, read at each session setup.
    fn secured_by(mut self, secret: transport::Secured) -> Result<Self> {
        self.secret = Some(secret);
        Ok(self)
    }

    /// The node's Clock, which a response's blob is made at.
    fn timed_by(mut self, clock: &Arc<dyn xcore::Clock>) -> Self {
        self.clock = Arc::clone(clock);
        self
    }
}

#[cfg(feature = "default")]
impl SmbTransport {
    /// Both ends on this machine: an ephemeral local port, the share this
    /// crate's server serves, the loopback timeout on every read.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", session::SHARE).timing_out_after(LOOPBACK_TIMEOUT)
    }
}

#[cfg(feature = "default")]
impl Accepting for SmbTransport {
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        // The client keeps its session for the next file.
        self.accept_one(listener)?
            .next_store()?
            .ok_or_else(|| protocol_error("the client logged off without writing"))
    }
}

#[cfg(feature = "default")]
impl Loopback for SmbTransport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::Unnamed(
            "a file names no sender: the share it was taken from is in its origin",
        )
    }

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
    use xcore::settings::Applies;

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
        assert!(pair.claims().is_some(), "files are artifacts");
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
                .receive()?
                .into_iter()
                .map(Arrived::taken)
                .collect::<Result<Vec<_>>>()?;
            let again = SmbTransport::new(address, session::SHARE)
                .leaving_files()
                .timing_out_after(secs(2))
                .receive()?
                .into_iter()
                .map(Arrived::taken)
                .collect::<Result<Vec<_>>>()?;
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
    fn a_failed_file_stays_on_the_share_and_an_accepted_one_is_removed() {
        let far_end = SmbTransport::new("127.0.0.1:0", session::SHARE).timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let long: Vec<u8> = (0..2_500_000u32).map(|n| (n % 251) as u8).collect();
        let expected = long.clone();
        let receiver = std::thread::spawn(move || {
            let near = SmbTransport::new(address, session::SHARE).timing_out_after(secs(2));
            let first = transport::arrived::one_arrival(near.receive()?, "listed")?;
            assert!(first.defers());
            let (_, mut body, acknowledgement) = first.into_parts();
            let mut read = Vec::new();
            std::io::Read::read_to_end(&mut body, &mut read).expect("reading");
            drop(body);
            acknowledgement.acknowledge(transport::Verdict::Failed)?;
            let again = transport::arrived::one_arrival(near.receive()?, "listed again")?;
            let taken = again.taken()?;
            Ok::<_, transport::TransportError>((read, taken, near.receive()?.len()))
        });
        let files = BTreeMap::from([("1.bin".to_string(), long)]);
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_files(files);
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("event") {
            events.push(event);
        }
        let (read, taken, after) = receiver.join().expect("thread").expect("receiving");
        assert_eq!(read, expected, "read in chunks to its end");
        assert_eq!(taken.bytes, expected);
        assert_eq!(after, 0, "accepted, so not listed again");
        let removed = Event::Removed("1.bin".to_string());
        assert_eq!(
            events.iter().filter(|event| **event == removed).count(),
            1,
            "the failed read removed nothing: {events:?}"
        );
        assert!(session.files().is_empty(), "removed once accepted");
    }

    #[test]
    fn a_refused_file_stays_unlisted_while_unchanged_and_written_again_arrives_again() {
        let far_end = SmbTransport::new("127.0.0.1:0", session::SHARE).timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = SmbTransport::new(address, session::SHARE).timing_out_after(secs(2));
            let first = transport::arrived::one_arrival(near.receive()?, "listed")?;
            first.refused(transport::Refusal::Forbidden)?;
            let unchanged = near.receive()?.len();
            near.send("1.bin", b"written again")?;
            let again = transport::arrived::one_arrival(near.receive()?, "written again")?;
            let (_, mut body, acknowledgement) = again.into_parts();
            let mut read = Vec::new();
            std::io::Read::read_to_end(&mut body, &mut read).expect("reading");
            drop(body);
            acknowledgement
                .acknowledge(transport::Verdict::Refused(transport::Refusal::Forbidden))?;
            Ok::<_, transport::TransportError>((unchanged, read, near.receive()?.len()))
        });
        let files = BTreeMap::from([("1.bin".to_string(), b"refused".to_vec())]);
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_files(files);
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("event") {
            events.push(event);
        }
        let (unchanged, read, after) = receiver.join().expect("thread").expect("receiving");
        assert_eq!(unchanged, 0, "the refused file lies there unchanged");
        assert_eq!(read, b"written again", "written again, a new arrival");
        assert_eq!(after, 0, "refused again, and unchanged since");
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Removed(_))),
            "{events:?}"
        );
        assert_eq!(
            session
                .files()
                .get("1.bin")
                .expect("the refused file lies there"),
            b"written again"
        );
    }

    #[test]
    fn a_thousand_files_set_up_once_and_a_session_the_server_closed_is_replaced() {
        const SENDS: usize = 1000;
        let far_end = SmbTransport::new("127.0.0.1:0", session::SHARE).timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = SmbTransport::new(address, session::SHARE).timing_out_after(secs(5));
        let sending = near.clone();
        let sender = std::thread::spawn(move || {
            for n in 0..SENDS {
                sending.send(&format!("{n}.edi"), n.to_string().as_bytes())?;
            }
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
            for _ in 0..RECEIVES {
                assert!(near.receive()?.is_empty());
            }
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
    fn the_password_is_the_locations_secret_read_at_each_session_setup() {
        use transport::secured::Kept;
        use xcore::SecretKind::Password;
        use xcore::settings::Given;
        let kept = Arc::new(Kept::default());
        let drawn = Kept::drawn();
        let far_end = SmbTransport::new("127.0.0.1:0", session::SHARE)
            .admitting(transport::Login::new("orders", &drawn))
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let given = [
            text("share", session::SHARE),
            text("user", "orders"),
            text("timeout", "2s"),
        ];
        let near = SmbTransport::open(&format!("smb://{address}"), Applies::Send, &given)
            .expect("built")
            .secured_by(kept.secured("partner-x.smb"))
            .expect("kept");
        let unset = near.send("1.edi", b"x").expect_err("not set");
        assert!(unset.retryable, "asked again at the next session setup");
        assert!(unset.message.contains("is not set"), "{unset}");

        kept.set("partner-x.smb", Password, &format!("{drawn}-wrong"));
        let sending = near.clone();
        let sender = std::thread::spawn(move || sending.send("1.edi", b"x").err());
        let refused = far_end.accept_one(&listener).err().expect("refused");
        assert!(refused.message.contains("the logon failed"), "{refused}");
        let wrong = sender.join().expect("thread").expect("refused");
        assert!(
            wrong.message.contains("the logon failed (0xc000006d)"),
            "{wrong}"
        );
        assert!(!wrong.retryable, "{wrong}");

        kept.set("partner-x.smb", Password, &drawn);
        let sending = near.clone();
        let sender = std::thread::spawn(move || sending.send("1.edi", b"right"));
        let mut session = far_end.accept_one(&listener).expect("admitted");
        let stored = session.next_store().expect("stored").expect("one");
        assert_eq!(stored.bytes, b"right");
        sender.join().expect("thread").expect("sent");

        let guest = SmbTransport::new(address, session::SHARE).timing_out_after(secs(2));
        let sender = std::thread::spawn(move || guest.send("1.edi", b"x").err());
        let refused = far_end
            .accept_one(&listener)
            .err()
            .expect("a guest refused");
        assert!(refused.message.contains("the logon failed"), "{refused}");
        sender.join().expect("thread").expect("refused");
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
