//! The server's side of one connection: what a test puts at the far end,
//! and what a Receive Location that accepts writes directly runs.
//!
//! Not an SMB server. One session answers one client over one share kept
//! in memory: it negotiates the 2.0.2 dialect, sets up a session with the
//! `NTLMSSP` challenge and takes the logon as a guest (the `NTLMv2` check is
//! the identity capability's), connects the one tree, and serves create,
//! write, read, close and query-directory over the files in memory. A
//! file the client wrote is handed up as a Stream when it is closed; a
//! file opened to delete is removed then. One tree, one file at a time.

use std::collections::BTreeMap;
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use transport::Arrived;
use transport::error::{Result, protocol_error};
use transport::socket;

use ntlm::flags::{NEGOTIATE_NTLM, NEGOTIATE_UNICODE};
use ntlm::{Authenticate, Challenge, Negotiate};

use crate::directory;
use crate::message::{self, FileId};
use crate::wire::{self, Message};

/// The share this session serves.
pub const SHARE: &str = "xmip";

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client connected the tree at this share.
    TreeConnected(String),
    /// The client created this name.
    Created(String),
    /// The client wrote this many bytes to this name.
    Written(String, usize),
    /// The client closed a file it had written; here is the Stream.
    Committed(Arrived),
    /// The client read this name.
    Read(String),
    /// The client closed a file opened to delete; it is gone.
    Removed(String),
    /// The client listed the share.
    Listed,
}

/// One open file: its name, whether it has been written, and whether it
/// is to be removed when it closes.
struct Open {
    name: String,
    written: bool,
    delete_on_close: bool,
}

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    peer: SocketAddr,
    id: u64,
    tree: String,
    files: BTreeMap<String, Vec<u8>>,
    handles: BTreeMap<[u8; 16], Open>,
    next_handle: u64,
}

/// Session ids handed out, one a connection.
static SESSIONS: AtomicU64 = AtomicU64::new(1);

impl Session {
    /// Accept one client on `listener`: negotiate, set up the session and
    /// connect the tree.
    ///
    /// # Errors
    /// Where the connection could not be accepted, or the client did not
    /// open with the SMB2 handshake.
    pub fn accept(listener: &TcpListener, timeout: Option<Duration>) -> Result<Self> {
        let (stream, peer) = socket::accept_tcp(listener, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut session = Self {
            reader,
            writer,
            peer,
            id: SESSIONS.fetch_add(1, Ordering::Relaxed),
            tree: String::new(),
            files: BTreeMap::new(),
            handles: BTreeMap::new(),
            next_handle: 1,
        };
        session.negotiate()?;
        session.session_setup()?;
        session.tree_connect()?;
        Ok(session)
    }

    fn negotiate(&mut self) -> Result<()> {
        let request = self.expect(wire::NEGOTIATE)?;
        let answer = request.respond(wire::STATUS_SUCCESS, message::negotiate_response());
        answer.write(&mut self.writer)
    }

    fn session_setup(&mut self) -> Result<()> {
        let negotiate = self.expect(wire::SESSION_SETUP)?;
        let asked = Negotiate::parse(message::session_token(&negotiate.body)?)
            .map_err(|error| protocol_error(error.message))?;
        let nonce = fresh_nonce(&self.peer);
        let offered = Challenge::new(asked.flags & (NEGOTIATE_UNICODE | NEGOTIATE_NTLM), nonce);
        let mut challenge = negotiate.respond(
            wire::STATUS_MORE_PROCESSING,
            message::session_setup(true, &offered.to_bytes()),
        );
        challenge.session_id = self.id;
        challenge.write(&mut self.writer)?;
        let authenticate = self.expect(wire::SESSION_SETUP)?;
        // The NTLMv2 response the identity capability would check is not
        // computed here; the identity is taken and the logon is a guest.
        Authenticate::parse(message::session_token(&authenticate.body)?)
            .map_err(|error| protocol_error(error.message))?;
        let answer = authenticate.respond(wire::STATUS_SUCCESS, message::session_setup(true, &[]));
        answer.write(&mut self.writer)
    }

    fn tree_connect(&mut self) -> Result<()> {
        let request = self.expect(wire::TREE_CONNECT)?;
        let path = message::tree_connect_path(&request.body)?;
        let share = path.rsplit('\\').next().unwrap_or(&path).to_string();
        let (status, body) = if share == SHARE {
            (wire::STATUS_SUCCESS, message::tree_connect_response())
        } else {
            (wire::STATUS_BAD_NETWORK_NAME, Vec::new())
        };
        let mut answer = request.respond(status, body);
        answer.tree_id = 1;
        answer.write(&mut self.writer)?;
        if status != wire::STATUS_SUCCESS {
            return Err(protocol_error(format!(
                "a tree connect for {share:?}, not {SHARE:?}"
            )));
        }
        self.tree = share;
        Ok(())
    }

    /// Serve these files to opens, reads and listings.
    #[must_use]
    pub fn with_files(mut self, files: BTreeMap<String, Vec<u8>>) -> Self {
        self.files = files;
        self
    }

    /// What the share holds now, writes included.
    #[must_use]
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    /// The share the client connected.
    #[must_use]
    pub fn tree(&self) -> &str {
        &self.tree
    }

    /// The next file the client writes and closes, or `None` when it
    /// logged off.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_store(&mut self) -> Result<Option<Arrived>> {
        loop {
            match self.next_event()? {
                Some(Event::Committed(arrived)) => return Ok(Some(arrived)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
    }

    /// The next thing the client did with the share, or `None` when it
    /// logged off or closed the connection.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            let Some(request) = Message::read(&mut self.reader)? else {
                return Ok(None);
            };
            if request.command == wire::LOGOFF {
                return Ok(None);
            }
            if let Some(event) = self.serve(&request)? {
                return Ok(Some(event));
            }
        }
    }

    fn serve(&mut self, request: &Message) -> Result<Option<Event>> {
        match request.command {
            wire::CREATE => self.on_create(request),
            wire::WRITE => self.on_write(request),
            wire::READ => self.on_read(request),
            wire::CLOSE => self.on_close(request),
            wire::QUERY_DIRECTORY => self.on_query(request),
            wire::TREE_DISCONNECT => {
                self.answer(request, wire::STATUS_SUCCESS, vec![4, 0, 0, 0])?;
                Ok(None)
            }
            other => Err(protocol_error(format!(
                "command {other:#06x} after the tree connect"
            ))),
        }
    }

    fn on_create(&mut self, request: &Message) -> Result<Option<Event>> {
        let (name, disposition, options) = message::create_fields(&request.body)?;
        let directory = options & message::FILE_DIRECTORY != 0;
        if !directory && disposition == message::FILE_OPEN && !self.files.contains_key(&name) {
            self.answer(request, wire::STATUS_OBJECT_NAME_NOT_FOUND, Vec::new())?;
            return Ok(None);
        }
        if disposition == message::FILE_OVERWRITE_IF {
            self.files.insert(name.clone(), Vec::new());
        }
        let id = FileId::of(self.next_handle);
        self.next_handle += 1;
        let length = self.files.get(&name).map_or(0, Vec::len) as u64;
        self.handles.insert(
            id.0,
            Open {
                name: name.clone(),
                written: false,
                delete_on_close: options & message::FILE_DELETE_ON_CLOSE != 0,
            },
        );
        self.answer(
            request,
            wire::STATUS_SUCCESS,
            message::create_response(id, length),
        )?;
        if directory {
            Ok(None)
        } else {
            Ok(Some(Event::Created(name)))
        }
    }

    fn on_write(&mut self, request: &Message) -> Result<Option<Event>> {
        let (id, offset, data) = message::write_fields(&request.body)?;
        let Some(open) = self.handles.get_mut(&id.0) else {
            self.answer(request, wire::STATUS_OBJECT_NAME_NOT_FOUND, Vec::new())?;
            return Ok(None);
        };
        open.written = true;
        let name = open.name.clone();
        let bytes = self.files.entry(name.clone()).or_default();
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if bytes.len() < start + data.len() {
            bytes.resize(start + data.len(), 0);
        }
        bytes[start..start + data.len()].copy_from_slice(&data);
        let count = u32::try_from(data.len()).unwrap_or(u32::MAX);
        self.answer(
            request,
            wire::STATUS_SUCCESS,
            message::write_response(count),
        )?;
        Ok(Some(Event::Written(name, data.len())))
    }

    fn on_read(&mut self, request: &Message) -> Result<Option<Event>> {
        let (id, offset, length) = message::read_fields(&request.body)?;
        let Some(open) = self.handles.get(&id.0) else {
            self.answer(request, wire::STATUS_OBJECT_NAME_NOT_FOUND, Vec::new())?;
            return Ok(None);
        };
        let name = open.name.clone();
        let bytes = self.files.get(&name).cloned().unwrap_or_default();
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        if start == bytes.len() {
            self.answer(
                request,
                wire::STATUS_END_OF_FILE,
                message::read_response(&[]),
            )?;
            return Ok(Some(Event::Read(name)));
        }
        let end = start.saturating_add(length as usize).min(bytes.len());
        self.answer(
            request,
            wire::STATUS_SUCCESS,
            message::read_response(&bytes[start..end]),
        )?;
        Ok(Some(Event::Read(name)))
    }

    fn on_close(&mut self, request: &Message) -> Result<Option<Event>> {
        let id = message::close_id(&request.body)?;
        let open = self.handles.remove(&id.0);
        self.answer(request, wire::STATUS_SUCCESS, message::close_response())?;
        let Some(open) = open else {
            return Ok(None);
        };
        if open.delete_on_close {
            self.files.remove(&open.name);
            return Ok(Some(Event::Removed(open.name)));
        }
        if open.written {
            let bytes = self.files.get(&open.name).cloned().unwrap_or_default();
            let origin = format!("smb://{}/{}/{}", self.peer, self.tree, open.name);
            return Ok(Some(Event::Committed(Arrived::new(origin, bytes))));
        }
        Ok(None)
    }

    fn on_query(&mut self, request: &Message) -> Result<Option<Event>> {
        directory::id(&request.body)?;
        let names: Vec<String> = self.files.keys().cloned().collect();
        if names.is_empty() {
            self.answer(request, wire::STATUS_NO_MORE_FILES, Vec::new())?;
        } else {
            let body = directory::response(&names);
            self.answer(request, wire::STATUS_SUCCESS, body)?;
        }
        Ok(Some(Event::Listed))
    }

    fn answer(&mut self, request: &Message, status: u32, body: Vec<u8>) -> Result<()> {
        let mut answer = request.respond(status, body);
        answer.session_id = self.id;
        answer.tree_id = request.tree_id;
        answer.write(&mut self.writer)
    }

    fn expect(&mut self, command: u16) -> Result<Message> {
        let request = Message::expect(&mut self.reader)?;
        if request.command == command {
            Ok(request)
        } else {
            Err(protocol_error(format!(
                "command {:#06x} where {command:#06x} was due",
                request.command
            )))
        }
    }
}

/// Eight bytes no two sessions share: the clock, the peer and a counter.
fn fresh_nonce(peer: &SocketAddr) -> [u8; 8] {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
        });
    let seed = nanos ^ SESSIONS.load(Ordering::Relaxed).rotate_left(17) ^ u64::from(peer.port());
    seed.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_is_eight_bytes_and_fresh() {
        let peer: SocketAddr = "127.0.0.1:445".parse().expect("address");
        let first = fresh_nonce(&peer);
        assert_eq!(first.len(), 8);
        SESSIONS.fetch_add(1, Ordering::Relaxed);
        assert_ne!(first, fresh_nonce(&peer));
    }
}
