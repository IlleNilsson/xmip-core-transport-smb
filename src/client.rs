//! Xmip's side of one connection to an SMB2 server: negotiate the 2.0.2
//! dialect, set up a session with the `NTLMSSP` tokens, connect the tree,
//! then create, write, read, close and list one file on the share. The
//! `NTLMv2` response is the identity capability's (see `ntlm.rs`); a server
//! that does not require signing takes the guest logon.

use std::io::BufReader;
use std::net::TcpStream;
use std::time::Duration;

use transport::error::{Result, TransportError, protocol_error};
use transport::socket;
use transport::wire::MAX_BODY;

use crate::directory;
use crate::message::{self, FileId};
use crate::ntlm::{self, Identity};
use crate::wire::{self, Message};

/// The largest read or write in one message, well within the negotiated
/// message ceiling.
pub const CHUNK: usize = 1024 * 1024;

pub struct Client {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    session_id: u64,
    tree_id: u32,
    next_message_id: u64,
}

impl Client {
    /// Connect to `server`, set up a session as `identity`, and connect
    /// the tree at `share` — `\\server\share`.
    ///
    /// # Errors
    /// Where the server could not be reached, refused the logon, or has no
    /// such share.
    pub fn connect(
        server: &str,
        share: &str,
        identity: &Identity,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let stream = socket::connect_tcp(server, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut client = Self {
            reader,
            writer,
            session_id: 0,
            tree_id: 0,
            next_message_id: 0,
        };
        client.negotiate()?;
        client.session_setup(identity)?;
        client.tree_connect(share)?;
        Ok(client)
    }

    fn negotiate(&mut self) -> Result<()> {
        let answer = self.call(wire::NEGOTIATE, message::negotiate_request())?;
        let _ = answer;
        Ok(())
    }

    fn session_setup(&mut self, identity: &Identity) -> Result<()> {
        let setup = message::session_setup(false, &ntlm::negotiate());
        let request = Message::request(wire::SESSION_SETUP, self.take_id(), setup);
        let challenge = self.exchange(&request)?;
        if challenge.status != wire::STATUS_MORE_PROCESSING {
            return Err(status_error("the session setup", challenge.status));
        }
        self.session_id = challenge.session_id;
        let nonce = ntlm::read_challenge(message::session_token(&challenge.body)?)?;
        let _ = nonce;
        let auth = message::session_setup(false, &ntlm::authenticate(identity));
        let answer = self.call(wire::SESSION_SETUP, auth)?;
        if answer.status != wire::STATUS_SUCCESS {
            return Err(status_error("the logon", answer.status));
        }
        Ok(())
    }

    fn tree_connect(&mut self, share: &str) -> Result<()> {
        let answer = self.call(wire::TREE_CONNECT, message::tree_connect_request(share))?;
        self.tree_id = answer.tree_id;
        Ok(())
    }

    /// Open `name` as an existing file, and its length.
    ///
    /// # Errors
    /// Where there is no such file, or the server refused.
    pub fn open(&mut self, name: &str) -> Result<(FileId, u64)> {
        let request = message::create_request(name, message::FILE_OPEN, 0);
        message::created(&self.call(wire::CREATE, request)?.body)
    }

    /// Open `name` as an existing file to be removed when it is closed.
    ///
    /// # Errors
    /// Where there is no such file, or the server refused.
    pub fn open_to_delete(&mut self, name: &str) -> Result<FileId> {
        let request =
            message::create_request(name, message::FILE_OPEN, message::FILE_DELETE_ON_CLOSE);
        Ok(message::created(&self.call(wire::CREATE, request)?.body)?.0)
    }

    /// Create `name`, replacing it if it is there, and its handle.
    ///
    /// # Errors
    /// Where the server refused.
    pub fn create(&mut self, name: &str) -> Result<FileId> {
        let request = message::create_request(name, message::FILE_OVERWRITE_IF, 0);
        Ok(message::created(&self.call(wire::CREATE, request)?.body)?.0)
    }

    /// Open the share's root directory.
    ///
    /// # Errors
    /// Where the server refused.
    pub fn open_root(&mut self) -> Result<FileId> {
        let request = message::create_request("", message::FILE_OPEN, message::FILE_DIRECTORY);
        Ok(message::created(&self.call(wire::CREATE, request)?.body)?.0)
    }

    /// Write `bytes` to `id` from the start, a chunk per message.
    ///
    /// # Errors
    /// Where the server refused or wrote short.
    pub fn write_all(&mut self, id: FileId, bytes: &[u8]) -> Result<()> {
        let mut offset = 0u64;
        for chunk in split_chunks(bytes) {
            let request = message::write_request(id, offset, chunk);
            let written = message::written(&self.call(wire::WRITE, request)?.body) as usize;
            if written != chunk.len() {
                return Err(protocol_error(format!(
                    "the server wrote {written} of {} bytes",
                    chunk.len()
                )));
            }
            offset += written as u64;
        }
        Ok(())
    }

    /// Read `length` bytes of `id` from the start, a chunk per message.
    ///
    /// # Errors
    /// Where the server refused.
    pub fn read_all(&mut self, id: FileId, length: u64) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        while (bytes.len() as u64) < length {
            let want = (length - bytes.len() as u64).min(CHUNK as u64);
            let want = u32::try_from(want).unwrap_or(u32::MAX);
            let request = message::read_request(id, bytes.len() as u64, want);
            let answer = self.call(wire::READ, request)?;
            if answer.status == wire::STATUS_END_OF_FILE {
                break;
            }
            let data = message::read_data(&answer.body)?;
            if data.is_empty() {
                break;
            }
            bytes.extend_from_slice(&data);
        }
        Ok(bytes)
    }

    /// The names on the share, `.` and `..` left out.
    ///
    /// # Errors
    /// Where the server refused.
    pub fn list(&mut self, pattern: &str) -> Result<Vec<String>> {
        let root = self.open_root()?;
        let request = directory::request(root, pattern);
        let answer =
            self.call_allowing(wire::QUERY_DIRECTORY, request, wire::STATUS_NO_MORE_FILES)?;
        self.close(root)?;
        if answer.status == wire::STATUS_NO_MORE_FILES {
            return Ok(Vec::new());
        }
        Ok(directory::names(&answer.body)?
            .into_iter()
            .filter(|name| name != "." && name != "..")
            .collect())
    }

    /// Close `id`.
    ///
    /// # Errors
    /// Where the server refused.
    pub fn close(&mut self, id: FileId) -> Result<()> {
        self.call(wire::CLOSE, message::close_request(id))?;
        Ok(())
    }

    /// Log off and hang up.
    ///
    /// # Errors
    /// Where the server had already gone.
    pub fn logoff(mut self) -> Result<()> {
        let mut request = Message::request(wire::LOGOFF, self.take_id(), vec![4, 0, 0, 0]);
        request.session_id = self.session_id;
        request.write(&mut self.writer)
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_message_id;
        self.next_message_id += 1;
        id
    }

    fn call(&mut self, command: u16, body: Vec<u8>) -> Result<Message> {
        self.call_allowing(command, body, wire::STATUS_SUCCESS)
    }

    /// One message and its answer; a status other than success or `allow`
    /// is the error it names.
    fn call_allowing(&mut self, command: u16, body: Vec<u8>, allow: u32) -> Result<Message> {
        let mut request = Message::request(command, self.take_id(), body);
        request.session_id = self.session_id;
        request.tree_id = self.tree_id;
        let answer = self.exchange(&request)?;
        if answer.status != wire::STATUS_SUCCESS && answer.status != allow {
            return Err(status_error("the server answered", answer.status));
        }
        Ok(answer)
    }

    fn exchange(&mut self, request: &Message) -> Result<Message> {
        let id = request.message_id;
        request.write(&mut self.writer)?;
        let answer = Message::expect(&mut self.reader)?;
        if answer.message_id != id {
            return Err(protocol_error("an answer to another message"));
        }
        Ok(answer)
    }
}

/// The chunks a write is split into, one empty chunk where the whole is
/// empty so a zero-length file is still written.
fn split_chunks(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() {
        return vec![&[]];
    }
    bytes.chunks(CHUNK).collect()
}

/// The failure a status names; retryable where it is the server briefly
/// busy or a share not yet up.
#[must_use]
pub fn status_error(what: &str, status: u32) -> TransportError {
    let text = format!(
        "{what}: {} ({status:#010x})",
        directory::status_name(status)
    );
    if matches!(status, 0xC000_0203 | 0x8000_0011 | 0xC000_0235) {
        TransportError::retryable(text)
    } else {
        TransportError::permanent(text)
    }
}

/// The largest whole Stream read off one file: what a receive will not
/// exceed.
pub const MAX_FILE: usize = MAX_BODY;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_names_its_failure_and_a_transient_is_retryable() {
        let error = status_error("opening", wire::STATUS_OBJECT_NAME_NOT_FOUND);
        assert!(error.message.contains("no such file"), "{error}");
        assert!(!error.retryable);
        assert!(status_error("x", 0xC000_0203).retryable, "a network error");
        assert_eq!(split_chunks(b"").len(), 1, "empty is one write");
        assert_eq!(split_chunks(&vec![0u8; CHUNK + 1]).len(), 2);
    }
}
