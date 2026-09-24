//! The SMB2 packet header (MS-SMB2 section 2.2.1) and the way it crosses
//! TCP: a four-byte length a direct-TCP session prefixes each message
//! with, then the sixty-four-byte synchronous header — the `\xFESMB`
//! signature, the command, the message id, the tree and session ids, and
//! the status a response carries. Signing is not done here: with the
//! signature field left zero a server that does not require signing takes
//! the message, and the HMAC-SHA256 a server that does is the identity
//! capability's (ADR-0044). Nothing here knows a command's body.

use std::io::{Read, Write};

use transport::error::{Result, classify, protocol_error};

/// The four bytes that open every SMB2 message.
pub const SIGNATURE: [u8; 4] = [0xFE, b'S', b'M', b'B'];
/// The fixed size of the synchronous header.
pub const HEADER: usize = 64;
/// `SMB2_FLAGS_SERVER_TO_REDIR`: this message is a response.
pub const FLAGS_RESPONSE: u32 = 0x0000_0001;
/// The largest message either side reads, over the four-byte length's
/// seventeen-bit ceiling but well within it.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// `SMB2 NEGOTIATE`.
pub const NEGOTIATE: u16 = 0x0000;
/// `SMB2 SESSION_SETUP`.
pub const SESSION_SETUP: u16 = 0x0001;
/// `SMB2 LOGOFF`.
pub const LOGOFF: u16 = 0x0002;
/// `SMB2 TREE_CONNECT`.
pub const TREE_CONNECT: u16 = 0x0003;
/// `SMB2 TREE_DISCONNECT`.
pub const TREE_DISCONNECT: u16 = 0x0004;
/// `SMB2 CREATE`.
pub const CREATE: u16 = 0x0005;
/// `SMB2 CLOSE`.
pub const CLOSE: u16 = 0x0006;
/// `SMB2 READ`.
pub const READ: u16 = 0x0008;
/// `SMB2 WRITE`.
pub const WRITE: u16 = 0x0009;
/// `SMB2 QUERY_DIRECTORY`.
pub const QUERY_DIRECTORY: u16 = 0x000E;

/// `STATUS_SUCCESS`.
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_MORE_PROCESSING_REQUIRED`, the challenge step of a session
/// setup.
pub const STATUS_MORE_PROCESSING: u32 = 0xC000_0016;
/// `STATUS_NO_MORE_FILES`, the end of a directory listing.
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
/// `STATUS_LOGON_FAILURE`.
pub const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
/// `STATUS_OBJECT_NAME_NOT_FOUND`.
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
/// `STATUS_BAD_NETWORK_NAME`, no such share.
pub const STATUS_BAD_NETWORK_NAME: u32 = 0xC000_00CC;
/// `STATUS_END_OF_FILE`.
pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;

/// One SMB2 message: the header fields a session cares about, and the
/// body past the header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub command: u16,
    pub status: u32,
    pub flags: u32,
    pub message_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
    pub body: Vec<u8>,
}

impl Message {
    /// A request of `command`.
    #[must_use]
    pub fn request(command: u16, message_id: u64, body: Vec<u8>) -> Self {
        Self {
            command,
            status: STATUS_SUCCESS,
            flags: 0,
            message_id,
            tree_id: 0,
            session_id: 0,
            body,
        }
    }

    /// The answer to this request: same command and ids, the response
    /// flag, `status`, and `body`.
    #[must_use]
    pub fn respond(&self, status: u32, body: Vec<u8>) -> Self {
        Self {
            command: self.command,
            status,
            flags: FLAGS_RESPONSE,
            message_id: self.message_id,
            tree_id: self.tree_id,
            session_id: self.session_id,
            body,
        }
    }

    /// True where this is a response.
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.flags & FLAGS_RESPONSE != 0
    }

    /// The bytes of this message: the four-byte direct-TCP length, the
    /// header, the body.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut header = vec![0u8; HEADER];
        header[0..4].copy_from_slice(&SIGNATURE);
        put_u16(&mut header, 4, u16::try_from(HEADER).unwrap_or(u16::MAX));
        put_u32(&mut header, 8, self.status);
        put_u16(&mut header, 12, self.command);
        put_u16(&mut header, 14, 1);
        put_u32(&mut header, 16, self.flags);
        put_u64(&mut header, 24, self.message_id);
        put_u32(&mut header, 36, self.tree_id);
        put_u64(&mut header, 40, self.session_id);
        let length = header.len() + self.body.len();
        let mut out = Vec::with_capacity(length + 4);
        out.extend_from_slice(&u32::try_from(length).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.body);
        out
    }

    /// Write this message and flush.
    ///
    /// # Errors
    /// Where the connection broke.
    pub fn write(&self, writer: &mut impl Write) -> Result<()> {
        writer
            .write_all(&self.to_bytes())
            .and_then(|()| writer.flush())
            .map_err(|e| classify("writing a message", &e))
    }

    /// Read one message; `None` where the connection closed cleanly before
    /// one began.
    ///
    /// # Errors
    /// Where the connection broke, the message is not SMB2, or it is over
    /// [`MAX_MESSAGE`].
    pub fn read(reader: &mut impl Read) -> Result<Option<Self>> {
        let mut length = [0u8; 4];
        match reader.read_exact(&mut length) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(classify("reading a message length", &e)),
        }
        let length = (u32::from_be_bytes(length) & 0x00FF_FFFF) as usize;
        if !(HEADER..=MAX_MESSAGE).contains(&length) {
            return Err(protocol_error(format!("an SMB2 message of {length} bytes")));
        }
        let mut raw = vec![0u8; length];
        reader
            .read_exact(&mut raw)
            .map_err(|e| classify("reading a message", &e))?;
        if raw[0..4] != SIGNATURE {
            return Err(protocol_error("a message without the SMB2 signature"));
        }
        Ok(Some(Self {
            command: u16::from_le_bytes([raw[12], raw[13]]),
            status: get_u32(&raw, 8),
            flags: get_u32(&raw, 16),
            message_id: get_u64(&raw, 24),
            tree_id: get_u32(&raw, 36),
            session_id: get_u64(&raw, 40),
            body: raw[HEADER..].to_vec(),
        }))
    }

    /// Read one message, which must be there.
    ///
    /// # Errors
    /// As [`Message::read`], and where the connection closed.
    pub fn expect(reader: &mut impl Read) -> Result<Self> {
        Self::read(reader)?.ok_or_else(|| protocol_error("the peer closed the connection"))
    }
}

/// Append a little-endian u16.
pub fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append a little-endian u32.
pub fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append a little-endian u64.
pub fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Write a little-endian u16 at `at`.
pub fn put_u16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

/// Write a little-endian u32 at `at`.
pub fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// Write a little-endian u64 at `at`.
pub fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// A little-endian u16 at `at`, zero past the end.
#[must_use]
pub fn get_u16(bytes: &[u8], at: usize) -> u16 {
    bytes
        .get(at..at + 2)
        .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
}

/// A little-endian u32 at `at`, zero past the end.
#[must_use]
pub fn get_u32(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// A little-endian u64 at `at`, zero past the end.
#[must_use]
pub fn get_u64(bytes: &[u8], at: usize) -> u64 {
    bytes.get(at..at + 8).map_or(0, |b| {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

/// A security buffer or a name a request carries out of line: the bytes
/// at `offset` from the header for `length`, none where either is zero.
///
/// # Errors
/// Where the region runs past the message.
pub fn region(body: &[u8], offset: u16, length: u16) -> Result<&[u8]> {
    if offset == 0 || length == 0 {
        return Ok(&[]);
    }
    let start = (offset as usize).checked_sub(HEADER);
    let start = start.ok_or_else(|| protocol_error("an offset inside the header"))?;
    body.get(start..start + length as usize)
        .ok_or_else(|| protocol_error("a region past the end of the message"))
}

/// Like [`region`], but for a length that a `u32` field carries — a read
/// or write buffer larger than sixty-five kibibytes.
///
/// # Errors
/// Where the region runs past the message.
pub fn wide_region(body: &[u8], offset: u16, length: u32) -> Result<&[u8]> {
    if offset == 0 || length == 0 {
        return Ok(&[]);
    }
    let start = (offset as usize)
        .checked_sub(HEADER)
        .ok_or_else(|| protocol_error("an offset inside the header"))?;
    body.get(start..start + length as usize)
        .ok_or_else(|| protocol_error("a region past the end of the message"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_and_its_response_read_back_over_a_wire() {
        let request = Message::request(CREATE, 7, b"body".to_vec());
        let mut with_ids = request.clone();
        with_ids.tree_id = 3;
        with_ids.session_id = 9;
        let mut wire = Vec::new();
        with_ids.write(&mut wire).expect("write");
        let response = with_ids.respond(STATUS_SUCCESS, b"answer".to_vec());
        response.write(&mut wire).expect("write");
        let mut cursor = &wire[..];
        let read = Message::expect(&mut cursor).expect("request");
        assert_eq!(read, with_ids);
        assert!(!read.is_response());
        let read = Message::expect(&mut cursor).expect("response");
        assert!(read.is_response());
        assert_eq!(read.tree_id, 3);
        assert_eq!(read.session_id, 9);
        assert_eq!(Message::read(&mut cursor).expect("closed"), None);
    }

    #[test]
    fn regions_and_a_bad_signature_are_handled() {
        let body = b"..data..".to_vec();
        assert_eq!(
            region(&body, u16::try_from(HEADER).unwrap_or(0) + 2, 4).expect("region"),
            b"data"
        );
        assert_eq!(region(&body, 0, 0).expect("none"), b"");
        assert!(region(&body, 4, 4).is_err(), "inside the header");
        assert!(
            region(&body, u16::try_from(HEADER).unwrap_or(0), 99).is_err(),
            "past the end"
        );
        let mut bad = Message::request(READ, 1, Vec::new()).to_bytes();
        bad[4] = 0;
        assert!(Message::read(&mut &bad[..]).is_err(), "no signature");
    }
}
