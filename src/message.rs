//! The SMB2 command bodies this transport speaks (MS-SMB2 section 2.2):
//! the request a client sends and the response a server answers, for the
//! eight commands that carry one file — negotiate, session setup, tree
//! connect, create, write, read, close and query directory. The fixed
//! parts and their structure sizes, offsets and dispositions are the
//! specification's; a directory entry is carried in a simplified shape,
//! since this crate's own server is the only reader of it.

use transport::error::{Result, protocol_error};

use crate::wire::{
    HEADER, get_u16, get_u32, get_u64, push_u16, push_u32, push_u64, region, wide_region,
};

/// `FILE_OPEN`: open an existing file.
pub const FILE_OPEN: u32 = 1;
/// `FILE_OVERWRITE_IF`: create it, or replace it if it is there.
pub const FILE_OVERWRITE_IF: u32 = 5;
/// `FILE_DIRECTORY_FILE`, a create option: open a directory.
pub const FILE_DIRECTORY: u32 = 0x0000_0001;
/// `FILE_DELETE_ON_CLOSE`, a create option: remove the file when it is
/// closed.
pub const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

/// A sixteen-byte SMB2 file id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId(pub [u8; 16]);

impl FileId {
    /// The persistent and volatile halves both set to `seed`, so a server
    /// hands out an id no open file shares.
    #[must_use]
    pub fn of(seed: u64) -> Self {
        let mut id = [0u8; 16];
        id[0..8].copy_from_slice(&seed.to_le_bytes());
        id[8..16].copy_from_slice(&seed.rotate_left(32).to_le_bytes());
        Self(id)
    }

    pub(crate) fn read(bytes: &[u8], at: usize) -> Result<Self> {
        bytes
            .get(at..at + 16)
            .and_then(|slice| slice.try_into().ok())
            .map(Self)
            .ok_or_else(|| protocol_error("a file id cut short"))
    }
}

/// A `NEGOTIATE` request offering the 2.0.2 dialect.
#[must_use]
pub fn negotiate_request() -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, 36);
    push_u16(&mut out, 1);
    push_u16(&mut out, 1);
    push_u16(&mut out, 0);
    push_u32(&mut out, 0);
    out.extend_from_slice(&[0u8; 16]);
    push_u16(&mut out, 0x0202);
    out
}

/// A `NEGOTIATE` response naming the 2.0.2 dialect.
#[must_use]
pub fn negotiate_response() -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, 65);
    push_u16(&mut out, 1);
    push_u16(&mut out, 0x0202);
    out.extend_from_slice(&[0u8; 32]);
    out
}

/// A `SESSION_SETUP` request or response carrying `token` as its security
/// buffer; the request's fixed part is twenty-four bytes, the response's
/// eight.
#[must_use]
pub fn session_setup(is_response: bool, token: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if is_response {
        push_u16(&mut out, 9);
        push_u16(&mut out, 0);
        push_u16(&mut out, u16::try_from(HEADER + 8).unwrap_or(u16::MAX));
        push_u16(&mut out, u16::try_from(token.len()).unwrap_or(u16::MAX));
    } else {
        push_u16(&mut out, 25);
        out.push(0);
        out.push(0);
        push_u32(&mut out, 0);
        push_u32(&mut out, 0);
        push_u16(&mut out, u16::try_from(HEADER + 24).unwrap_or(u16::MAX));
        push_u16(&mut out, u16::try_from(token.len()).unwrap_or(u16::MAX));
        push_u64(&mut out, 0);
    }
    out.extend_from_slice(token);
    out
}

/// The security buffer a session setup carries.
///
/// # Errors
/// Where the buffer runs past the message.
pub fn session_token(body: &[u8]) -> Result<&[u8]> {
    let offset_at = if get_u16(body, 0) == 9 { 4 } else { 12 };
    region(body, get_u16(body, offset_at), get_u16(body, offset_at + 2))
}

/// A `TREE_CONNECT` request for `path` — `\\server\share`.
#[must_use]
pub fn tree_connect_request(path: &str) -> Vec<u8> {
    let name = codec::utf16::encode(path);
    let mut out = Vec::new();
    push_u16(&mut out, 9);
    push_u16(&mut out, 0);
    push_u16(&mut out, u16::try_from(HEADER + 8).unwrap_or(u16::MAX));
    push_u16(&mut out, u16::try_from(name.len()).unwrap_or(u16::MAX));
    out.extend_from_slice(&name);
    out
}

/// The path a tree connect names.
///
/// # Errors
/// Where the path runs past the message.
pub fn tree_connect_path(body: &[u8]) -> Result<String> {
    Ok(codec::utf16::decode_lossy(region(
        body,
        get_u16(body, 4),
        get_u16(body, 6),
    )?))
}

/// A `TREE_CONNECT` response for a disk share.
#[must_use]
pub fn tree_connect_response() -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, 16);
    out.push(1);
    out.push(0);
    push_u32(&mut out, 0);
    push_u32(&mut out, 0x001F_01FF);
    out
}

/// A `CREATE` request for `name` with `disposition` and `options`.
#[must_use]
pub fn create_request(name: &str, disposition: u32, options: u32) -> Vec<u8> {
    let encoded = codec::utf16::encode(name);
    let mut out = Vec::new();
    push_u16(&mut out, 57);
    out.push(0);
    out.push(0);
    push_u32(&mut out, 2);
    push_u64(&mut out, 0);
    push_u64(&mut out, 0);
    push_u32(&mut out, 0x001F_01FF);
    push_u32(&mut out, 0x0000_0080);
    push_u32(&mut out, 7);
    push_u32(&mut out, disposition);
    push_u32(&mut out, options);
    let name_offset = HEADER + 56;
    push_u16(&mut out, u16::try_from(name_offset).unwrap_or(u16::MAX));
    push_u16(&mut out, u16::try_from(encoded.len()).unwrap_or(u16::MAX));
    push_u32(&mut out, 0);
    push_u32(&mut out, 0);
    out.extend_from_slice(&encoded);
    out
}

/// The name, disposition and options a create names.
///
/// # Errors
/// Where the name runs past the message.
pub fn create_fields(body: &[u8]) -> Result<(String, u32, u32)> {
    let disposition = get_u32(body, 36);
    let options = get_u32(body, 40);
    let name = codec::utf16::decode_lossy(region(body, get_u16(body, 44), get_u16(body, 46))?);
    Ok((name, disposition, options))
}

/// A `CREATE` response handing out `id` for a file `end_of_file` bytes
/// long.
#[must_use]
pub fn create_response(id: FileId, end_of_file: u64) -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, 89);
    out.push(0);
    out.push(0);
    push_u32(&mut out, 1);
    for _ in 0..4 {
        push_u64(&mut out, 0);
    }
    push_u64(&mut out, end_of_file);
    push_u64(&mut out, end_of_file);
    push_u32(&mut out, 0x0000_0080);
    push_u32(&mut out, 0);
    out.extend_from_slice(&id.0);
    out
}

/// The file id a create response handed out, and the file's length.
///
/// # Errors
/// Where the response is cut short.
pub fn created(body: &[u8]) -> Result<(FileId, u64)> {
    Ok((FileId::read(body, 64)?, get_u64(body, 48)))
}

/// A `WRITE` request putting `data` at `offset` of `id`.
#[must_use]
pub fn write_request(id: FileId, offset: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, 49);
    push_u16(&mut out, u16::try_from(HEADER + 48).unwrap_or(u16::MAX));
    push_u32(&mut out, u32::try_from(data.len()).unwrap_or(u32::MAX));
    push_u64(&mut out, offset);
    out.extend_from_slice(&id.0);
    push_u32(&mut out, 0);
    push_u32(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u32(&mut out, 0);
    out.extend_from_slice(data);
    out
}

/// The file id, offset and data a write carries.
///
/// # Errors
/// Where the data runs past the message.
pub fn write_fields(body: &[u8]) -> Result<(FileId, u64, Vec<u8>)> {
    let id = FileId::read(body, 16)?;
    let offset = get_u64(body, 8);
    let data = wide_region(body, get_u16(body, 2), get_u32(body, 4))?;
    Ok((id, offset, data.to_vec()))
}

/// A `WRITE` response reporting `count` bytes written.
#[must_use]
pub fn write_response(count: u32) -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, 17);
    push_u16(&mut out, 0);
    push_u32(&mut out, count);
    push_u32(&mut out, 0);
    push_u32(&mut out, 0);
    out
}

/// The count a write response reports.
#[must_use]
pub fn written(body: &[u8]) -> u32 {
    get_u32(body, 4)
}

/// A `READ` request for `length` bytes at `offset` of `id`.
#[must_use]
pub fn read_request(id: FileId, offset: u64, length: u32) -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, 49);
    out.push(0);
    out.push(0);
    push_u32(&mut out, length);
    push_u64(&mut out, offset);
    out.extend_from_slice(&id.0);
    push_u32(&mut out, 0);
    push_u32(&mut out, 0);
    push_u32(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    out
}

/// The file id, offset and length a read asks for.
///
/// # Errors
/// Where the request is cut short.
pub fn read_fields(body: &[u8]) -> Result<(FileId, u64, u32)> {
    let length = get_u32(body, 4);
    let offset = get_u64(body, 8);
    let id = FileId::read(body, 16)?;
    Ok((id, offset, length))
}

/// A `READ` response carrying `data`.
#[must_use]
pub fn read_response(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, 17);
    out.push(u8::try_from(HEADER + 16).unwrap_or(u8::MAX));
    out.push(0);
    push_u32(&mut out, u32::try_from(data.len()).unwrap_or(u32::MAX));
    push_u32(&mut out, 0);
    push_u32(&mut out, 0);
    out.extend_from_slice(data);
    out
}

/// The data a read response carries.
///
/// # Errors
/// Where the data runs past the message.
pub fn read_data(body: &[u8]) -> Result<Vec<u8>> {
    let offset = u16::from(*body.get(2).unwrap_or(&0));
    Ok(wide_region(body, offset, get_u32(body, 4))?.to_vec())
}

/// A `CLOSE` request for `id`.
#[must_use]
pub fn close_request(id: FileId) -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, 24);
    push_u16(&mut out, 0);
    push_u32(&mut out, 0);
    out.extend_from_slice(&id.0);
    out
}

/// The file id a close names.
///
/// # Errors
/// Where the request is cut short.
pub fn close_id(body: &[u8]) -> Result<FileId> {
    FileId::read(body, 8)
}

/// A `CLOSE` response.
#[must_use]
pub fn close_response() -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, 60);
    out.extend_from_slice(&[0u8; 58]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_setup_and_a_tree_connect_carry_their_out_of_line_fields() {
        let token = b"NTLMSSP\0token".to_vec();
        assert_eq!(
            session_token(&session_setup(false, &token)).expect("req"),
            token
        );
        assert_eq!(
            session_token(&session_setup(true, &token)).expect("resp"),
            token
        );
        let path = r"\\server\share";
        assert_eq!(
            tree_connect_path(&tree_connect_request(path)).expect("path"),
            path
        );
    }

    #[test]
    fn a_create_write_read_and_close_round_trip_their_ids_and_bytes() {
        let (name, disp, options) = create_fields(&create_request(
            "orders.edi",
            FILE_OPEN,
            FILE_DELETE_ON_CLOSE,
        ))
        .expect("create");
        assert_eq!(
            (name.as_str(), disp, options),
            ("orders.edi", FILE_OPEN, FILE_DELETE_ON_CLOSE)
        );
        let id = FileId::of(42);
        let (created_id, len) = created(&create_response(id, 7)).expect("created");
        assert_eq!((created_id, len), (id, 7));
        let (wid, off, data) = write_fields(&write_request(id, 8, b"\0\xff")).expect("write");
        assert_eq!((wid, off, data), (id, 8, b"\0\xff".to_vec()));
        assert_eq!(written(&write_response(2)), 2);
        let (rid, roff, rlen) = read_fields(&read_request(id, 0, 16)).expect("read");
        assert_eq!((rid, roff, rlen), (id, 0, 16));
        assert_eq!(read_data(&read_response(b"data")).expect("data"), b"data");
        assert_eq!(close_id(&close_request(id)).expect("close"), id);
    }
}
