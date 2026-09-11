//! The `QUERY_DIRECTORY` command (MS-SMB2 section 2.2.33) and the status
//! codes a caller reads. A directory entry is carried in a simplified
//! shape — a next-entry offset and a counted UTF-16 name — since this
//! crate's own server is the only reader of the listing; the many fields
//! of a real `FileIdBothDirectoryInformation` a whole-file drop box does
//! not need.

use transport::error::{Result, protocol_error};

use crate::message::FileId;
use crate::wire::{
    self, HEADER, from_utf16, get_u16, get_u32, push_u16, push_u32, utf16, wide_region,
};

/// A `QUERY_DIRECTORY` request over `id`, matching `pattern`.
#[must_use]
pub fn request(id: FileId, pattern: &str) -> Vec<u8> {
    let name = utf16(pattern);
    let mut out = Vec::new();
    push_u16(&mut out, 33);
    out.push(37);
    out.push(0);
    push_u32(&mut out, 0);
    out.extend_from_slice(&id.0);
    push_u16(&mut out, u16::try_from(HEADER + 32).unwrap_or(u16::MAX));
    push_u16(&mut out, u16::try_from(name.len()).unwrap_or(u16::MAX));
    push_u32(&mut out, 0x0001_0000);
    out.extend_from_slice(&name);
    out
}

/// The file id a query directory names.
///
/// # Errors
/// Where the request is cut short.
pub fn id(body: &[u8]) -> Result<FileId> {
    FileId::read(body, 8)
}

/// A `QUERY_DIRECTORY` response listing `names`, each entry a next-entry
/// offset and a counted UTF-16 name.
#[must_use]
pub fn response(names: &[String]) -> Vec<u8> {
    let mut buffer = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let encoded = utf16(name);
        let entry_len = 8 + encoded.len();
        let next = if index + 1 == names.len() {
            0
        } else {
            entry_len
        };
        push_u32(&mut buffer, u32::try_from(next).unwrap_or(0));
        push_u32(
            &mut buffer,
            u32::try_from(encoded.len()).unwrap_or(u16::MAX.into()),
        );
        buffer.extend_from_slice(&encoded);
    }
    let mut out = Vec::new();
    push_u16(&mut out, 9);
    push_u16(&mut out, u16::try_from(HEADER + 8).unwrap_or(u16::MAX));
    push_u32(&mut out, u32::try_from(buffer.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(&buffer);
    out
}

/// The names a query directory response lists.
///
/// # Errors
/// Where an entry runs past the buffer.
pub fn names(body: &[u8]) -> Result<Vec<String>> {
    let buffer = wide_region(body, get_u16(body, 2), get_u32(body, 4))?;
    let mut listed = Vec::new();
    let mut at = 0;
    while at + 8 <= buffer.len() {
        let next = get_u32(buffer, at) as usize;
        let name_len = get_u32(buffer, at + 4) as usize;
        let start = at + 8;
        let end = start
            .checked_add(name_len)
            .filter(|end| *end <= buffer.len())
            .ok_or_else(|| protocol_error("a directory entry past the buffer"))?;
        listed.push(from_utf16(&buffer[start..end]));
        if next == 0 {
            break;
        }
        at += next;
    }
    Ok(listed)
}

/// The status code of a status, named for a message.
#[must_use]
pub fn status_name(status: u32) -> &'static str {
    match status {
        wire::STATUS_SUCCESS => "success",
        wire::STATUS_LOGON_FAILURE => "the logon failed",
        wire::STATUS_BAD_NETWORK_NAME => "no such share",
        wire::STATUS_OBJECT_NAME_NOT_FOUND => "no such file",
        wire::STATUS_END_OF_FILE => "the end of the file",
        wire::STATUS_NO_MORE_FILES => "no more files",
        _ => "an error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_listing_carries_its_names_and_a_status_names_itself() {
        let handle = FileId::of(1);
        assert_eq!(id(&request(handle, "*")).expect("id"), handle);
        let listing = vec!["a.edi".to_string(), "b.bin".to_string()];
        let response = response(&listing);
        assert_eq!(names(&response).expect("names"), listing);
        assert!(names(&super::response(&[])).expect("empty").is_empty());
        assert_eq!(status_name(wire::STATUS_BAD_NETWORK_NAME), "no such share");
    }
}
