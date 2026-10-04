//! The `QUERY_DIRECTORY` command (MS-SMB2 section 2.2.33) and the status
//! codes a caller reads. A listing asks for `FileDirectoryInformation`
//! (MS-FSCC section 2.4.10): each entry carries its name with its
//! `EndOfFile` and `LastWriteTime`, the stamp that says a file is unchanged.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use transport::error::{Result, protocol_error};

use crate::message::FileId;
use crate::wire::{
    self, HEADER, get_u16, get_u32, get_u64, push_u16, push_u32, push_u64, wide_region,
};

/// `FileDirectoryInformation`, the information class a listing asks for.
const FILE_DIRECTORY_INFORMATION: u8 = 1;
/// Where an entry's name starts, past its fixed fields.
const ENTRY: usize = 64;
/// Where an entry's `LastWriteTime`, `EndOfFile` and name length lie.
const LAST_WRITE: usize = 24;
const END_OF_FILE: usize = 40;
const NAME_LENGTH: usize = 60;
/// The 100-nanosecond intervals from 1601 to the Unix epoch.
const FILETIME_AT_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// What says a listed file is unchanged: its length and when it was last
/// written, a `FILETIME`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub length: u64,
    pub written: u64,
}

/// A listed file's name and stamp.
pub type Listed = (String, Stamp);

/// When each file on a far end's share was last written, as a `FILETIME`,
/// each write after the one before it, so a file written again lists as
/// changed however soon.
#[derive(Default)]
pub struct Written {
    at: BTreeMap<String, u64>,
    newest: u64,
}

impl Written {
    /// Note `name` written now.
    pub fn touch(&mut self, name: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_nanos() / 100).unwrap_or(u64::MAX)
            });
        self.newest = now
            .saturating_add(FILETIME_AT_UNIX_EPOCH)
            .max(self.newest.saturating_add(1));
        self.at.insert(name.to_string(), self.newest);
    }

    /// Forget `name`, removed.
    pub fn forget(&mut self, name: &str) {
        self.at.remove(name);
    }

    /// When `name` was last written; never, for a file the share was given.
    #[must_use]
    pub fn at(&self, name: &str) -> u64 {
        self.at.get(name).copied().unwrap_or(0)
    }
}

/// A `QUERY_DIRECTORY` request over `id`, matching `pattern`.
#[must_use]
pub fn request(id: FileId, pattern: &str) -> Vec<u8> {
    let name = codec::utf16::encode(pattern);
    let mut out = Vec::new();
    push_u16(&mut out, 33);
    out.push(FILE_DIRECTORY_INFORMATION);
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

/// A `QUERY_DIRECTORY` response listing `files`, each a
/// `FileDirectoryInformation` entry aligned to eight bytes.
#[must_use]
pub fn response(files: &[Listed]) -> Vec<u8> {
    let mut buffer = Vec::new();
    for (index, (name, stamp)) in files.iter().enumerate() {
        let start = buffer.len();
        let encoded = codec::utf16::encode(name);
        let aligned = (ENTRY + encoded.len()).next_multiple_of(8);
        let next = if index + 1 == files.len() { 0 } else { aligned };
        push_u32(&mut buffer, u32::try_from(next).unwrap_or(0));
        push_u32(&mut buffer, 0);
        // Created, accessed, written and changed: written is what is kept.
        for time in [stamp.written; 4] {
            push_u64(&mut buffer, time);
        }
        push_u64(&mut buffer, stamp.length);
        push_u64(&mut buffer, stamp.length);
        push_u32(&mut buffer, 0x80);
        push_u32(
            &mut buffer,
            u32::try_from(encoded.len()).unwrap_or(u32::MAX),
        );
        buffer.extend_from_slice(&encoded);
        if next != 0 {
            buffer.resize(start + aligned, 0);
        }
    }
    let mut out = Vec::new();
    push_u16(&mut out, 9);
    push_u16(&mut out, u16::try_from(HEADER + 8).unwrap_or(u16::MAX));
    push_u32(&mut out, u32::try_from(buffer.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(&buffer);
    out
}

/// The files a query directory response lists, each with its stamp.
///
/// # Errors
/// Where an entry runs past the buffer.
pub fn names(body: &[u8]) -> Result<Vec<Listed>> {
    let buffer = wide_region(body, get_u16(body, 2), get_u32(body, 4))?;
    let mut listed = Vec::new();
    let mut at = 0;
    while at + ENTRY <= buffer.len() {
        let next = get_u32(buffer, at) as usize;
        let name_len = get_u32(buffer, at + NAME_LENGTH) as usize;
        let start = at + ENTRY;
        let end = start
            .checked_add(name_len)
            .filter(|end| *end <= buffer.len())
            .ok_or_else(|| protocol_error("a directory entry past the buffer"))?;
        let stamp = Stamp {
            length: get_u64(buffer, at + END_OF_FILE),
            written: get_u64(buffer, at + LAST_WRITE),
        };
        listed.push((codec::utf16::decode_lossy(&buffer[start..end]), stamp));
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
    fn a_directory_listing_carries_its_names_and_stamps_and_a_status_names_itself() {
        let handle = FileId::of(1);
        assert_eq!(id(&request(handle, "*")).expect("id"), handle);
        let stamp = |length, written| Stamp { length, written };
        let listing = vec![
            ("a.edi".to_string(), stamp(5, 7)),
            ("b.bin".to_string(), stamp(0, 9)),
        ];
        let response = response(&listing);
        assert_eq!(names(&response).expect("names"), listing);
        assert!(names(&super::response(&[])).expect("empty").is_empty());
        assert_eq!(status_name(wire::STATUS_BAD_NETWORK_NAME), "no such share");
    }

    #[test]
    fn a_file_written_again_is_written_later_even_at_once() {
        let mut written = Written::default();
        written.touch("a.edi");
        let first = written.at("a.edi");
        assert!(first > FILETIME_AT_UNIX_EPOCH, "written now");
        written.touch("a.edi");
        assert!(written.at("a.edi") > first);
        written.forget("a.edi");
        assert_eq!(written.at("a.edi"), 0);
    }
}
