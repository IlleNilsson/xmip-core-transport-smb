//! The kept SMB session, shared by the pool and the arrivals of the
//! receive that listed on it.
//!
//! A receive lists the share and hands each file back unread. Its body
//! opens the file on its first read and reads it a `READ` at a time as the
//! runtime asks, closing it at its end; its acknowledgement removes it on
//! `Accepted` — opened with delete-on-close, and closed, as the receive did
//! when it removed every file itself. SMB2 carries any number of open files
//! on one session, so the session is locked for one request and its answer,
//! never across a file: a send on the same session goes between two reads.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use transport::body::chunked;
use transport::error::Result;
use transport::pool::Pooled;
use transport::{Acknowledgement, Arrived, Verdict};

use crate::client::Client;
use crate::message::FileId;

/// A set-up session on one share, kept by the pool and shared with the
/// arrivals of the receive that listed on it.
#[derive(Clone)]
pub struct Connection(Arc<Mutex<Client>>);

impl Connection {
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self(Arc::new(Mutex::new(client)))
    }

    fn client(&self) -> MutexGuard<'_, Client> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Run `act` on the session: one request and its answer, or a few.
    ///
    /// # Errors
    /// As `act`.
    pub fn with<T>(&self, act: impl FnOnce(&mut Client) -> Result<T>) -> Result<T> {
        act(&mut self.client())
    }

    /// `name`, listed on this session, as an arrival from `origin`: read as
    /// the runtime asks, removed on `Accepted` and on `Refused` where
    /// `remove` says — a share has no place for a refused file — and left
    /// on `Failed`.
    #[must_use]
    pub fn arrival(&self, origin: String, name: String, remove: bool) -> Arrived {
        let connection = self.clone();
        let removing = name.clone();
        let acknowledgement = Acknowledgement::deferred(move |verdict| match verdict {
            Verdict::Accepted | Verdict::Refused(_) if remove => connection.with(|client| {
                let handle = client.open_to_delete(&removing)?;
                client.close(handle)
            }),
            Verdict::Accepted | Verdict::Refused(_) | Verdict::Failed => Ok(()),
        });
        let mut file = ShareFile {
            connection: self.clone(),
            name,
            open: None,
            offset: 0,
        };
        Arrived::new(origin, chunked(move || file.next_chunk()), acknowledgement)
    }
}

impl Pooled for Connection {
    fn usable(&mut self) -> bool {
        self.client().usable()
    }
}

/// One file's body: opened on the first read, read a chunk at a time,
/// closed at its end or when let go.
struct ShareFile {
    connection: Connection,
    name: String,
    /// The open file and its length as it was opened, or `None` before the
    /// first read and after the end.
    open: Option<(FileId, u64)>,
    /// Where the next `READ` starts.
    offset: u64,
}

impl ShareFile {
    /// The next chunk off the share, or `None` at the end, where the file
    /// is closed.
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        let mut client = self.connection.client();
        let (id, length) = match self.open {
            Some(open) => open,
            None if self.offset > 0 => return Ok(None),
            None => *self.open.insert(client.open(&self.name)?),
        };
        // The length the open answered ends the file without a `READ` more.
        let read = if self.offset < length {
            client.read_at(id, self.offset)?
        } else {
            None
        };
        if let Some(chunk) = read {
            self.offset += chunk.len() as u64;
            return Ok(Some(chunk));
        }
        self.open = None;
        // Past the start, so a read after the end opens nothing.
        self.offset = self.offset.max(1);
        client.close(id)?;
        Ok(None)
    }
}

impl Drop for ShareFile {
    /// A body let go before its end closes the file it opened.
    fn drop(&mut self) {
        if let Some((id, _)) = self.open.take() {
            let _ = self.connection.client().close(id);
        }
    }
}
