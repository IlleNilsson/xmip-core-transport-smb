# xmip-core-transport-smb

SMB transport: one file on a share is one Stream — SMB2 over TCP, one tree, against a server or the in-process one this crate carries. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The session setup carries the three NTLM messages as MS-NLMP lays them out,
written and read through `xmip-core-library-ntlm`, the one layout the
identity gates read too; until 2026-09-24 this crate carried a counted-field
simplification of its own. Names on the wire are UTF-16 through
`xmip-core-library-codec`.

A Location that names a secret logs on with its password (`logon`): the
AUTHENTICATE carries the `NTLMv2` response to the server's challenge,
computed through `ntlm::response` — the one computation the `ntlm` gate
verifies with too — over a blob made at the node's Clock, the secret read
as each session is set up, never per file on a kept one (ADR-0019,
amendment 2026-11-25). A Location that names none logs on with the names
alone, as a guest. Until 2026-11-25 every logon was a guest's, and a
Location naming a secret was refused as the node started. Messages are
still not signed, so a server that requires signing — Windows 11 24H2 and
Windows Server 2025 by default — refuses the session. The in-process
server, given a login (`SmbTransport::admitting`), admits only an
AUTHENTICATE for that user whose proof its password makes, answering any
other `STATUS_LOGON_FAILURE`; given none, it admits any logon as a guest.

The in-process server draws each session id from the operating system's
random source (`codec::random`), never zero or all ones; until 2026-09-28 it
counted them, and a counted id is one another connection can name where
signing is off.

A Send Location creates, writes and closes on a session set up once per server and share and kept (`transport::Pool`). Until 2026-09-27 every file negotiated, set up a session, connected the tree and logged off. A send writes the Message a `WRITE` at a time as it is read from the Ledger, never whole in memory (`Sending::Streamed`, 2026-10-19), and a receive hands over no more files of a listing than the runtime has room for.

A Receive Location lists, reads and removes on the same kept session. Until 2026-09-28 every receive set up a session and logged off.

## Acknowledgement

A file is consumed only after the runtime's whole receive cycle. A receive lists the share and hands each file back unread; its body opens the file on its first read and reads it a `READ` (1 MiB at most) at a time as the runtime asks, never whole in memory, closing it at the length its open answered. `Accepted` removes it, opened with delete-on-close and closed, unless `leave_files = true`. `Refused` leaves it where it lies, whatever the setting: a refusal at a transport gate keeps nothing in Xmip, so the file is the only copy. This Location does not receive it again while it is unchanged — the `EndOfFile` and `LastWriteTime` its `QUERY_DIRECTORY` entry carries (`FileDirectoryInformation`); written again, it is a new arrival. What is remembered as refused is the node process's: a node started again receives a refused file once more, and refuses it again. `Failed` leaves it, and the next receive lists it again. The session is locked for one request and its answer, never across a file, so a send on the same session goes between two reads. Until 2026-10-02 a receive read and removed every file before handing it back.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## The declaration

What a Location of this technology is configured with is two `const`s in its `declaration` module, `src/declaration.rs`, beside the code, which `Configured` reads (ADR-0064, amendment 2026-11-26): `declaration::SETTINGS`, `share`, `domain`, `user`, `workstation`, `leave_files` and `timeout`, and `SCHEMES`, `smb`. Built with its `declaration` feature alone (`--no-default-features --features declaration`), the crate is those and nothing more: its code and every crate the code is built on — NTLM among them — are behind the default feature. So the library the surfaces load carries it without the code, through the gathering crate xmip-core-declaration (open problem 48), and the language server and the desktop suggest and check an SMB Location's settings though no node in their process loaded the technology. `test/Declaration.Test.ps1` in the estate holds that the declaration builds nothing the transport capability does not.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
