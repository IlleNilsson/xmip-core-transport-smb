# xmip-core-transport-smb

SMB transport: one file on a share is one Stream — SMB2 over TCP, one tree, against a server or the in-process one this crate carries. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The session setup carries the three NTLM messages as MS-NLMP lays them out,
written and read through `xmip-core-library-ntlm`, the one layout the
identity gates read too; until 2026-09-24 this crate carried a counted-field
simplification of its own. Names on the wire are UTF-16 through
`xmip-core-library-codec`.

The in-process server draws each session id from the operating system's
random source (`codec::random`), never zero or all ones; until 2026-09-28 it
counted them, and a counted id is one another connection can name where
signing is off.

A Send Location creates, writes and closes on a session set up once per server and share and kept (`transport::Pool`). Until 2026-09-27 every file negotiated, set up a session, connected the tree and logged off.

A Receive Location lists, reads and removes on the same kept session. Until 2026-09-28 every receive set up a session and logged off.

## Acknowledgement

A file is consumed only after the runtime's whole receive cycle. A receive lists the share and hands each file back unread; its body opens the file on its first read and reads it a `READ` (1 MiB at most) at a time as the runtime asks, never whole in memory, closing it at the length its open answered. `Accepted` removes it, opened with delete-on-close and closed, unless `leave_files = true`. `Refused` removes it too, under the same setting: a share has no place for a refused file, the runtime audited the refusal, and from Message creation on the Stream is kept in Xmip (ADR-0013); left, it would be listed and refused again on every receive. `Failed` leaves it, and the next receive lists it again. The session is locked for one request and its answer, never across a file, so a send on the same session goes between two reads. Until 2026-10-02 a receive read and removed every file before handing it back.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
