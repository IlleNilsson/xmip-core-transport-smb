# xmip-core-transport-smb

SMB transport: one file on a share is one Stream — SMB2 over TCP, one tree, against a server or the in-process one this crate carries. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The session setup carries the three NTLM messages as MS-NLMP lays them out,
written and read through `xmip-core-library-ntlm`, the one layout the
identity gates read too; until 2026-09-24 this crate carried a counted-field
simplification of its own. Names on the wire are UTF-16 through
`xmip-core-library-codec`.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
