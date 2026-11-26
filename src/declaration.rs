//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// Every setting a Location takes beyond its address, the server,
/// `host:445`: where a Location connects.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "share",
            kind: Kind::Text,
            presence: Presence::Required,
            meaning: "The share a Receive Location lists and a Send Location writes into \
                      when a target names none.",
            applies: Applies::Both,
        },
        Setting {
            name: "domain",
            kind: Kind::Text,
            presence: Presence::Optional,
            meaning: "The domain the session setup presents; `WORKGROUP` when left out.",
            applies: Applies::Both,
        },
        Setting {
            name: "user",
            kind: Kind::Text,
            presence: Presence::Optional,
            meaning: "The user the session setup presents, its password the Location's \
                      secret; `xmip` when left out.",
            applies: Applies::Both,
        },
        Setting {
            name: "workstation",
            kind: Kind::Text,
            presence: Presence::Optional,
            meaning: "The workstation the session setup presents; `XMIP` when left out.",
            applies: Applies::Both,
        },
        Setting {
            name: "leave_files",
            kind: Kind::Boolean,
            presence: Presence::Optional,
            meaning: "Whether a Receive Location leaves the files it accepted in place; \
                      each is removed once its receive cycle accepted it when left out.",
            applies: Applies::Receive,
        },
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long a server that stops mid-answer is waited on; unbounded when \
             left out.",
        ),
    ],
};

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["smb"];
