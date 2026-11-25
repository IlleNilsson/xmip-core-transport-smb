//! The logon a session setup carries in its AUTHENTICATE (MS-NLMP 3.1.5.1.2):
//! what a client presents, and whether a server admits it.
//!
//! A Location that names a secret logs on with its password: the `NTLMv2`
//! response to the server's challenge, computed from it as the estate
//! computes it once (`ntlm::response`), over a blob made at the moment the
//! node's Clock reads and a client challenge drawn fresh. The secret is read
//! as the session is set up, never per file on a kept one (ADR-0019,
//! amendment 2026-11-25). A Location that names none logs on with the names
//! alone, which a server that admits guests takes as a guest. Until
//! 2026-11-25 every logon was a guest's.
//!
//! A far end given a login ([`admits`]) admits only an AUTHENTICATE for its
//! user whose `NTProofStr` that password makes over the challenge it sent,
//! as a Windows server holding the account does; it admits any logon where
//! it is given none.

use ntlm::response::{nt_hash, nt_response, proof, response_key};
use ntlm::{Authenticate, Challenge, ClientChallenge};
use transport::error::Result;
use transport::{Login, Secured};
use xcore::SecretKind;

use crate::client::Identity;

/// What a client presents: the names, and the password its `NTLMv2`
/// response is computed from, with the Unix seconds its blob is made at.
/// The password is never printed: there is no `Debug`.
pub struct Logon {
    identity: Identity,
    password: Option<(String, u64)>,
}

impl Logon {
    /// The names alone: a guest's logon.
    #[must_use]
    pub const fn guest(identity: Identity) -> Self {
        Self {
            identity,
            password: None,
        }
    }

    /// As `identity`, with `password`, the response made at `unix_seconds`.
    #[must_use]
    pub fn with_password(identity: Identity, password: String, unix_seconds: u64) -> Self {
        Self {
            identity,
            password: Some((password, unix_seconds)),
        }
    }

    /// As `identity`, with the password `secured` holds, read now, the
    /// response made at `unix_seconds`; a guest's where no secret is named.
    ///
    /// # Errors
    /// Where the secret is not set, is no password, or could not be read.
    pub fn presented(
        identity: Identity,
        secured: Option<&Secured>,
        unix_seconds: u64,
    ) -> Result<Self> {
        Ok(match secured {
            Some(secured) => {
                let password = secured.as_kind(SecretKind::Password, "smb")?;
                Self::with_password(identity, password, unix_seconds)
            }
            None => Self::guest(identity),
        })
    }

    /// The AUTHENTICATE answering `offered` with `flags`: the `NTLMv2`
    /// response and an empty LM one, `Z(24)`, where a password is given, as
    /// MS-NLMP 3.1.5.1.2 has a client send with `NTLMv2`; no response at
    /// all for a guest.
    #[must_use]
    pub fn authenticate(&self, offered: &Challenge, flags: u32) -> Authenticate {
        let (lm_response, nt_response) = match &self.password {
            Some((password, unix_seconds)) => {
                let blob = ClientChallenge::at(*unix_seconds).to_blob(codec::random::array());
                let identity = &self.identity;
                let key = response_key(&nt_hash(password), &identity.user, &identity.domain);
                (
                    vec![0; 24],
                    nt_response(&key, &offered.server_challenge, &blob),
                )
            }
            None => (Vec::new(), Vec::new()),
        };
        Authenticate {
            domain: self.identity.domain.clone(),
            user: self.identity.user.clone(),
            workstation: self.identity.workstation.clone(),
            flags,
            lm_response,
            nt_response,
            ..Authenticate::default()
        }
    }
}

/// Whether `read`, answering the server `challenge`, logs on as `expected`:
/// its user is `expected`'s, as Windows compares one, and its `NTProofStr`
/// is the one `expected`'s password makes, compared in constant time. An
/// `NTLMv1` response, or none, is no logon.
#[must_use]
pub fn admits(expected: &Login, challenge: &[u8; 8], read: &Authenticate) -> bool {
    let Ok((offered, blob)) = read.ntlmv2() else {
        return false;
    };
    let key = response_key(&nt_hash(&expected.password), &read.user, &read.domain);
    let named = read.user.eq_ignore_ascii_case(&expected.user);
    let proven = codec::constant_time::equal(&proof(&key, challenge, blob), offered);
    named & proven
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntlm::flags::{NEGOTIATE_NTLM, NEGOTIATE_UNICODE};

    fn party() -> Identity {
        Identity {
            domain: "PARTY".to_string(),
            user: "orders".to_string(),
            workstation: "XMIP".to_string(),
        }
    }

    #[test]
    fn a_logon_with_the_password_is_admitted_and_one_with_another_or_none_is_not() {
        let flags = NEGOTIATE_UNICODE | NEGOTIATE_NTLM;
        let offered = Challenge::new(flags, [7; 8]);
        let expected = Login::new("ORDERS", "pencil");
        let made = |logon: &Logon| {
            let sent = logon.authenticate(&offered, flags).to_bytes();
            Authenticate::parse(&sent).expect("read back")
        };
        let right = made(&Logon::with_password(
            party(),
            "pencil".into(),
            1_800_000_000,
        ));
        assert!(
            admits(&expected, &[7; 8], &right),
            "the user as Windows compares it"
        );
        assert_eq!(right.lm_response, [0; 24]);
        assert!(!admits(&expected, &[8; 8], &right), "another challenge");
        let wrong = made(&Logon::with_password(party(), "pen".into(), 1_800_000_000));
        assert!(!admits(&expected, &[7; 8], &wrong), "another password");
        let other = Login::new("invoices", "pencil");
        assert!(!admits(&other, &[7; 8], &right), "another user");
        let guest = made(&Logon::guest(party()));
        assert_eq!(guest.nt_response, Vec::<u8>::new(), "a guest's has none");
        assert!(!admits(&expected, &[7; 8], &guest), "a guest");
    }
}
