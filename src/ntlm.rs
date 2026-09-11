//! The `NTLMSSP` tokens the SMB2 session setup carries (MS-NLMP): the
//! client's Negotiate, the server's Challenge with its eight-byte nonce,
//! and the client's Authenticate naming the domain, user and workstation.
//!
//! **The `NTLMv2` response is not computed here.** A real Authenticate
//! carries an `HMAC-MD5` over the challenge keyed by an MD4 of the password
//! (MS-NLMP section 3.3.2); that cryptography is one mechanism at one gate
//! and belongs to the identity capability, which will lift this module
//! (ADR-0044, ADR-0050). Until it does, the Authenticate carries the
//! identity and the server takes it as a guest logon — the way TLS is
//! deferred to the transport capability (ADR-0033). The token layout here
//! is a counted-field simplification of the security-buffer table the
//! specification uses; it is enough to carry the identity both ways.

use transport::error::{Result, protocol_error};

use crate::wire::{from_utf16, get_u16, push_u16, utf16};

/// The eight bytes that open every `NTLMSSP` token.
const NTLMSSP: &[u8; 8] = b"NTLMSSP\0";

/// `NtLmNegotiate`.
pub const NEGOTIATE: u32 = 1;
/// `NtLmChallenge`.
pub const CHALLENGE: u32 = 2;
/// `NtLmAuthenticate`.
pub const AUTHENTICATE: u32 = 3;

/// The identity an Authenticate token carries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    pub domain: String,
    pub user: String,
    pub workstation: String,
}

fn head(message_type: u32) -> Vec<u8> {
    let mut out = NTLMSSP.to_vec();
    out.extend_from_slice(&message_type.to_le_bytes());
    out
}

/// The client's Negotiate token.
#[must_use]
pub fn negotiate() -> Vec<u8> {
    head(NEGOTIATE)
}

/// The server's Challenge token, carrying its `nonce`.
#[must_use]
pub fn challenge(nonce: &[u8; 8]) -> Vec<u8> {
    let mut out = head(CHALLENGE);
    out.extend_from_slice(nonce);
    out
}

/// The nonce a Challenge token carries.
///
/// # Errors
/// Where the token is not a Challenge or is too short.
pub fn read_challenge(token: &[u8]) -> Result<[u8; 8]> {
    if message_type(token)? != CHALLENGE {
        return Err(protocol_error("not an NTLM challenge"));
    }
    token
        .get(12..20)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| protocol_error("a challenge without its nonce"))
}

/// The client's Authenticate token, naming `identity`. The `NTLMv2`
/// response the identity capability computes would follow; here there is
/// none, and the server takes the logon as a guest.
#[must_use]
pub fn authenticate(identity: &Identity) -> Vec<u8> {
    let mut out = head(AUTHENTICATE);
    for field in [&identity.domain, &identity.user, &identity.workstation] {
        let encoded = utf16(field);
        push_u16(&mut out, u16::try_from(encoded.len()).unwrap_or(u16::MAX));
        out.extend_from_slice(&encoded);
    }
    out
}

/// The identity an Authenticate token carries.
///
/// # Errors
/// Where the token is not an Authenticate or is cut short.
pub fn read_authenticate(token: &[u8]) -> Result<Identity> {
    if message_type(token)? != AUTHENTICATE {
        return Err(protocol_error("not an NTLM authenticate"));
    }
    let mut at = 12;
    let mut field = || -> Result<String> {
        let length = get_u16(token, at) as usize;
        let start = at + 2;
        let end = start
            .checked_add(length)
            .filter(|end| *end <= token.len())
            .ok_or_else(|| protocol_error("an NTLM field past the token"))?;
        at = end;
        Ok(from_utf16(&token[start..end]))
    };
    Ok(Identity {
        domain: field()?,
        user: field()?,
        workstation: field()?,
    })
}

/// The message type a token declares.
///
/// # Errors
/// Where the token does not open with the `NTLMSSP` signature.
pub fn message_type(token: &[u8]) -> Result<u32> {
    if token.get(0..8) != Some(NTLMSSP) {
        return Err(protocol_error("a token without the NTLMSSP signature"));
    }
    Ok(u32::from_le_bytes([
        token[8], token[9], token[10], token[11],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_tokens_carry_their_type_and_read_back() {
        assert_eq!(message_type(&negotiate()).expect("type"), NEGOTIATE);
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let challenge = challenge(&nonce);
        assert_eq!(message_type(&challenge).expect("type"), CHALLENGE);
        assert_eq!(read_challenge(&challenge).expect("nonce"), nonce);
        let identity = Identity {
            domain: "WORKGROUP".to_string(),
            user: "xmip".to_string(),
            workstation: "XMIP-HOST".to_string(),
        };
        let token = authenticate(&identity);
        assert_eq!(message_type(&token).expect("type"), AUTHENTICATE);
        assert_eq!(read_authenticate(&token).expect("identity"), identity);
    }

    #[test]
    fn a_token_of_the_wrong_type_or_shape_is_refused() {
        assert!(message_type(b"nope").is_err());
        assert!(read_challenge(&negotiate()).is_err());
        assert!(read_authenticate(&challenge(&[0; 8])).is_err());
        let mut cut = authenticate(&Identity::default());
        cut.truncate(13);
        assert!(read_authenticate(&cut).is_err(), "cut short");
    }
}
