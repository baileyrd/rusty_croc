//! Port of croc's `src/pakekey` — the peer PAKE key schedule that binds an
//! exchange to its participants, room, purpose and exact wire transcript.
//!
//! croc's peer handshake (protocol version 2) is:
//!
//! 1. Both sides build the PAKE with the ordered identities returned by
//!    [`identities`] (party A is the receiver, party B the sender).
//! 2. The responder picks a 32-byte [`SALT_SIZE`] salt and both sides expand
//!    the raw PAKE session key with [`derive`] into a traffic key plus the two
//!    role-specific confirmation tags.
//! 3. Each side proves possession of its tag with a `pake-confirm` message
//!    ([`confirm`]) before any encrypted traffic flows.

use crate::pake::{Pake, PakeError};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// The fail-closed croc peer PAKE protocol version (Go: `pakekey.ProtocolVersion`).
pub const PROTOCOL_VERSION: i64 = 2;
/// Required peer key-schedule salt size.
pub const SALT_SIZE: usize = 32;

pub const PURPOSE_TRANSFER: &str = "peer-transfer";
pub const PURPOSE_LOCAL_PROBE: &str = "local-ip-probe";

const IDENTITY_DOMAIN: &[u8] = b"croc/spake2/participant/v2";
const TRANSCRIPT_DOMAIN: &[u8] = b"croc/spake2/channel/v2";
const TAG_SIZE: usize = 32;

#[derive(Debug)]
pub enum KeyError {
    UnsupportedPurpose(String),
    MissingRoom,
    MissingSessionKey,
    MissingCurve,
    MissingWireValues,
    BadSaltLength(usize),
    Pake(PakeError),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::UnsupportedPurpose(p) => write!(f, "unsupported PAKE purpose {p:?}"),
            KeyError::MissingRoom => write!(f, "PAKE room is required"),
            KeyError::MissingSessionKey => write!(f, "PAKE session key is required"),
            KeyError::MissingCurve => write!(f, "PAKE curve is required"),
            KeyError::MissingWireValues => write!(f, "both PAKE wire values are required"),
            KeyError::BadSaltLength(n) => {
                write!(f, "PAKE salt must be {SALT_SIZE} bytes, got {n}")
            }
            KeyError::Pake(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<PakeError> for KeyError {
    fn from(e: PakeError) -> Self {
        KeyError::Pake(e)
    }
}

/// Public session values authenticated by the channel key schedule.
/// `initiator` is party A's first PAKE value, `responder` party B's reply.
pub struct Context<'a> {
    pub purpose: &'a str,
    pub room: &'a str,
    pub curve: &'a str,
    pub initiator: &'a [u8],
    pub responder: &'a [u8],
    pub salt: &'a [u8],
}

/// Traffic key plus the role-specific confirmation tags.
#[derive(Clone, Default)]
pub struct Keys {
    pub encryption_key: Vec<u8>,
    /// Sent by the receiver (party A) and checked by the sender.
    pub confirmation_a: Vec<u8>,
    /// Sent by the sender (party B) and checked by the receiver.
    pub confirmation_b: Vec<u8>,
}

impl Drop for Keys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.encryption_key.zeroize();
    }
}

/// Ordered, implicit participant identities. Party A is always the receiver
/// and party B the sender. Mirrors `pakekey.Identities`.
pub fn identities(purpose: &str, room: &str) -> Result<(Vec<u8>, Vec<u8>), KeyError> {
    if purpose != PURPOSE_TRANSFER && purpose != PURPOSE_LOCAL_PROBE {
        return Err(KeyError::UnsupportedPurpose(purpose.to_string()));
    }
    if room.is_empty() {
        return Err(KeyError::MissingRoom);
    }
    let version = (PROTOCOL_VERSION as u64).to_le_bytes();
    let id_a = frame(&[
        IDENTITY_DOMAIN,
        &version,
        purpose.as_bytes(),
        room.as_bytes(),
        b"receiver",
    ]);
    let id_b = frame(&[
        IDENTITY_DOMAIN,
        &version,
        purpose.as_bytes(),
        room.as_bytes(),
        b"sender",
    ]);
    Ok((id_a, id_b))
}

/// Identity-bound PAKE instance for a croc session. Mirrors `pakekey.Init`.
pub fn init(
    password: &[u8],
    role: u8,
    curve: &str,
    purpose: &str,
    room: &str,
) -> Result<Pake, KeyError> {
    let (id_a, id_b) = identities(purpose, room)?;
    Ok(Pake::init_curve_with_identities(
        password, role, curve, &id_a, &id_b,
    )?)
}

/// Expand a PAKE session key into a traffic key and mutual key-confirmation
/// tags bound to the exact croc transcript. Mirrors `pakekey.Derive`.
pub fn derive(shared_key: &[u8], ctx: &Context<'_>) -> Result<Keys, KeyError> {
    if shared_key.is_empty() {
        return Err(KeyError::MissingSessionKey);
    }
    if ctx.curve.is_empty() {
        return Err(KeyError::MissingCurve);
    }
    if ctx.initiator.is_empty() || ctx.responder.is_empty() {
        return Err(KeyError::MissingWireValues);
    }
    if ctx.salt.len() != SALT_SIZE {
        return Err(KeyError::BadSaltLength(ctx.salt.len()));
    }
    let (id_a, id_b) = identities(ctx.purpose, ctx.room)?;
    let version = (PROTOCOL_VERSION as u64).to_le_bytes();
    let transcript = frame(&[
        TRANSCRIPT_DOMAIN,
        &version,
        ctx.purpose.as_bytes(),
        ctx.room.as_bytes(),
        ctx.curve.as_bytes(),
        &id_a,
        &id_b,
        ctx.initiator,
        ctx.responder,
        ctx.salt,
    ]);

    let mut material = [0u8; 96];
    Hkdf::<Sha256>::new(Some(ctx.salt), shared_key)
        .expand(&transcript, &mut material)
        .expect("96 bytes is a valid HKDF-SHA256 output length");
    let keys = Keys {
        encryption_key: material[..32].to_vec(),
        confirmation_a: confirmation_tag(&material[32..64], &transcript),
        confirmation_b: confirmation_tag(&material[64..96], &transcript),
    };
    use zeroize::Zeroize;
    material.zeroize();
    Ok(keys)
}

/// Constant-time confirmation-tag check. Mirrors `pakekey.Confirm`.
pub fn confirm(expected: &[u8], received: &[u8]) -> bool {
    expected.len() == TAG_SIZE && received.len() == TAG_SIZE && expected.ct_eq(received).into()
}

fn confirmation_tag(key: &[u8], transcript: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(transcript);
    mac.finalize().into_bytes().to_vec()
}

/// Length-prefixed field encoding (little-endian u64 lengths), matching Go's
/// `frame` so both implementations hash identical transcripts.
fn frame(fields: &[&[u8]]) -> Vec<u8> {
    let total: usize = fields.iter().map(|f| 8 + f.len()).sum();
    let mut out = Vec::with_capacity(total);
    for field in fields {
        out.extend_from_slice(&(field.len() as u64).to_le_bytes());
        out.extend_from_slice(field);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_exchange(curve: &str, purpose: &str, room: &str) -> (Keys, Keys) {
        let pw = b"shared password";
        let mut a = init(pw, 0, curve, purpose, room).unwrap();
        let mut b = init(pw, 1, curve, purpose, room).unwrap();
        let initiator = a.bytes();
        b.update(&initiator).unwrap();
        let responder = b.bytes();
        a.update(&responder).unwrap();
        let salt = [0x42u8; SALT_SIZE];
        let ctx = Context {
            purpose,
            room,
            curve,
            initiator: &initiator,
            responder: &responder,
            salt: &salt,
        };
        (
            derive(&a.session_key().unwrap(), &ctx).unwrap(),
            derive(&b.session_key().unwrap(), &ctx).unwrap(),
        )
    }

    #[test]
    fn peers_agree_on_channel_material() {
        for curve in ["p256", "p384", "p521", "siec"] {
            let (ka, kb) = run_exchange(curve, PURPOSE_TRANSFER, "room-one");
            assert_eq!(ka.encryption_key, kb.encryption_key);
            assert_eq!(ka.encryption_key.len(), 32);
            assert!(confirm(&ka.confirmation_a, &kb.confirmation_a));
            assert!(confirm(&ka.confirmation_b, &kb.confirmation_b));
            assert_ne!(ka.confirmation_a, ka.confirmation_b);
        }
    }

    #[test]
    fn different_rooms_and_purposes_diverge() {
        let (a, _) = run_exchange("p256", PURPOSE_TRANSFER, "room-one");
        let (b, _) = run_exchange("p256", PURPOSE_TRANSFER, "room-two");
        let (c, _) = run_exchange("p256", PURPOSE_LOCAL_PROBE, "room-one");
        assert_ne!(a.encryption_key, b.encryption_key);
        assert_ne!(a.encryption_key, c.encryption_key);
    }

    // Values produced by Go's pakekey.Derive for a fixed session key/transcript.
    #[test]
    fn derive_matches_go_vectors() {
        let salt = [0x42u8; SALT_SIZE];
        let ctx = Context {
            purpose: PURPOSE_TRANSFER,
            room: "room-one",
            curve: "p256",
            initiator: b"initiator-wire-value",
            responder: b"responder-wire-value",
            salt: &salt,
        };
        let keys = derive(&[1u8; 32], &ctx).unwrap();
        assert_eq!(
            hex_of(&keys.encryption_key),
            "be2e8cc761b7a5a59a5bc1cb52f0b296d0247f618e2ca620470e996b0a0a29ad"
        );
        assert_eq!(
            hex_of(&keys.confirmation_a),
            "7ba94b4e401ffcab9a5b5d35eb2b73810ee1934d922200df96301635f7df3844"
        );
        assert_eq!(
            hex_of(&keys.confirmation_b),
            "faba5168442a153b80cb3d1e69ec3603931287b4f79b46930bc517f3d45fcca9"
        );
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn rejects_bad_inputs() {
        let salt = [0u8; 4];
        let ctx = Context {
            purpose: PURPOSE_TRANSFER,
            room: "r",
            curve: "p256",
            initiator: b"a",
            responder: b"b",
            salt: &salt,
        };
        assert!(matches!(
            derive(&[1u8; 32], &ctx),
            Err(KeyError::BadSaltLength(4))
        ));
        assert!(identities("nope", "room").is_err());
        assert!(identities(PURPOSE_TRANSFER, "").is_err());
        assert!(!confirm(&[0u8; 32], &[0u8; 31]));
    }
}
