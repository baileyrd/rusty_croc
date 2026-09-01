//! Port of `src/message` — the encrypted control-message envelope.
//!
//! Wire-compatible with croc v10: a message is JSON with short field names
//! (`t`, `m`, `b`, `b2`, `n`; byte fields base64-encoded, empties omitted),
//! then DEFLATE-compressed, then (optionally) AES-256-GCM encrypted via
//! [`crate::crypt`].

use crate::{compress, crypt};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Message type constants, mirroring the Go `message.Type` values.
pub const TYPE_PAKE: &str = "pake";
pub const TYPE_PAKE_CONFIRM: &str = "pake-confirm";
pub const TYPE_EXTERNAL_IP: &str = "externalip";
pub const TYPE_FINISHED: &str = "finished";
pub const TYPE_ERROR: &str = "error";
pub const TYPE_CLOSE_RECIPIENT: &str = "close-recipient";
pub const TYPE_CLOSE_SENDER: &str = "close-sender";
pub const TYPE_RECIPIENT_READY: &str = "recipientready";
pub const TYPE_FILEINFO: &str = "fileinfo";

fn is_zero(n: &i64) -> bool {
    *n == 0
}

fn as_base64<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&BASE64.encode(bytes))
}

fn from_base64<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    BASE64.decode(s).map_err(serde::de::Error::custom)
}

/// Mirrors Go's `message.Message` including its `omitempty` JSON behavior.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "t", default, skip_serializing_if = "String::is_empty")]
    pub typ: String,
    /// croc's peer PAKE protocol version (`pakekey::PROTOCOL_VERSION`), set on
    /// `pake`/`pake-confirm` messages only; peers reject a mismatch.
    #[serde(rename = "v", default, skip_serializing_if = "is_zero")]
    pub version: i64,
    #[serde(rename = "m", default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(
        rename = "b",
        default,
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "as_base64",
        deserialize_with = "from_base64"
    )]
    pub bytes: Vec<u8>,
    #[serde(
        rename = "b2",
        default,
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "as_base64",
        deserialize_with = "from_base64"
    )]
    pub bytes2: Vec<u8>,
    #[serde(rename = "n", default, skip_serializing_if = "is_zero")]
    pub num: i64,
    /// Optional protocol extensions the peer advertises. We negotiate none, so
    /// peers fall back to the base protocol for us; the field is kept so their
    /// advertisements round-trip instead of failing to parse.
    #[serde(rename = "f", default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

#[derive(Debug)]
pub enum MessageError {
    Json(serde_json::Error),
    Crypt(crypt::CryptError),
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageError::Json(e) => write!(f, "json error: {e}"),
            MessageError::Crypt(e) => write!(f, "crypt error: {e}"),
        }
    }
}

impl std::error::Error for MessageError {}

/// JSON → compress → encrypt (when a key is present). Mirrors `message.Encode`.
pub fn encode(key: Option<&[u8]>, m: &Message) -> Result<Vec<u8>, MessageError> {
    let json = serde_json::to_vec(m).map_err(MessageError::Json)?;
    let compressed = compress::compress(&json);
    match key {
        Some(k) => crypt::encrypt(&compressed, k).map_err(MessageError::Crypt),
        None => Ok(compressed),
    }
}

/// Inverse of [`encode`]. Mirrors `message.Decode`.
pub fn decode(key: Option<&[u8]>, b: &[u8]) -> Result<Message, MessageError> {
    let compressed = match key {
        Some(k) => crypt::decrypt(b, k).map_err(MessageError::Crypt)?,
        None => b.to_vec(),
    };
    let json = compress::decompress(&compressed);
    serde_json::from_slice(&json).map_err(MessageError::Json)
}

/// Encode and send over a [`crate::comm::Comm`]. Mirrors `message.Send`.
pub fn send(
    c: &mut crate::comm::Comm,
    key: Option<&[u8]>,
    m: &Message,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = encode(key, m)?;
    c.send(&payload)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Message {
        Message {
            typ: TYPE_FILEINFO.to_string(),
            message: "hi".to_string(),
            bytes: vec![1, 2, 3, 255],
            bytes2: vec![],
            num: 42,
            ..Default::default()
        }
    }

    #[test]
    fn pake_fields_match_go() {
        // Go produces: {"t":"pake","v":2,"b":"AQ==","f":["x"]}
        let m = Message {
            typ: TYPE_PAKE.to_string(),
            version: 2,
            bytes: vec![1],
            features: vec!["x".to_string()],
            ..Default::default()
        };
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, r#"{"t":"pake","v":2,"b":"AQ==","f":["x"]}"#);
        assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), m);
    }

    #[test]
    fn json_matches_go() {
        // Go produces: {"t":"fileinfo","m":"hi","b":"AQID/w==","n":42}
        let json = serde_json::to_string(&sample()).unwrap();
        assert_eq!(json, r#"{"t":"fileinfo","m":"hi","b":"AQID/w==","n":42}"#);
    }

    #[test]
    fn round_trip_plain_and_encrypted() {
        let m = sample();
        let plain = encode(None, &m).unwrap();
        assert_eq!(decode(None, &plain).unwrap(), m);

        let (key, _) = crypt::new_key(b"pass123", Some(b"saltsalt")).unwrap();
        let enc = encode(Some(&key), &m).unwrap();
        assert_eq!(decode(Some(&key), &enc).unwrap(), m);
    }

    // Encoded bytes produced by croc's Go message.Encode with the same
    // key/salt — proves cross-decodability Go → Rust.
    #[test]
    fn go_encoded_vectors() {
        let m = sample();
        let (key, _) = crypt::new_key(b"pass123", Some(b"saltsalt")).unwrap();

        let go_plain = hex::decode(
            "002f00d0ff7b2274223a2266696c65696e666f222c226d223a226869222c2262223a22415149442f773d3d222c226e223a34327d010000ffff",
        )
        .unwrap();
        assert_eq!(decode(None, &go_plain).unwrap(), m);

        let go_encrypted = hex::decode(
            "18c6cd24c3f3db5f289b82a8ac209af5432ab946c38d64ac5d805ce431daef245393e16531a786b27bc4654ccfbef9bcc44765bbb633c7bcdd8866b380a09a17009c2ad3d8bad0bec8daf86341cbf7b1ca6dba6f1f",
        )
        .unwrap();
        assert_eq!(decode(Some(&key), &go_encrypted).unwrap(), m);
    }

    // Robustness smoke test (a deterministic mini-fuzz; the real campaign
    // lives in fuzz/). Decoding arbitrary bytes must never panic.
    #[test]
    fn decode_never_panics_on_garbage() {
        let (key, _) = crypt::new_key(b"pass123", Some(b"saltsalt")).unwrap();
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        for len in 0..256usize {
            // xorshift-derived pseudo-random bytes, no external rng needed.
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = seed as u8;
            }
            let _ = decode(None, &buf);
            let _ = decode(Some(&key), &buf);
        }
    }

    #[test]
    fn empty_fields_omitted() {
        let m = Message {
            typ: TYPE_FINISHED.to_string(),
            ..Default::default()
        };
        assert_eq!(serde_json::to_string(&m).unwrap(), r#"{"t":"finished"}"#);
        let back: Message = serde_json::from_str(r#"{"t":"finished"}"#).unwrap();
        assert_eq!(back, m);
    }
}
