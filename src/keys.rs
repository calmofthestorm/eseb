use std::fmt::Write;

use anyhow::{Context, Error, Result};
use sodiumoxide::crypto::secretstream;

pub struct SymmetricKey {
    key: secretstream::xchacha20poly1305::Key,
}

impl std::str::FromStr for SymmetricKey {
    type Err = anyhow::Error;
    fn from_str(data: &str) -> Result<SymmetricKey> {
        let key_data = parse_header(data.trim(), &Self::HEADER)?;
        let key = secretstream::xchacha20poly1305::Key::from_slice(&key_data)
            .ok_or_else(|| Error::msg("sodiumoxide returned error attempting to parse the key"))?;
        Ok(SymmetricKey { key })
    }
}

impl AsRef<secretstream::xchacha20poly1305::Key> for SymmetricKey {
    fn as_ref(&self) -> &secretstream::xchacha20poly1305::Key {
        &self.key
    }
}

impl SymmetricKey {
    pub fn gen_key() -> SymmetricKey {
        SymmetricKey {
            key: secretstream::xchacha20poly1305::gen_key(),
        }
    }
}

impl KeyMaterial for SymmetricKey {
    const HEADER: &'static str = "eseb0::sym::";
    fn key_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }
}

pub trait KeyMaterial {
    const HEADER: &'static str;

    fn key_bytes(&self) -> &[u8];

    fn serialize_to_string(&self) -> String {
        let mut v = String::default();
        self.append_serialized(&mut v);
        v
    }

    fn append_serialized(&self, v: &mut String) {
        append_serialized(v, &Self::HEADER, self.key_bytes());
    }
}

fn append_serialized(v: &mut String, header: &str, key: &[u8]) {
    let start = v.len();
    v.push_str(&header);
    v.push_str(&mut base64::encode(&key));
    crc_encode(v, start);
}

fn crc_encode(buf: &mut String, start: usize) {
    let crc = crc16::State::<crc16::ARC>::calculate(&buf.as_bytes()[start..]);
    write!(buf, "::{:#05}", crc).expect("error writing to string");
}

fn crc_decode<'a>(buf: &'a str, header: &str) -> Result<Vec<u8>> {
    if buf.len() < 7 || buf[buf.len() - 7..buf.len() - 5] != *"::" {
        return Err(Error::msg(format!(
            "expected ::xxxxx trailing 5 digit crc16"
        )));
    }

    let msg_crc16: u16 = buf[buf.len() - 5..].parse().context("parse crc16")?;
    let data = &buf[..buf.len() - 7];
    let comp_crc = crc16::State::<crc16::ARC>::calculate(data.as_bytes());
    if msg_crc16 != comp_crc {
        return Err(Error::msg(format!(
            "expected crc16 {} calculated {}",
            msg_crc16, comp_crc
        )));
    }

    Ok(base64::decode(&data.as_bytes()[header.len()..]).context("decode bas64")?)
}

fn parse_header<'a>(data: &'a str, header: &str) -> Result<Vec<u8>> {
    if data.starts_with(header) {
        crc_decode(data, header)
    } else {
        return Err(Error::msg(format!(
            "key does not start with header {}",
            &header
        )));
    }
}
