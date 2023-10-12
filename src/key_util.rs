use std::fmt::Write;

use anyhow::{Context, Error, Result};

pub trait KeyMaterial {
    const HEADER: &'static str;

    fn key_bytes(&self) -> Vec<u8>;

    fn serialize_to_string(&self) -> String {
        let mut v = String::default();
        self.append_serialized(&mut v);
        v
    }

    fn append_serialized(&self, v: &mut String) {
        append_serialized(v, &Self::HEADER, &self.key_bytes());
    }
}

pub fn append_serialized(v: &mut String, header: &str, key: &[u8]) {
    let start = v.len();
    v.push_str(&header);
    v.push_str(&mut base64::encode(&key));
    crc_encode(v, start);
}

pub fn crc_encode(buf: &mut String, start: usize) {
    let crc = crc16::State::<crc16::ARC>::calculate(&buf.as_bytes()[start..]);
    write!(buf, "::{:#05}", crc).expect("error writing to string");
}

pub fn crc_decode<'a>(buf: &'a str, header: &str) -> Result<Vec<u8>> {
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

pub fn parse_header<'a>(data: &'a str, header: &str) -> Result<Vec<u8>> {
    if data.starts_with(header) {
        crc_decode(data, header)
    } else {
        return Err(Error::msg(format!(
            "key does not start with header {}",
            &header
        )));
    }
}
