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
        append_serialized(v, Self::HEADER, &self.key_bytes());
    }
}

pub fn append_serialized(v: &mut String, header: &str, key: &[u8]) {
    let start = v.len();
    v.push_str(header);
    v.push_str(&base64::encode(key));
    crc_encode(v, start);
}

pub fn crc_encode(buf: &mut String, start: usize) {
    let crc = crc16::State::<crc16::ARC>::calculate(&buf.as_bytes()[start..]);
    write!(buf, "::{:#05}", crc).expect("error writing to string");
}

pub fn crc_decode(buf: &str, header: &str) -> Result<Vec<u8>> {
    let bytes = buf.as_bytes();
    if bytes.len() < 7 || &bytes[bytes.len() - 7..bytes.len() - 5] != b"::" {
        return Err(Error::msg(
            "expected ::xxxxx trailing 5 digit crc16".to_string(),
        ));
    }

    if bytes.len() < header.len() + 7 {
        return Err(Error::msg("buffer shorter than header"));
    }

    let crc_str = std::str::from_utf8(&bytes[bytes.len() - 5..]).context("parse crc16")?;
    let msg_crc16: u16 = crc_str.parse().context("parse crc16")?;
    let data = &bytes[..bytes.len() - 7];
    let comp_crc = crc16::State::<crc16::ARC>::calculate(data);
    if msg_crc16 != comp_crc {
        return Err(Error::msg(format!(
            "expected crc16 {} calculated {}",
            msg_crc16, comp_crc
        )));
    }

    base64::decode(&data[header.len()..]).context("decode bas64")
}

pub fn parse_header(data: &str, header: &str) -> Result<Vec<u8>> {
    if data.starts_with(header) {
        crc_decode(data, header)
    } else {
        Err(Error::msg(format!(
            "key does not start with header {}",
            &header
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_append_and_parse_roundtrip() {
        let header = "eseb0::test::";
        let key = b"hello world";
        let mut buf = String::default();
        append_serialized(&mut buf, header, key);

        let parsed = parse_header(&buf, header).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn test_crc_mismatch() {
        let header = "eseb0::test::";
        let key = b"hello world";
        let mut buf = String::default();
        append_serialized(&mut buf, header, key);

        let mut bad = buf.into_bytes();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == b'0' { b'1' } else { b'0' };
        let bad = String::from_utf8(bad).unwrap();

        let err = crc_decode(&bad, header).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("expected crc16"));
    }

    #[test]
    fn test_header_mismatch() {
        let header = "eseb0::test::";
        let key = b"hello world";
        let mut buf = String::default();
        append_serialized(&mut buf, header, key);

        let err = parse_header(&buf, "eseb0::other::").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("key does not start with header"));
    }

    #[test]
    fn test_crc_decode_short_string() {
        let err = crc_decode("short", "eseb0::test::").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("expected ::xxxxx"));
    }

    #[test]
    fn test_crc_decode_bad_base64() {
        let header = "eseb0::test::";
        let mut buf = String::from(header);
        buf.push_str("%%");
        crc_encode(&mut buf, 0);

        let err = crc_decode(&buf, header).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("decode bas64"));
    }

    proptest! {
        #[test]
        fn prop_append_and_parse_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let header = "eseb0::prop::";
            let mut buf = String::default();
            append_serialized(&mut buf, header, &data);

            let parsed = parse_header(&buf, header).unwrap();
            prop_assert_eq!(parsed, data);
        }
    }
}
