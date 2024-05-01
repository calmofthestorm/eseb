use anyhow::Result;

use crate::key_util::{parse_header, KeyMaterial};

// Note that this is generally useless without the psk. This library is geared
// toward using Snow via symmetric encryption, so both sides have the full key
// and it is not reused.
#[derive(Clone)]
pub struct SnowPublicKey {
    key: Vec<u8>,
}

crate::serde_support::derive_serde!(SnowPublicKey, SnowPublicKeyVisitor);

impl std::str::FromStr for SnowPublicKey {
    type Err = anyhow::Error;
    fn from_str(data: &str) -> Result<SnowPublicKey> {
        let key_data = parse_header(data.trim(), &Self::HEADER)?;
        assert_eq!(key_data.len(), 32);
        Ok(SnowPublicKey { key: key_data })
    }
}

impl SnowPublicKey {
    pub fn key(&self) -> &[u8] {
        self.key.as_slice()
    }

    pub fn new(key: Vec<u8>) -> SnowPublicKey {
        SnowPublicKey { key }
    }
}

impl KeyMaterial for SnowPublicKey {
    const HEADER: &'static str = "eseb1::snow_public_key::";
    fn key_bytes(&self) -> Vec<u8> {
        self.key.clone()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serde() {
        let key = crate::SnowKeyPair::gen_key().unwrap().into_public();
        let ser_key = bincode::serialize(&key).unwrap();
        assert!(!ser_key.is_empty());
        let deser_key: SnowPublicKey = bincode::deserialize(&ser_key).unwrap();
        assert_eq!(deser_key.key_bytes(), key.key_bytes());
    }
}
