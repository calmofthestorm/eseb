use anyhow::{Error, Result};
use sodiumoxide::crypto::secretstream;

use crate::key_util::*;

#[derive(Clone)]
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
    pub fn gen_key() -> Result<SymmetricKey> {
        Ok(SymmetricKey {
            key: secretstream::xchacha20poly1305::gen_key(),
        })
    }
}

impl KeyMaterial for SymmetricKey {
    const HEADER: &'static str = "eseb0::sym::";
    fn key_bytes(&self) -> Vec<u8> {
        self.key.as_ref().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    #[test]
    fn test_symmetric_key() {
        let key = SymmetricKey::gen_key().unwrap();
        let ser_key = key.serialize_to_string();
        assert!(!ser_key.is_empty());
        let deser_key = SymmetricKey::from_str(&ser_key).unwrap();
        assert_eq!(deser_key.key_bytes(), key.key_bytes());
    }
}
