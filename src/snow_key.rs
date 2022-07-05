use anyhow::Result;
use snow::Builder;
use sodiumoxide::randombytes::randombytes;

use crate::key_util::*;

#[derive(Clone)]
pub struct SnowPublicKey {
    public: Vec<u8>,
    psk: Vec<u8>,
}

#[derive(Clone)]
pub struct SnowKeyPair {
    public: SnowPublicKey,
    private: Vec<u8>,
}

impl std::str::FromStr for SnowKeyPair {
    type Err = anyhow::Error;
    fn from_str(data: &str) -> Result<SnowKeyPair> {
        let mut key_data = parse_header(data.trim(), &Self::HEADER)?;
        assert_eq!(key_data.len(), 32 * 3);
        let private = key_data.split_off(64);
        let psk = key_data.split_off(32);
        let public = key_data;
        let public = SnowPublicKey { public, psk };
        Ok(SnowKeyPair { public, private })
    }
}

impl std::str::FromStr for SnowPublicKey {
    type Err = anyhow::Error;
    fn from_str(data: &str) -> Result<SnowPublicKey> {
        let mut key_data = parse_header(data.trim(), &Self::HEADER)?;
        assert_eq!(key_data.len(), 32 * 2);
        let psk = key_data.split_off(64);
        let public = key_data;
        Ok(SnowPublicKey { public, psk })
    }
}

impl SnowKeyPair {
    pub fn gen_key() -> Result<SnowKeyPair> {
        let params: snow::params::NoiseParams = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse()?;
        let builder: Builder<'_> = Builder::new(params.clone());
        let kp = builder.generate_keypair()?;

        let psk = randombytes(32);

        assert_eq!(kp.public.len(), 32);
        assert_eq!(kp.private.len(), 32);
        assert_eq!(psk.len(), 32);

        Ok(SnowKeyPair {
            public: SnowPublicKey {
                public: kp.public,
                psk,
            },
            private: kp.private,
        })
    }

    pub fn to_public(&self) -> &SnowPublicKey {
        return &self.public;
    }

    pub fn into_public(self) -> SnowPublicKey {
        return self.public;
    }
}

impl AsRef<SnowPublicKey> for SnowKeyPair {
    fn as_ref(&self) -> &SnowPublicKey {
        &self.public
    }
}

impl KeyMaterial for SnowPublicKey {
    const HEADER: &'static str = "eseb0::snow_public_key::";
    fn key_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.public.len() + self.psk.len());
        v.extend_from_slice(&self.public);
        v.extend_from_slice(&self.psk);
        v
    }
}

impl KeyMaterial for SnowKeyPair {
    const HEADER: &'static str = "eseb0::snow_private_key::";
    fn key_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            self.public.public.len() + self.private.len() + self.public.psk.len(),
        );
        v.extend_from_slice(&self.public.public);
        v.extend_from_slice(&self.public.psk);
        v.extend_from_slice(&self.private);
        v
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_generate() {
        let keypair = SnowKeyPair::gen_key().unwrap();
        assert!(!keypair.public.public.is_empty());
        assert!(!keypair.private.is_empty());
        assert!(!keypair.public.psk.is_empty());

        let public_key: &SnowPublicKey = keypair.as_ref();
        let pub_ser = public_key.serialize_to_string();
        let priv_ser = keypair.serialize_to_string();

        let deser_keypair = SnowKeyPair::from_str(&priv_ser).unwrap();
        let deser_pub = SnowPublicKey::from_str(&pub_ser).unwrap();

        assert_eq!(keypair.key_bytes(), deser_keypair.key_bytes());
        assert_eq!(public_key.key_bytes(), deser_pub.key_bytes());
        assert_eq!(keypair.to_public().key_bytes(), deser_pub.key_bytes());
    }
}
