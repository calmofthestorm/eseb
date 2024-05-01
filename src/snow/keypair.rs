use anyhow::Result;
use snow::Builder;
use sodiumoxide::randombytes::randombytes;

use crate::key_util::*;
use crate::snow::{SnowPrivateKey, SnowPsk, SnowPublicKey};

#[derive(Clone)]
pub struct SnowKeyPair {
    public: SnowPublicKey,
    private: SnowPrivateKey,
    psk: SnowPsk,
}

crate::serde_support::derive_serde!(SnowKeyPair, SnowKeyPairVisitor);

impl std::str::FromStr for SnowKeyPair {
    type Err = anyhow::Error;
    fn from_str(data: &str) -> Result<SnowKeyPair> {
        let mut key_data = parse_header(data.trim(), &Self::HEADER)?;
        assert_eq!(key_data.len(), 32 * 3);
        let private = key_data.split_off(64);
        let psk = key_data.split_off(32);
        let public = key_data;
        let public = SnowPublicKey::new(public);
        let private = SnowPrivateKey::new(private);
        let psk = SnowPsk::new(psk)?;
        Ok(SnowKeyPair {
            public,
            private,
            psk,
        })
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
            public: SnowPublicKey::new(kp.public),
            psk: SnowPsk::new(psk)?,
            private: SnowPrivateKey::new(kp.private),
        })
    }

    pub fn to_public(&self) -> SnowPublicKey {
        self.public.clone()
    }

    pub fn public(&self) -> &SnowPublicKey {
        &self.public
    }

    pub fn into_public(self) -> SnowPublicKey {
        self.public
    }

    pub fn to_private(&self) -> SnowPrivateKey {
        self.private.clone()
    }

    pub fn private(&self) -> &SnowPrivateKey {
        &self.private
    }

    pub fn into_private(self) -> SnowPrivateKey {
        self.private
    }

    pub fn to_psk(&self) -> SnowPsk {
        self.psk.clone()
    }

    pub fn psk(&self) -> &SnowPsk {
        &self.psk
    }

    pub fn into_psk(self) -> SnowPsk {
        self.psk
    }
}

impl AsRef<SnowPublicKey> for SnowKeyPair {
    fn as_ref(&self) -> &SnowPublicKey {
        &self.public
    }
}

impl KeyMaterial for SnowKeyPair {
    const HEADER: &'static str = "eseb1::snow_key_pair::";
    fn key_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            self.public().key().len() + self.private().key().len() + self.psk().key().len(),
        );
        v.extend_from_slice(&self.public().key());
        v.extend_from_slice(&self.psk().key());
        v.extend_from_slice(&self.private().key());
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
        assert!(!keypair.public().key().is_empty());
        assert!(!keypair.private().key().is_empty());
        assert!(!keypair.psk().key().is_empty());

        let public_key: &SnowPublicKey = keypair.as_ref();
        let pub_ser = public_key.serialize_to_string();
        let priv_ser = keypair.serialize_to_string();

        let deser_keypair = SnowKeyPair::from_str(&priv_ser).unwrap();
        let deser_pub = SnowPublicKey::from_str(&pub_ser).unwrap();

        assert_eq!(keypair.key_bytes(), deser_keypair.key_bytes());
        assert_eq!(public_key.key_bytes(), deser_pub.key_bytes());
        assert_eq!(keypair.to_public().key_bytes(), deser_pub.key_bytes());
    }

    crate::serde_support::test_derive_serde!(SnowKeyPair);
}
