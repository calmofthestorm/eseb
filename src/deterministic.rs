use aes::{
    Aes256,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
};
use anyhow::Result;
use generic_array::{GenericArray, sequence::Split, typenum::U32};

use crate::key_util::*;

/// Used to deterministically encrypt 256-bit messages. Be aware of the security
/// implications of deterministic encryption, in particular, that the encryption
/// is deterministic and therefore cannot provide a security level that
/// guarantees that the encryption is non-deterministic (you know, because it's
/// deterministic):
/// https://en.wikipedia.org/wiki/Deterministic_encryption#Security
///
/// Not for use in applications that require non-deterministic encryption, nor
/// in applications where deterministic encryption would be inappropriate. We
/// recommend that you discuss your cryptographic situation with a licensed
/// cryptographic counselor before proceeding.
///
/// Basically, see this picture:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#/media/File:Tux_encrypted_ecb.png
///
/// In addition to the above problem shared by all deterministic encryption,
/// this implementation additionally leaks information by virtue of the two
/// blocks being encrypted independently -- a bit flip in the first half will
/// not satisfy the "avalanche" requirement -- only the first half will change.
/// It also does not provide any authentication/integrity.
///
/// This is intended for a very specific purpose where the inputs are
/// cryptographic hash functions. They are therefore uniformly distributed and
/// provide the necessary "avalanche" relative to their input.
///
/// AES-SIV would be a better choice for general purpose deterministic
/// encryption, or FFX/EME to keep the same length. At some point, some
/// AI-powered vulnerability scanner is going to flag this and start sending
/// increasingly threatening letters to my neighbors, at which point I'll
/// probably give in and switch, like how I did for non-cryptographic
/// applications of MD5.
#[derive(Clone)]
pub struct DeterministicEncryptionSymmetricKey256 {
    aes_key: [u8; 32],
    aes: Aes256,
    iv: [u8; 16],
}

crate::serde_support::derive_serde!(
    DeterministicEncryptionSymmetricKey256,
    DeterministicEncryptionSymmetricKey256Visitor
);

impl KeyMaterial for DeterministicEncryptionSymmetricKey256 {
    const HEADER: &'static str = "eseb1::deterministic_aes256_ecb::";
    fn key_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(48);
        v.extend_from_slice(&self.aes_key);
        v.extend_from_slice(&self.iv);
        v
    }
}

impl std::str::FromStr for DeterministicEncryptionSymmetricKey256 {
    type Err = anyhow::Error;
    fn from_str(data: &str) -> Result<DeterministicEncryptionSymmetricKey256> {
        let key_data = parse_header(data.trim(), Self::HEADER)?;
        Self::from_slice(&key_data)
    }
}

impl DeterministicEncryptionSymmetricKey256 {
    pub fn gen_key() -> Result<DeterministicEncryptionSymmetricKey256> {
        Self::from_slice(&sodiumoxide::randombytes::randombytes(48))
    }

    pub fn encrypt<B>(&self, cleartext: B) -> [u8; 32]
    where
        B: Into<GenericArray<u8, U32>>,
    {
        let mut cleartext = cleartext.into();
        for j in 0..16 {
            cleartext[j] ^= self.iv[j];
        }
        let (block1, block2) = cleartext.split();
        let mut blocks = [block1, block2];
        self.aes.encrypt_blocks(&mut blocks);
        GenericArray::from_exact_iter(blocks.into_iter().flatten())
            .unwrap()
            .into()
    }

    pub fn decrypt<B>(&self, crypttext: B) -> [u8; 32]
    where
        B: Into<GenericArray<u8, U32>>,
    {
        let (block1, block2) = crypttext.into().split();
        let mut blocks = [block1, block2];
        self.aes.decrypt_blocks(&mut blocks);
        let mut cleartext = GenericArray::from_exact_iter(blocks.into_iter().flatten()).unwrap();
        for j in 0..16 {
            cleartext[j] ^= self.iv[j];
        }
        cleartext.into()
    }

    fn from_slice(slice: &[u8]) -> Result<DeterministicEncryptionSymmetricKey256> {
        if slice.len() != 48 {
            anyhow::bail!("Keys must be exactly 48 bytes.");
        }
        let (aes_key, iv) = slice.split_at(32);
        let aes_key: GenericArray<u8, U32> = *GenericArray::from_slice(aes_key);
        Ok(DeterministicEncryptionSymmetricKey256 {
            aes: Aes256::new(&aes_key),
            aes_key: aes_key.into(),
            iv: iv.try_into().expect(""),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    #[test]
    fn test_key_serialization() {
        let key = DeterministicEncryptionSymmetricKey256::gen_key().unwrap();
        let ser_key = key.serialize_to_string();
        assert!(!ser_key.is_empty());
        let deser_key = DeterministicEncryptionSymmetricKey256::from_str(&ser_key).unwrap();
        assert_eq!(deser_key.key_bytes(), key.key_bytes());
    }

    #[test]
    fn test_deterministic_encryption() {
        let ser_key = "eseb1::deterministic_aes256_ecb::fFQYNb2eELqivWZohtZrXUO93OTrxgVqemQtRlGqoYVMz2q/yaiH/oqmxWCUkvOo::48978";
        let key = DeterministicEncryptionSymmetricKey256::from_str(ser_key).unwrap();
        let cleartext = *GenericArray::from_slice(b"1192645332aaXysz!!924cbeeeeeeeee");
        let crypttext = key.encrypt(cleartext);
        assert_eq!(
            hex::encode(crypttext),
            "4e154674cc7c4fa5db8fecb365f698085ccfdd74603bc96fa319b1f97959e574"
        );
        assert_eq!(cleartext, key.decrypt(crypttext).into());
    }

    /// Test that with an all-zero IV, and a key where the first 16 and second
    /// 16 bytes are identical, the first and second 16 bytes of the crypttext
    /// are also identical. We include this test to illustrate that these
    /// properties are intentional consequences of the design. Of course we
    /// could avoid this particular matter with a 32 byte block cipher.
    #[test]
    fn test_initialization_vector() {
        let cleartext = *GenericArray::from_slice(b"THE SUN THE SUN THE SUN THE SUN ");
        let mut key = DeterministicEncryptionSymmetricKey256::gen_key().unwrap();

        let crypttext = key.encrypt(cleartext);
        assert_ne!(crypttext[..16], crypttext[16..]);
        assert_eq!(cleartext, key.decrypt(crypttext).into());

        key.iv.fill(0);
        let crypttext = key.encrypt(cleartext);
        assert_eq!(crypttext[..16], crypttext[16..]);
        assert_eq!(cleartext, key.decrypt(crypttext).into());
    }

    crate::serde_support::test_derive_serde!(DeterministicEncryptionSymmetricKey256);
}
