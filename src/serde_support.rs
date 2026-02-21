macro_rules! derive_serde {
    ($key:ty, $visitor: ident) => {
        impl serde::Serialize for $key {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                serializer.serialize_str(&self.serialize_to_string())
            }
        }

        // Deserialize this to a single buffer.
        impl<'de> serde::Deserialize<'de> for $key {
            fn deserialize<D>(deserializer: D) -> Result<$key, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                deserializer.deserialize_str($visitor)
            }
        }

        pub(crate) struct $visitor;

        impl<'de> serde::de::Visitor<'de> for $visitor {
            type Value = $key;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a serialized string key")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(|_| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str("invalid string"),
                        &"valid string",
                    )
                })
            }
        }

        impl bincode::Encode for $key {
            fn encode<E: bincode::enc::Encoder>(
                &self,
                encoder: &mut E,
            ) -> Result<(), bincode::error::EncodeError> {
                let serialized = self.serialize_to_string();
                bincode::Encode::encode(&serialized, encoder)
            }
        }

        impl<Context> bincode::Decode<Context> for $key {
            fn decode<D: bincode::de::Decoder<Context = Context>>(
                decoder: &mut D,
            ) -> Result<Self, bincode::error::DecodeError> {
                let serialized = String::decode(decoder)?;
                serialized.parse().map_err(|_| {
                    bincode::error::DecodeError::Other("failed to parse serialized key")
                })
            }
        }

        bincode::impl_borrow_decode!($key);
    };
}

#[cfg(test)]
macro_rules! test_derive_serde {
    ($key:ty) => {
        #[test]
        fn test_serde() {
            let config = bincode::config::legacy();
            let key1 = <$key>::gen_key().unwrap();
            let key2 = <$key>::gen_key().unwrap();
            assert_ne!(key1.key_bytes(), key2.key_bytes());
            let ser_key1 = bincode::encode_to_vec(&key1, config).unwrap();
            let ser_key2 = bincode::encode_to_vec(&key2, config).unwrap();
            assert!(!ser_key1.is_empty());
            assert!(!ser_key2.is_empty());
            assert_ne!(ser_key1, ser_key2);
            let (deser_key1, _): ($key, usize) =
                bincode::decode_from_slice(&ser_key1, config).unwrap();
            let (deser_key2, _): ($key, usize) =
                bincode::decode_from_slice(&ser_key2, config).unwrap();
            assert_eq!(deser_key1.key_bytes(), key1.key_bytes());
            assert_eq!(deser_key2.key_bytes(), key2.key_bytes());
        }
    };
}

pub(crate) use derive_serde;

#[cfg(test)]
pub(crate) use test_derive_serde;
