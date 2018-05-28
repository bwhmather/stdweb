use webapi::typed_array::{TypedArray, ArrayKind};
use webcore::value::{Reference, Value, ConversionError};
use webcore::try_from::{TryFrom, TryInto};
use webcore::promise::Promise;


/// https://www.w3.org/TR/WebCryptoAPI/#dfn-Crypto
#[derive(Clone, Debug, PartialEq, Eq, ReferenceType)]
#[reference(instance_of = "Crypto")]
pub struct Crypto(Reference);


#[allow(missing_docs)]
impl Crypto {
    pub fn get_random_values<T: ArrayKind>(&self, array_buffer: &TypedArray<T>) {
        js!( @(no_return) @{self}.getRandomValues(@{array_buffer}); );
    }

    pub fn subtle(&self) -> SubtleCrypto {
        unsafe {
            js!(
                return @{self}.subtle;
            ).into_reference_unchecked().unwrap()
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyType {
    Public,
    Private,
    Secret,
}

impl TryFrom<Value> for KeyType {
    type Error = ConversionError;

    fn try_from(v: Value) -> Result<KeyType, ConversionError> {
        if let Some(string) = v.as_str() {
            match string {
                "public" => Ok(KeyType::Public),
                "private" => Ok(KeyType::Private),
                "secret" => Ok(KeyType::Secret),
                _ => Err(ConversionError::Custom(format!("Unknown key type: {}", string)))
            }
        } else {
            Err(ConversionError::Custom("Value for key type must be a string".to_string()))
        }
    }
}


impl<'a> Into<Value> for &'a KeyType {
    fn into(self: Self) -> Value {
        match self {
            KeyType::Public => "public",
            KeyType::Private => "private",
            KeyType::Secret => "secret",
        }.into()
    }
}


#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyUsage {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    DeriveKey,
    DeriveBits,
    WrapKey,
    UnwrapKey,
}


impl TryFrom<Value> for KeyUsage {
    type Error = ConversionError;

    fn try_from(v: Value) -> Result<KeyUsage, ConversionError> {
        if let Some(string) = v.as_str() {
            match string {
                "encrypt" => Ok(KeyUsage::Encrypt),
                "decrypt" => Ok(KeyUsage::Decrypt),
                "sign" => Ok(KeyUsage::Sign),
                "verify" => Ok(KeyUsage::Verify),
                "deriveKey" => Ok(KeyUsage::DeriveKey),
                "deriveBits" => Ok(KeyUsage::DeriveBits),
                "wrapKey" => Ok(KeyUsage::WrapKey),
                "unwrapKey" => Ok(KeyUsage::UnwrapKey),
                _ => Err(ConversionError::Custom(format!("Unknown key usage: {}", string)))
            }
        } else {
            Err(ConversionError::Custom("Value for key usage must be a string".to_string()))
        }
    }
}

impl<'a> Into<Value> for &'a KeyUsage {
    fn into(self: Self) -> Value {
        match self {
            KeyUsage::Encrypt => "encrypt",
            KeyUsage::Decrypt => "decrypt",
            KeyUsage::Sign => "sign",
            KeyUsage::Verify => "verify",
            KeyUsage::DeriveKey => "deriveKey",
            KeyUsage::DeriveBits => "deriveBits",
            KeyUsage::WrapKey => "wrapKey",
            KeyUsage::UnwrapKey => "unwrapKey",
        }.into()
    }
}



/// https://www.w3.org/TR/WebCryptoAPI/#dfn-SubtleCrypto
#[derive(Clone, Debug, PartialEq, Eq, ReferenceType)]
#[reference(instance_of = "Crypto")]
pub struct CryptoKey(Reference);


impl CryptoKey {
    pub fn key_type(&self) -> KeyType {
        js!( return @{self}.type; ).try_into().unwrap()
    }

    pub fn extractable(&self) -> bool {
        js!( return @{self}.extractable; ).try_into().unwrap()
    }

    pub fn algorithm(&self) -> Value {
        js!( return @{self}.algorithm; )
    }

    pub fn usages(&self) -> Vec<KeyUsage> {
        js!( return @{self}.usages; ).try_into().unwrap()
    }
}

pub trait KeyedAlgorithm: Into<Value> {}
impl KeyedAlgorithm for &'static str {}
impl KeyedAlgorithm for Value {}

pub trait EncryptAlgorithm: Into<Value> {}
impl EncryptAlgorithm for &'static str {}
impl EncryptAlgorithm for Value {}

pub trait SignAlgorithm: Into<Value> {}
impl SignAlgorithm for &'static str {}
impl SignAlgorithm for Value {}

pub trait DigestAlgorithm: Into<Value> {}
impl DigestAlgorithm for &'static str {}
impl DigestAlgorithm for Value {}

pub trait DeriveAlgorithm: Into<Value> {}
impl DeriveAlgorithm for &'static str {}
impl DeriveAlgorithm for Value {}

/// https://www.w3.org/TR/WebCryptoAPI/#dfn-SubtleCrypto
#[derive(Clone, Debug, PartialEq, Eq, ReferenceType)]
#[reference(instance_of = "Crypto")]
pub struct SubtleCrypto(Reference);

#[allow(missing_docs)]
impl SubtleCrypto {
    pub fn encrypt(
        &self, algorithm: impl EncryptAlgorithm, key: CryptoKey, data: TypedArray<u8>,
    ) -> Promise {
        unsafe {
            js!(
                return @{self}.encrypt(@{algorithm.into()}, @{key}, @{data})
            ).into_reference_unchecked().unwrap()
        }
    }

    pub fn decrypt(
        &self, algorithm: impl EncryptAlgorithm, key: CryptoKey, data: TypedArray<u8>,
    ) -> Promise {
        unsafe {
            js!(
                return @{self}.decrypt(@{algorithm.into()}, @{key}, @{data})
            ).into_reference_unchecked().unwrap()
        }
    }

    pub fn sign(
        &self, algorithm: impl SignAlgorithm, key: CryptoKey, data: TypedArray<u8>,
    ) -> Promise {
        unsafe {
            js!(
                return @{self}.sign(@{algorithm.into()}, @{key}, @{data})
            ).into_reference_unchecked().unwrap()
        }
    }

    pub fn verify(
        &self, algorithm: impl SignAlgorithm, key: CryptoKey,
        signature: TypedArray<u8>, data: TypedArray<u8>,
    ) -> Promise {
        unsafe {
            js!(
                return @{self}.verify(
                    @{algorithm.into()}, @{key},
                    @{signature}, @{data}
                )
            ).into_reference_unchecked().unwrap()
        }
    }

    pub fn digest(
        &self, algorithm: impl DigestAlgorithm, data: TypedArray<u8>,
    ) -> Promise {
        unsafe {
            js!(
                return @{self}.digest(@{algorithm.into()}, @{data})
            ).into_reference_unchecked().unwrap()
        }
    }

    pub fn generate_key(
        &self, algorithm: impl KeyedAlgorithm, extractable: bool, usages: &[KeyUsage],
    ) -> Promise {
        unimplemented!();
    }

    pub fn derive_key(
        &self, algorithm: impl DeriveAlgorithm, base_key: CryptoKey,
        derived_key_type: impl KeyedAlgorithm,
        extractable: bool, usages: &[KeyUsage],
    ) -> Promise {
        unimplemented!();
    }

    pub fn derive_bits(
        &self, algorithm: impl DeriveAlgorithm, base_key: CryptoKey, length: usize,
    ) -> Promise {
        unimplemented!();
    }

    pub fn import_key_from_buffer(
        &self, data: TypedArray<u8>, algorithm: impl KeyedAlgorithm,
        extractable: bool, usages: &[KeyUsage],
    ) -> Promise {
        unimplemented!();
    }

    pub fn import_key_from_json(
        &self, data: Reference, algorithm: impl KeyedAlgorithm,
        extractable: bool, usages: &[KeyUsage],
    ) -> Promise {
        unimplemented!();
    }

    pub fn export_key_to_buffer(&self, key: CryptoKey) -> Promise {
        unimplemented!();
    }

    pub fn export_key_to_json(&self, key: CryptoKey) -> Promise {
        unimplemented!();
    }
}


#[cfg(all(test, feature = "web_test"))]
mod web_tests {
    use super::*;
    use webapi::window::window;

    #[test]
    fn test_get_random_values() {
        let input: Vec<u8> = vec![0; 512];

        let array: TypedArray<u8> = input.as_slice().into();
        let crypto = window().crypto();
        crypto.get_random_values(&array);

        let output: Vec<u8> = array.into();
        assert_eq!(output.len(), input.len());
        assert_ne!(output, input);
    }
}
