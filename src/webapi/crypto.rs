use webapi::typed_array::{TypedArray, ArrayKind};
use webcore::value::Reference;


/// https://www.w3.org/TR/WebCryptoAPI/#dfn-Crypto
#[derive(Clone, Debug, PartialEq, Eq, ReferenceType)]
#[reference(instance_of = "Crypto")]
pub struct Crypto(Reference);


impl Crypto {
    pub fn get_random_values<T: ArrayKind>(&self, array_buffer: &TypedArray<T>) {
        js!( @(no_return) @{self}.getRandomValues(@{array_buffer}); );
    }

    pub fn subtle(&self) -> SubtleCrypto {
        unsafe {
            js!(
                return @{self}.crypto;
            ).into_reference_unchecked().unwrap()
        }
    }
}

pub enum KeyType {
    Public,
    Private,
    Secret,
}

impl TryFrom<Value> for KeyType {
    type Error = ConversionError;

    fn try_from(v: Value) -> Result<KeyType, ConversionError> {
        match v.try_into()? {
            "public" => Ok(KeyType::Public),
            "private" => Ok(KeyType::Private),
            "secret" => Ok(KeyType::Secret),
            other => Err(ConversionError::Custom(format!("Unknown key type: {}", other)))
        }
    }
}


enum KeyUsage {
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

    fn try_from(v: Value) -> Result<KeyUsage> {
        match v.try_into()? {
            "encrypt" => Ok(KeyUsage::Encrypt),
            "decrypt" => Ok(KeyUsage::Decrypt),
            "sign" => Ok(KeyUsage::Sign),
            "verify" => Ok(KeyUsage::Verify),
            "deriveKey" => Ok(KeyUsage::DeriveKey),
            "deriveBits" => Ok(KeyUsage::DeriveBits),
            "wrapKey" => Ok(KeyUsage::WrapKey),
            "unwrapKey" => Ok(KeyUsage::UnwrapKey),
        }
    }
}


/// https://www.w3.org/TR/WebCryptoAPI/#dfn-SubtleCrypto
#[derive(Clone, Debug, PartialEq, Eq, ReferenceType)]
#[reference(instance_of = "Crypto")]
pub struct CryptoKey(Reference);


impl CryptoKey {
    pub fn type(&self) -> KeyType {

    }

    pub fn extractable(&self) -> bool {

    }

    pub fn algorithm(&self) -> Value {

    }

    pub fn usages(&self) -> Vec<KeyUsage> {

    }
}


pub trait KeyedAlgorithm: Copy + Into<Value> {}
impl KeyedAlgorithm for &str {}
impl KeyedAlgorithm for Value {}


pub trait EncryptAlgorithm: Copy + Into<Value> {}
impl EncryptAlgorithm for &str {}
impl EncryptAlgorithm for Value {}


pub trait SignAlgorithm: Copy + Into<Value> {}
impl SignAlgorithm for &str {}
impl SignAlgorithm for Value {}


pub trait DeriveAlgorithm: Copy + Into<Value> {}
impl DeriveAlgorithm for &str {}
impl DeriveAlgorithm for Value {}


pub trait SerializableAlgorithm: Copy + Into<Value> {}
impl SerializableAlgorithm for &str {}
impl SerializableAlgorithm for Value {}


/// https://www.w3.org/TR/WebCryptoAPI/#dfn-SubtleCrypto
#[derive(Clone, Debug, PartialEq, Eq, ReferenceType)]
#[reference(instance_of = "Crypto")]
pub struct SubtleCrypto(Reference);

impl SubtleCrypto {
    pub fn encrypt(
        algorithm: impl EncryptAlgorithm, key: CryptoKey, data: TypedArray<u8>,
    ) -> PromiseFuture<TypedArray<u8>> {


    }

    pub fn decrypt(
        algorithm: impl EncryptAlgorithm, key: CryptoKey, data: TypedArray<u8>,
    ) -> PromiseFuture<TypedArray<u8>> {


    }

    pub fn sign(
        algorithm: impl SignAlgorithm, key: CryptoKey, data: TypedArray<u8>,
    ) -> PromiseFuture<TypedArray<u8>> {

    }


    pub fn verify(
        algorithm: impl SignAlgorithm, key: CryptoKey,
        signature: TypedArray<u8>, data: TypedArray<u8>,
    ) -> PromiseFuture<bool> {

    }

    pub fn digest(
        algorithm: impl DigestAlgorithm, data: TypedArray<u8>,
    ) -> PromiseFuture<TypedArray> {

    }

    pub fn generate_key(
        algorithm: impl KeyedAlgorithm, extractable: bool, usages: &[KeyUsage],
    ) -> PromiseFuture<CryptoKey> {

    }

    pub fn derive_key(
        algorithm: impl DeriveAlgorithm, base_key: CryptoKey,
        derived_key_type: impl KeyedAlgorithm,
        extractable: bool, usages: &[KeyUsage],
    ) -> PromiseFuture<CryptoKey> {

    }

    pub fn derive_bits(
        algorithm: impl DeriveAlgorithm, base_key: CryptoKey, length: usize,
    ) -> Promise {

    }

    pub fn import_key_from_buffer(
        data: TypedArray<u8>, algorithm: AlgorithmIdentifier,
        extractable: bool, usages: &[KeyUsage],
    ) -> Promise {

    }

    pub fn import_key_from_json(
        data: Reference, algorithm: AlgorithmIdentifier,
        extractable: bool, usages: &[KeyUsage],
    ) -> Promise {

    }

    pub fn export_key_to_buffer(key: CryptoKey) -> Promise {

    }

    pub fn export_key_to_json(key: CryptoKey) -> Promise {

    }

    pub fn wrap_key(


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
