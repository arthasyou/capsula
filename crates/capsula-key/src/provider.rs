// provider.rs
use crate::{
    error::Result,
    types::{Algorithm, KeyHandle},
};

pub trait KeyProvider: Send + Sync + 'static {
    fn generate(&self) -> Result<KeyHandle>;

    fn get_alg(&self) -> Result<Algorithm>;

    fn import_pkcs8_der(&self, der: &[u8]) -> Result<KeyHandle>;
    fn export_pkcs8_der(&self, handle: KeyHandle) -> Result<Vec<u8>>;

    fn public_spki_der(&self, handle: KeyHandle) -> Result<Vec<u8>>;

    fn sign(&self, handle: KeyHandle, msg: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool>;
}
