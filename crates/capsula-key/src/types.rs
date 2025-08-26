#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Ed25519,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct KeyHandle(pub(crate) u64);
