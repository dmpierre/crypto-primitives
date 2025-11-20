#![allow(clippy::upper_case_acronyms)]
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::Error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, fmt::Debug, hash::Hash, rand::Rng};

pub mod blake3;
pub mod bowe_hopwood;
#[cfg(feature = "r1cs")]
pub mod constraints;
pub mod injective_map;
pub mod pedersen;
pub mod poseidon;
pub mod sha256;
#[cfg(feature = "r1cs")]
pub use constraints::*;

/// Interface to CRH. Note that in this release, while all implementations of `CRH` have fixed length,
/// variable length CRH may also implement this trait in future.
pub trait CRHScheme {
    type Input: ?Sized + Send;
    type Output: Clone + Eq + Debug + Hash + Default + CanonicalSerialize + CanonicalDeserialize;
    type Parameters: Clone + CanonicalSerialize + CanonicalDeserialize + Sync;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;
    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error>;
}

/// CRH used by merkle tree inner hash. Merkle tree will convert leaf output to bytes first.
pub trait TwoToOneCRHScheme {
    /// Raw Input type of TwoToOneCRH
    type Input: ?Sized;
    /// Raw Output type of TwoToOneCRH
    type Output: Clone + Eq + Debug + Hash + Default + CanonicalSerialize + CanonicalDeserialize;
    type Parameters: Clone + CanonicalSerialize + CanonicalDeserialize + Sync;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error>;

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error>;
}

#[derive(Debug, Default)]
pub struct HashCounter;

static HASH_COUNTER: AtomicUsize = AtomicUsize::new(0);

impl HashCounter {
    pub(crate) fn add() -> usize {
        HASH_COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    pub fn reset() {
        HASH_COUNTER.store(0, Ordering::SeqCst);
    }

    pub fn get() -> usize {
        HASH_COUNTER.load(Ordering::SeqCst)
    }
}
