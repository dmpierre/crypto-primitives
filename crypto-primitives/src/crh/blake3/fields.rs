use ark_serialize::CanonicalSerialize;
use core::{borrow::Borrow, marker::PhantomData};

use ark_ff::Field;
use ark_std::rand::RngCore;

use crate::{
    crh::{CRHScheme, HashCounter},
    Error,
};

use super::GenericDigest;

// blake3, but taking field elements as inputs
#[derive(Clone)]
pub struct Blake3F<F: Field> {
    _f: PhantomData<F>,
}

impl<F: Field> CRHScheme for Blake3F<F> {
    type Input = [F];
    type Output = GenericDigest<32>;
    type Parameters = ();

    fn setup<R: RngCore>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        (): &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let mut buf = Vec::new();
        input.borrow().serialize_compressed(&mut buf)?;

        let output: [_; 32] = blake3::hash(&buf).into();
        HashCounter::add();
        Ok(output.into())
    }
}
