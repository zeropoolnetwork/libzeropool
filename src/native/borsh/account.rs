use crate::native::account::*;
use crate::{
    fawkes_crypto::{
        ff_uint::{PrimeField},
        borsh::{BorshSerialize, BorshDeserialize},
    },
};


use std::io::{self, Write};

impl<Fr:PrimeField> BorshSerialize for Account<Fr> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.eta.serialize(writer)?;
        self.i.serialize(writer)?;
        self.b.serialize(writer)?;
        self.e.serialize(writer)?;
        self.t.serialize(writer)
    }
}

impl<Fr:PrimeField> BorshDeserialize for Account<Fr> {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        Ok(Self{
            eta: BorshDeserialize::deserialize(buf)?,
            i: BorshDeserialize::deserialize(buf)?,
            b: BorshDeserialize::deserialize(buf)?,
            e: BorshDeserialize::deserialize(buf)?,
            t: BorshDeserialize::deserialize(buf)?
        })  
    }
}