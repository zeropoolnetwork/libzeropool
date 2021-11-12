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
        self.d.serialize(writer)?;
        self.p_d.serialize(writer)?;
        self.i.serialize(writer)?;
        self.b.serialize(writer)?;
        self.e.serialize(writer)
    }
}

impl<Fr:PrimeField> BorshDeserialize for Account<Fr> {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        Ok(Self{
            d: BorshDeserialize::deserialize(buf)?,
            p_d: BorshDeserialize::deserialize(buf)?,
            i: BorshDeserialize::deserialize(buf)?,
            b: BorshDeserialize::deserialize(buf)?,
            e: BorshDeserialize::deserialize(buf)?
        })  
    }
}