use crate::native::delegated_deposit::*;
use fawkes_crypto::ff_uint::PrimeField;
use crate::fawkes_crypto::borsh::{BorshSerialize, BorshDeserialize};
use std::io::{self, Write};


impl<Fr:PrimeField> BorshSerialize for DelegatedDeposit<Fr> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.d.serialize(writer)?;
        self.p_d.serialize(writer)?;
        self.b.serialize(writer)
    }
}

impl<Fr:PrimeField> BorshDeserialize for DelegatedDeposit<Fr> {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        Ok(Self{
            d: BorshDeserialize::deserialize(buf)?,
            p_d: BorshDeserialize::deserialize(buf)?,
            b: BorshDeserialize::deserialize(buf)?
        })  
    }
}