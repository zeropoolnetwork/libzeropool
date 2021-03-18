use crate::{
    fawkes_crypto::{
        ff_uint::Num,
        core::sizedvec::SizedVec,
        borsh::{self, BorshSerialize, BorshDeserialize}
    },
    native::{
        boundednum::BoundedNum,
        params::PoolParams
    },
    constants
};


use std::fmt::Debug;
use std::io::{self, Write};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct Account<P:PoolParams> {
    pub xsk: Num<P::Fr>,
    pub interval: SizedVec<BoundedNum<P::Fr, constants::H>, constants::INTN>,
    pub v: BoundedNum<P::Fr, constants::V>,
    pub st: BoundedNum<P::Fr, constants::ST>,
}


impl<P:PoolParams> BorshSerialize for Account<P> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.xsk.serialize(writer)?;
        self.interval.serialize(writer)?;
        self.v.serialize(writer)?;
        self.st.serialize(writer)
    }
}

impl<P:PoolParams> BorshDeserialize for Account<P> {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        Ok(Self{
            xsk: BorshDeserialize::deserialize(buf)?,
            interval: BorshDeserialize::deserialize(buf)?,
            v: BorshDeserialize::deserialize(buf)?,
            st: BorshDeserialize::deserialize(buf)?
        })  
    }
}
