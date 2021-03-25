use crate::{
    fawkes_crypto::{
        ff_uint::Num,
        borsh::{BorshSerialize, BorshDeserialize}
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
    pub interval: BoundedNum<P::Fr, constants::H>,
    pub v: BoundedNum<P::Fr, constants::V>,
    pub st: BoundedNum<P::Fr, constants::ST>,
}


impl<P:PoolParams> Eq for Account<P> {}

impl<P:PoolParams> PartialEq for Account<P> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.xsk.eq(&other.xsk) && 
        self.interval.eq(&other.interval) &&
        self.v.eq(&other.v) &&
        self.st.eq(&other.st)
    }
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



impl<P:PoolParams> fawkes_crypto::rand::distributions::Distribution<Account<P>>
    for fawkes_crypto::rand::distributions::Standard
{
    #[inline]
    fn sample<R: fawkes_crypto::rand::Rng + ?Sized>(&self, rng: &mut R) -> Account<P> {
        Account {
            xsk: rng.gen(),
            interval: rng.gen(),
            v: rng.gen(),
            st: rng.gen()
        }
    }
}