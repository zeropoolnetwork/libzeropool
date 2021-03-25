use crate::{
    fawkes_crypto::{
        ff_uint::Num,
        borsh::{BorshSerialize, BorshDeserialize},
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
pub struct Note<P:PoolParams> {
    pub d: BoundedNum<P::Fr, constants::D>,
    pub pk_d: Num<P::Fr>,
    pub v: BoundedNum<P::Fr, constants::V>,
    pub st: BoundedNum<P::Fr, constants::ST>,
}

impl<P:PoolParams> Copy for Note<P> {}

impl<P:PoolParams> Eq for Note<P> {}

impl<P:PoolParams> PartialEq for Note<P> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.d.eq(&other.d) && 
        self.pk_d.eq(&other.pk_d) &&
        self.v.eq(&other.v) &&
        self.st.eq(&other.st)
    }
}


impl<P:PoolParams> BorshSerialize for Note<P> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.d.serialize(writer)?;
        self.pk_d.serialize(writer)?;
        self.v.serialize(writer)?;
        self.st.serialize(writer)
    }
}

impl<P:PoolParams> BorshDeserialize for Note<P> {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        Ok(Self{
            d: BorshDeserialize::deserialize(buf)?,
            pk_d: BorshDeserialize::deserialize(buf)?,
            v: BorshDeserialize::deserialize(buf)?,
            st: BorshDeserialize::deserialize(buf)?
        })  
    }
}


impl<P:PoolParams> fawkes_crypto::rand::distributions::Distribution<Note<P>>
    for fawkes_crypto::rand::distributions::Standard
{
    #[inline]
    fn sample<R: fawkes_crypto::rand::Rng + ?Sized>(&self, rng: &mut R) -> Note<P> {
        Note {
            d: rng.gen(),
            pk_d: rng.gen(),
            v: rng.gen(),
            st: rng.gen()
        }
    }
}



