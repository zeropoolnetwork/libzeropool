use crate::{
    fawkes_crypto::{
        ff_uint::{Num, NumRepr, PrimeFieldParams, Uint},
        borsh::{BorshSerialize, BorshDeserialize},
        native::poseidon::poseidon,
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
    pub interval: BoundedNum<P::Fr, { constants::H }>,
    pub v: BoundedNum<P::Fr, { constants::V }>,
    pub e: BoundedNum<P::Fr, { constants::E }>,
    pub st: BoundedNum<P::Fr, { constants::ST }>,
}

impl<P:PoolParams> Account<P> {
    pub fn hash(&self, params:&P) -> Num<P::Fr> {
        let v = [self.xsk, self.interval.to_num(), self.v.to_num(), self.e.to_num(), self.st.to_num()];
        poseidon(v.as_ref(), params.account())
    }
}


impl<P:PoolParams> Eq for Account<P> {}

impl<P:PoolParams> PartialEq for Account<P> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.xsk.eq(&other.xsk) && 
        self.interval.eq(&other.interval) &&
        self.v.eq(&other.v) &&
        self.e.eq(&other.e) &&
        self.st.eq(&other.st)
    }
}


impl<P:PoolParams> BorshSerialize for Account<P> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.xsk.serialize(writer)?;
        self.interval.serialize(writer)?;
        self.v.serialize(writer)?;
        self.e.serialize(writer)?;
        self.st.serialize(writer)
    }
}

impl<P:PoolParams> BorshDeserialize for Account<P> {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        Ok(Self{
            xsk: BorshDeserialize::deserialize(buf)?,
            interval: BorshDeserialize::deserialize(buf)?,
            v: BorshDeserialize::deserialize(buf)?,
            e: BorshDeserialize::deserialize(buf)?,
            st: BorshDeserialize::deserialize(buf)?
        })  
    }
}



impl<P:PoolParams> fawkes_crypto::rand::distributions::Distribution<Account<P>>
    for fawkes_crypto::rand::distributions::Standard
{
    #[inline]
    fn sample<R: fawkes_crypto::rand::Rng + ?Sized>(&self, rng: &mut R) -> Account<P> {
        let n_bits = (<P::Fr as PrimeFieldParams>::Inner::NUM_WORDS*<P::Fr as PrimeFieldParams>::Inner::WORD_BITS) as u32;
        let v_num = rng.gen::<NumRepr<<P::Fr as PrimeFieldParams>::Inner>>()>>(n_bits - constants::V as u32/2);
        let e_num = rng.gen::<NumRepr<<P::Fr as PrimeFieldParams>::Inner>>()>>(n_bits - constants::E as u32/2);

        let v = BoundedNum::new(Num::from_uint(v_num).unwrap());
        let e = BoundedNum::new(Num::from_uint(e_num).unwrap());

        Account {
            xsk: rng.gen(),
            interval: rng.gen(),
            v,
            e,
            st: rng.gen()
        }
    }
}
