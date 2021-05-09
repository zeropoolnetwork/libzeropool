use crate::{
    fawkes_crypto::{
        ff_uint::{Num, NumRepr, PrimeField, PrimeFieldParams, Uint},
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
pub struct Account<Fr:PrimeField> {
    pub xsk: Num<Fr>,
    pub interval: BoundedNum<Fr, { constants::H }>,
    pub v: BoundedNum<Fr, { constants::V }>,
    pub e: BoundedNum<Fr, { constants::E }>,
    pub st: BoundedNum<Fr, { constants::ST }>,
}

impl<Fr:PrimeField> Account<Fr> {
    pub fn hash<P:PoolParams<Fr=Fr>>(&self, params:&P) -> Num<Fr> {
        let v = [self.xsk, self.interval.to_num(), self.v.to_num(), self.e.to_num(), self.st.to_num()];
        poseidon(v.as_ref(), params.account())
    }
}


impl<Fr:PrimeField> Eq for Account<Fr> {}

impl<Fr:PrimeField> PartialEq for Account<Fr> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.xsk.eq(&other.xsk) && 
        self.interval.eq(&other.interval) &&
        self.v.eq(&other.v) &&
        self.e.eq(&other.e) &&
        self.st.eq(&other.st)
    }
}


impl<Fr:PrimeField> BorshSerialize for Account<Fr> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.xsk.serialize(writer)?;
        self.interval.serialize(writer)?;
        self.v.serialize(writer)?;
        self.e.serialize(writer)?;
        self.st.serialize(writer)
    }
}

impl<Fr:PrimeField> BorshDeserialize for Account<Fr> {
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



impl<Fr:PrimeField> fawkes_crypto::rand::distributions::Distribution<Account<Fr>>
    for fawkes_crypto::rand::distributions::Standard
{
    #[inline]
    fn sample<R: fawkes_crypto::rand::Rng + ?Sized>(&self, rng: &mut R) -> Account<Fr> {
        let n_bits = (<Fr as PrimeFieldParams>::Inner::NUM_WORDS*<Fr as PrimeFieldParams>::Inner::WORD_BITS) as u32;
        let v_num = rng.gen::<NumRepr<<Fr as PrimeFieldParams>::Inner>>()>>(n_bits - constants::V as u32/2);
        let e_num = rng.gen::<NumRepr<<Fr as PrimeFieldParams>::Inner>>()>>(n_bits - constants::E as u32/2);

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
