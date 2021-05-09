use fawkes_crypto::ff_uint::{NumRepr, PrimeField, PrimeFieldParams, Uint};

use crate::{
    fawkes_crypto::{
        ff_uint::Num,
        borsh::{BorshSerialize, BorshDeserialize},
        native::poseidon::poseidon
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
pub struct Note<Fr:PrimeField> {
    pub d: BoundedNum<Fr, { constants::D }>,
    pub pk_d: Num<Fr>,
    pub v: BoundedNum<Fr, { constants::V }>,
    pub st: BoundedNum<Fr, { constants::ST }>,
}

impl<Fr:PrimeField> Note<Fr> {
    pub fn hash<P:PoolParams<Fr=Fr>>(&self, params:&P) -> Num<Fr> {
        let v = [self.d.to_num(), self.pk_d, self.v.to_num(), self.st.to_num()];
        poseidon(v.as_ref(), params.note())
    }
}

impl<Fr:PrimeField> Copy for Note<Fr> {}

impl<Fr:PrimeField> Eq for Note<Fr> {}

impl<Fr:PrimeField> PartialEq for Note<Fr> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.d.eq(&other.d) && 
        self.pk_d.eq(&other.pk_d) &&
        self.v.eq(&other.v) &&
        self.st.eq(&other.st)
    }
}


impl<Fr:PrimeField> BorshSerialize for Note<Fr> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.d.serialize(writer)?;
        self.pk_d.serialize(writer)?;
        self.v.serialize(writer)?;
        self.st.serialize(writer)
    }
}

impl<Fr:PrimeField> BorshDeserialize for Note<Fr> {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        Ok(Self{
            d: BorshDeserialize::deserialize(buf)?,
            pk_d: BorshDeserialize::deserialize(buf)?,
            v: BorshDeserialize::deserialize(buf)?,
            st: BorshDeserialize::deserialize(buf)?
        })  
    }
}


impl<Fr:PrimeField> fawkes_crypto::rand::distributions::Distribution<Note<Fr>>
    for fawkes_crypto::rand::distributions::Standard
{
    #[inline]
    fn sample<R: fawkes_crypto::rand::Rng + ?Sized>(&self, rng: &mut R) -> Note<Fr> {
        let n_bits = (<Fr as PrimeFieldParams>::Inner::NUM_WORDS*<Fr as PrimeFieldParams>::Inner::WORD_BITS) as u32;
        let v_num = rng.gen::<NumRepr<<Fr as PrimeFieldParams>::Inner>>()>>(n_bits - constants::V as u32/2);
        let v = BoundedNum::new(Num::from_uint(v_num).unwrap());
        Note {
            d: rng.gen(),
            pk_d: rng.gen(),
            v,
            st: rng.gen()
        }
    }
}



