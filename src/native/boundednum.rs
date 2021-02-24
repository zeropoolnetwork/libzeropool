
use crate::fawkes_crypto::{
    ff_uint::{Uint, PrimeField, Num, NumRepr},
    typenum::Unsigned,
    borsh::{BorshDeserialize, BorshSerialize},
    serde::{Serialize, Deserialize, Serializer, Deserializer, de},
};
use std::marker::PhantomData;
use std::io::{Write, self};


#[derive(Clone, Debug)]
pub struct BoundedNum<Fr:PrimeField, L:Unsigned>(Num<Fr>, PhantomData<L>);

impl<Fr:PrimeField, L:Unsigned> Copy for BoundedNum<Fr, L> {}

impl<Fr:PrimeField, L:Unsigned> Eq for BoundedNum<Fr, L> {}

impl<Fr:PrimeField, L:Unsigned> PartialEq for BoundedNum<Fr, L> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}


impl<Fr:PrimeField, L:Unsigned> BoundedNum<Fr, L> {
    pub fn new(n:Num<Fr>) -> Self {
        assert!(L::U32 < Fr::MODULUS_BITS && n.to_uint() < (NumRepr::<Fr::Inner>::ONE << L::U32));
        Self::new_unchecked(n)
    }

    pub fn new_unchecked(n:Num<Fr>) -> Self {
        Self(n, PhantomData)
    }

    pub fn as_num(&self) -> &Num<Fr> {
        &self.0
    }

    pub fn to_num(&self) -> Num<Fr> {
        self.0
    }
}


impl<Fr:PrimeField, L:Unsigned> BorshSerialize for BoundedNum<Fr, L> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let n_limbs = (L::USIZE - 1) / 8 + 1;
        let w = writer.write(&self.0.try_to_vec().unwrap()[0..n_limbs])?;
        if w!=n_limbs {
            Err(io::Error::new(io::ErrorKind::Other, "Writer is broken"))
        } else {
            Ok(())
        }
    }
}

impl<Fr:PrimeField, L:Unsigned> BorshDeserialize for BoundedNum<Fr, L> {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        let n_limbs = (L::USIZE - 1) / 8 + 1;
        let n_limbs_total = Fr::Inner::NUM_WORDS*Fr::Inner::WORD_BITS/8;
        let mut b = vec![0;n_limbs_total];
        b[0..n_limbs].copy_from_slice(&buf[0..n_limbs]);
        *buf = &buf[n_limbs..];
        let n = Num::<Fr>::try_from_slice(&b)?;
        Ok(Self(n, PhantomData))
    }
}

impl<Fr:PrimeField, L:Unsigned> Serialize for BoundedNum<Fr, L> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Serialize::serialize(&self.0, serializer)
    }
}

impl<'de, Fr:PrimeField, L:Unsigned> Deserialize<'de> for BoundedNum<Fr, L> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n: NumRepr<Fr::Inner> = Deserialize::deserialize(deserializer)?;
        if n >= (NumRepr::ONE << L::U32) {
            Err(de::Error::custom("Overflow"))
        } else {
            Ok(Self::new(Num::from_uint_unchecked(n)))
        }

    }
}


impl<Fr:PrimeField, L:Unsigned> fawkes_crypto::rand::distributions::Distribution<BoundedNum<Fr, L>>
    for fawkes_crypto::rand::distributions::Standard
{
    #[inline]
    fn sample<R: fawkes_crypto::rand::Rng + ?Sized>(&self, rng: &mut R) -> BoundedNum<Fr, L> {
        let mut t : NumRepr<Fr::Inner> = rng.gen();
        t >>= (Fr::Inner::NUM_WORDS*Fr::Inner::WORD_BITS) as u32 - L::U32;
        BoundedNum::new(Num::from_uint_unchecked(t))
    }
}
