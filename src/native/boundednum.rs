
use crate::fawkes_crypto::{
    ff_uint::{Uint, PrimeField, Num, NumRepr},
    borsh::{BorshDeserialize, BorshSerialize},
    serde::{Serialize, Deserialize, Serializer, Deserializer, de},
};
use std::io::{Write, self};


#[derive(Clone, Debug)]
pub struct BoundedNum<Fr:PrimeField, const L: usize>(Num<Fr>);

impl<Fr:PrimeField, const L: usize> Copy for BoundedNum<Fr, L> {}

impl<Fr:PrimeField, const L: usize> Eq for BoundedNum<Fr, L> {}

impl<Fr:PrimeField, const L: usize> PartialEq for BoundedNum<Fr, L> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}


impl<Fr:PrimeField, const L: usize> BoundedNum<Fr, L> {
    pub fn new(n:Num<Fr>) -> Self {
        assert!(L < Fr::MODULUS_BITS as usize && n.to_uint() < (NumRepr::<Fr::Inner>::ONE << L as u32));
        Self::new_unchecked(n)
    }

    pub fn new_unchecked(n:Num<Fr>) -> Self {
        Self(n)
    }

    pub fn as_num(&self) -> &Num<Fr> {
        &self.0
    }

    pub fn to_num(&self) -> Num<Fr> {
        self.0
    }
}


impl<Fr:PrimeField, const L: usize> BorshSerialize for BoundedNum<Fr, L> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let n_limbs = (L - 1) / 8 + 1;
        let w = writer.write(&self.0.try_to_vec().unwrap()[0..n_limbs])?;
        if w!=n_limbs {
            Err(io::Error::new(io::ErrorKind::Other, "Writer is broken"))
        } else {
            Ok(())
        }
    }
}

impl<Fr:PrimeField, const L: usize> BorshDeserialize for BoundedNum<Fr, L> {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        let n_limbs = (L - 1) / 8 + 1;
        let n_limbs_total = Fr::Inner::NUM_WORDS*Fr::Inner::WORD_BITS/8;
        let mut b = vec![0;n_limbs_total];
        b[0..n_limbs].copy_from_slice(&buf[0..n_limbs]);
        *buf = &buf[n_limbs..];
        let n = Num::<Fr>::try_from_slice(&b)?;
        Ok(Self(n))
    }
}

impl<Fr:PrimeField, const L: usize> Serialize for BoundedNum<Fr, L> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Serialize::serialize(&self.0, serializer)
    }
}

impl<'de, Fr:PrimeField, const L: usize> Deserialize<'de> for BoundedNum<Fr, L> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n: NumRepr<Fr::Inner> = Deserialize::deserialize(deserializer)?;
        if n >= (NumRepr::ONE << L as u32) {
            Err(de::Error::custom("Overflow"))
        } else {
            Ok(Self::new(Num::from_uint_unchecked(n)))
        }

    }
}


impl<Fr:PrimeField, const L: usize> fawkes_crypto::rand::distributions::Distribution<BoundedNum<Fr, L>>
    for fawkes_crypto::rand::distributions::Standard
{
    #[inline]
    fn sample<R: fawkes_crypto::rand::Rng + ?Sized>(&self, rng: &mut R) -> BoundedNum<Fr, L> {
        let mut t : NumRepr<Fr::Inner> = rng.gen();
        t >>= (Fr::Inner::NUM_WORDS*Fr::Inner::WORD_BITS) as u32 - L as u32;
        BoundedNum::new(Num::from_uint_unchecked(t))
    }
}
