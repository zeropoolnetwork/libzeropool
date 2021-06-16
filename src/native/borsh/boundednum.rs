use crate::native::boundednum::*;
use crate::fawkes_crypto::{
    ff_uint::{Uint, PrimeField, Num, NumRepr},
    borsh::{BorshDeserialize, BorshSerialize},
    serde::{Serialize, Deserialize, Serializer, Deserializer, de},
};
use std::io::{Write, self};



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
