use crate::fawkes_crypto::circuit::{
    bitify::{c_into_bits_le, c_into_bits_le_strict, c_from_bits_le},
    bool::CBool,
    num::CNum,
};
use crate::fawkes_crypto::core::{
    signal::Signal, 
};

use crate::fawkes_crypto::ff_uint::{NumRepr, PrimeField};
use crate::fawkes_crypto::circuit::cs::RCS;
use crate::native::boundednum::BoundedNum;

#[derive(Clone)]
pub struct CBoundedNum<Fr:PrimeField, const L: usize>(CNum<Fr>);

impl<Fr:PrimeField, const L: usize> CBoundedNum<Fr, L> {
    pub fn new_unchecked(n:&CNum<Fr>) -> Self {
        Self(n.clone())
    }

    pub fn new_trimmed(n:CNum<Fr>) -> Self {
        match n.as_const() {
            Some(cn) => n.derive_const(&BoundedNum::new_trimmed(cn)),
            _ => {
                assert!(L::U32 < Fr::MODULUS_BITS);
                let bits = c_into_bits_le_strict(&n);
                let new_n = c_from_bits_le(&bits[0..L::USIZE]);
                Self::new_unchecked(&new_n)
            }
        }
    }

    pub fn new(n:&CNum<Fr>) -> Self {
        assert!(L < Fr::MODULUS_BITS as usize);
        match n.as_const() {
            Some(cn) => {
                assert!(cn.to_uint() < (NumRepr::<Fr::Inner>::ONE << L as u32));
                Self::new_unchecked(n)
            },
            _ => {
                c_into_bits_le(n, L);
                Self::new_unchecked(n)
            }
        }
    }
    pub fn as_num(&self) -> &CNum<Fr> {
        &self.0
    }
}

impl<Fr:PrimeField, const L: usize> Signal<Fr> for CBoundedNum<Fr, L> {
    type Value = BoundedNum<Fr,L>;

    fn as_const(&self) -> Option<Self::Value> {
        let n = self.0.as_const()?;
        Some(BoundedNum::new(n))
    }

    fn get_value(&self) -> Option<Self::Value> {
        let n = self.0.get_value()?;
        Some(BoundedNum::new(n))
    }


    fn from_const(cs: &RCS<Fr>, value: &Self::Value) -> Self {
        let n = Signal::from_const(cs, value.as_num());
        Self::new(&n)
    }

    fn get_cs(&self) -> &RCS<Fr> {
        self.0.get_cs()
    }

    fn alloc(cs: &RCS<Fr>, value: Option<&Self::Value>) -> Self {
        let n = Signal::alloc(cs, value.map(|v| v.as_num()));
        Self::new(&n)
        
    }

    fn switch(&self, bit: &CBool<Fr>, if_else: &Self) -> Self {
        let n = self.0.switch(bit, &if_else.0);
        Self::new_unchecked(&n)
    }

    fn assert_const(&self, value: &Self::Value) {
        self.0.assert_const(value.as_num());
    }

    fn assert_eq(&self, other: &Self) {
        self.0.assert_eq(&other.0);
    }

    fn is_eq(&self, other: &Self) -> CBool<Fr> {
        self.0.is_eq(&other.0)
    }

    fn inputize(&self) {
        self.0.inputize();
    }
}
