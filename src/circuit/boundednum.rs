use crate::fawkes_crypto::circuit::{
    bitify::{c_into_bits_le, c_into_bits_le_strict, c_from_bits_le},
    bool::CBool,
    num::CNum,
};
use crate::fawkes_crypto::core::{
    signal::Signal, 
};

use crate::fawkes_crypto::ff_uint::{NumRepr, PrimeFieldParams};
use crate::fawkes_crypto::circuit::cs::{RCS, CS};
use crate::native::boundednum::BoundedNum;

#[derive(Clone)]
pub struct CBoundedNum<C:CS, const L: usize>(CNum<C>);

impl<C:CS, const L: usize> CBoundedNum<C, L> {
    pub fn new_unchecked(n:&CNum<C>) -> Self {
        Self(n.clone())
    }

    pub fn new_trimmed(n:CNum<C>) -> Self {
        match n.as_const() {
            Some(cn) => n.derive_const(&BoundedNum::new_trimmed(cn)),
            _ => {
                assert!((L as u32) < C::Fr::MODULUS_BITS);
                let bits = c_into_bits_le_strict(&n);
                let new_n = c_from_bits_le(&bits[0..L]);
                Self::new_unchecked(&new_n)
            }
        }
    }

    pub fn new(n:&CNum<C>) -> Self {
        assert!(L < C::Fr::MODULUS_BITS as usize);
        match n.as_const() {
            Some(cn) => {
                assert!(cn.to_uint() < (NumRepr::<<C::Fr as PrimeFieldParams>::Inner>::ONE << L as u32));
                Self::new_unchecked(n)
            },
            _ => {
                c_into_bits_le(n, L);
                Self::new_unchecked(n)
            }
        }
    }
    pub fn as_num(&self) -> &CNum<C> {
        &self.0
    }
}

impl<C:CS, const L: usize> Signal<C> for CBoundedNum<C, L> {
    type Value = BoundedNum<C::Fr,L>;

    fn as_const(&self) -> Option<Self::Value> {
        let n = self.0.as_const()?;
        Some(BoundedNum::new(n))
    }

    fn get_value(&self) -> Option<Self::Value> {
        let n = self.0.get_value()?;
        Some(BoundedNum::new(n))
    }


    fn from_const(cs: &RCS<C>, value: &Self::Value) -> Self {
        let n = Signal::from_const(cs, value.as_num());
        Self::new(&n)
    }

    fn get_cs(&self) -> &RCS<C> {
        self.0.get_cs()
    }

    fn alloc(cs: &RCS<C>, value: Option<&Self::Value>) -> Self {
        let n = Signal::alloc(cs, value.map(|v| v.as_num()));
        Self::new(&n)
        
    }

    fn switch(&self, bit: &CBool<C>, if_else: &Self) -> Self {
        let n = self.0.switch(bit, &if_else.0);
        Self::new_unchecked(&n)
    }

    fn assert_const(&self, value: &Self::Value) {
        self.0.assert_const(value.as_num());
    }

    fn assert_eq(&self, other: &Self) {
        self.0.assert_eq(&other.0);
    }

    fn is_eq(&self, other: &Self) -> CBool<C> {
        self.0.is_eq(&other.0)
    }

    fn inputize(&self) {
        self.0.inputize();
    }
}
