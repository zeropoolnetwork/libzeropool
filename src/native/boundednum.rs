
use crate::fawkes_crypto::ff_uint::{PrimeField, Num, NumRepr};


#[derive(Clone, Debug)]
pub struct BoundedNum<Fr:PrimeField, const L: usize>(pub(crate)Num<Fr>);

impl<Fr:PrimeField, const L: usize> Copy for BoundedNum<Fr, L> {}

impl<Fr:PrimeField, const L: usize> Eq for BoundedNum<Fr, L> {}

impl<Fr:PrimeField, const L: usize> PartialEq for BoundedNum<Fr, L> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}


impl<Fr:PrimeField, const L: usize> BoundedNum<Fr, L> {
    pub const ONE: Self = BoundedNum(Num::<Fr>::ONE);
    pub const ZERO: Self = BoundedNum(Num::<Fr>::ZERO);

    pub fn new(n:Num<Fr>) -> Self {
        assert!(L < Fr::MODULUS_BITS as usize && n.to_uint() < (NumRepr::<Fr::Inner>::ONE << L as u32));
        Self::new_unchecked(n)
    }

    pub fn new_trimmed(n:Num<Fr>) -> Self {
        assert!((L as u32) < Fr::MODULUS_BITS);
        let t = Num::from_uint_unchecked(n.to_uint() & ((NumRepr::<Fr::Inner>::ONE << L as u32) - NumRepr::<Fr::Inner>::ONE));
        Self::new_unchecked(t)
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
