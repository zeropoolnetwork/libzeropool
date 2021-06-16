use crate::fawkes_crypto::circuit::{
    bool::CBool,
    num::CNum,
    poseidon::c_poseidon
};
use crate::fawkes_crypto::core::signal::Signal;
use crate::fawkes_crypto::circuit::cs::{RCS, CS};
use crate::circuit::boundednum::CBoundedNum;
use crate::native::{note::Note, params::PoolParams};
use crate::constants;

#[derive(Clone, Signal)]
#[Value = "Note<C::Fr>"]
pub struct CNote<C:CS> {
    pub d: CBoundedNum<C, { constants::DIVERSIFIER_SIZE }>,
    pub p_d: CNum<C>,
    pub b: CBoundedNum<C, { constants::BALANCE_SIZE }>,
    pub t: CBoundedNum<C, { constants::SALT_SIZE }>,
}


impl<C:CS> CNote<C> {
    pub fn hash<P: PoolParams<Fr = C::Fr>>(
        &self,
        params: &P,
    ) -> CNum<C> {
        let inputs = [self.d.as_num().clone(), self.p_d.clone(), self.b.as_num().clone(), self.t.as_num().clone()];
        c_poseidon(&inputs, params.note())
    }

    // returns zero if note is dummy or nonzero otherwise
    pub fn is_dummy_raw(&self) -> CNum<C> {
        self.b.as_num().clone()
    }

    pub fn is_zero(&self) -> CBool<C> {
        (self.d.as_num() + &self.p_d + self.b.as_num() + self.t.as_num()).is_zero()
    }
}