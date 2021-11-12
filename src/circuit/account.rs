use crate::fawkes_crypto::circuit::{bool::CBool, num::CNum, cs::{CS, RCS}, poseidon::c_poseidon};
use crate::fawkes_crypto::core::signal::Signal;
use crate::circuit::boundednum::CBoundedNum;
use crate::native::{account::Account, params::PoolParams};
use crate::constants;

#[derive(Clone, Signal)]
#[Value = "Account<C::Fr>"]
pub struct CAccount<C:CS> {
    pub d: CBoundedNum<C, { constants::DIVERSIFIER_SIZE_BITS }>,
    pub p_d: CNum<C>,
    pub i: CBoundedNum<C, { constants::HEIGHT }>,
    pub b: CBoundedNum<C, { constants::BALANCE_SIZE_BITS }>,
    pub e: CBoundedNum<C, { constants::ENERGY_SIZE_BITS }>,
}


impl<C:CS> CAccount<C> {
    pub fn hash<P: PoolParams<Fr = C::Fr>>(&self, params: &P) -> CNum<C> {
        let inputs = [self.d.as_num().clone(), self.p_d.clone(), self.i.as_num().clone(), self.b.as_num().clone(), self.e.as_num().clone()];
        c_poseidon(&inputs, params.account())
    }

    pub fn is_initial(&self, poolid:&CNum<C>) -> CBool<C> {
        (self.i.as_num()+self.b.as_num()+self.e.as_num()).is_zero() & self.d.as_num().is_eq(poolid)
    }
}