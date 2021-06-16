use crate::fawkes_crypto::circuit::{bool::CBool, num::CNum, cs::{CS, RCS}, poseidon::c_poseidon};
use crate::fawkes_crypto::core::signal::Signal;
use crate::circuit::boundednum::CBoundedNum;
use crate::native::{account::Account, params::PoolParams};
use crate::constants;

#[derive(Clone, Signal)]
#[Value = "Account<C::Fr>"]
pub struct CAccount<C:CS> {
    pub eta: CNum<C>,
    pub i: CBoundedNum<C, { constants::HEIGHT }>,
    pub b: CBoundedNum<C, { constants::BALANCE_SIZE }>,
    pub e: CBoundedNum<C, { constants::ENERGY_SIZE }>,
    pub t: CBoundedNum<C, { constants::SALT_SIZE }>,
}


impl<C:CS> CAccount<C> {
    pub fn hash<P: PoolParams<Fr = C::Fr>>(&self, params: &P) -> CNum<C> {
        let inputs = [self.eta.clone(), self.i.as_num().clone(), self.b.as_num().clone(), self.e.as_num().clone(), self.t.as_num().clone()];
        c_poseidon(&inputs, params.account())
    }

    // returns zero if Note is dummy or nonzero otherwise
    pub fn is_dummy_raw(&self) -> CNum<C> {
        self.i.as_num()+self.b.as_num()+self.e.as_num()+self.t.as_num()
    }
}