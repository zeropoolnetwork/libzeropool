use crate::fawkes_crypto::{
    circuit::{
        bool::CBool,
        num::CNum,
    },
    core::{
        signal::Signal,
    },
    circuit::cs::RCS
};

use crate::circuit::boundednum::CBoundedNum;
use crate::native::{account::Account, params::PoolParams};
use crate::constants;

#[derive(Clone, Signal)]
#[Field = "P::Fr"]
#[Value = "Account<P>"]
pub struct CAccount<P:PoolParams> {
    pub xsk: CNum<P::Fr>,
    pub interval: CBoundedNum<P::Fr, constants::H>,
    pub v: CBoundedNum<P::Fr, constants::V>,
    pub e: CBoundedNum<P::Fr, constants::E>,
    pub st: CBoundedNum<P::Fr, constants::ST>,
}