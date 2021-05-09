use crate::fawkes_crypto::{
    circuit::{
        bool::CBool,
        num::CNum,
        cs::CS,
    },
    core::{
        signal::Signal,
    },
    circuit::cs::RCS
};

use crate::circuit::boundednum::CBoundedNum;
use crate::native::{account::Account};
use crate::constants;

#[derive(Clone, Signal)]
#[Value = "Account<C::Fr>"]
pub struct CAccount<C:CS> {
    pub xsk: CNum<C>,
    pub interval: CBoundedNum<C, { constants::H }>,
    pub v: CBoundedNum<C, { constants::V }>,
    pub e: CBoundedNum<C, { constants::E }>,
    pub st: CBoundedNum<C, { constants::ST }>,
}
