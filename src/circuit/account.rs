use crate::fawkes_crypto::{
    circuit::{
        bool::CBool,
        num::CNum,
    },
    core::{
        signal::Signal, sizedvec::SizedVec,
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
    pub interval: SizedVec<CBoundedNum<P::Fr, constants::H>, constants::INTN>,
    pub v: CBoundedNum<P::Fr, constants::V>,
    pub st: CBoundedNum<P::Fr, constants::ST>,
}