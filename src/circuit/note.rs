use crate::fawkes_crypto::circuit::{
    bool::CBool,
    num::CNum
};
use crate::fawkes_crypto::core::{
    signal::Signal, 
};
use crate::fawkes_crypto::circuit::cs::{RCS, SetupCS};
use crate::circuit::{
    boundednum::CBoundedNum
};


use crate::native::{
    params::PoolParams,
    note::Note
};

use crate::constants;

#[derive(Clone, Signal)]
#[Field = "SetupCS<P::Fr>"]
#[Value = "Note<P>"]
pub struct CNote<P:PoolParams> {
    pub d: CBoundedNum<P::Fr, { constants::D }>,
    pub pk_d: CNum<SetupCS<P::Fr>>,
    pub v: CBoundedNum<P::Fr, { constants::V }>,
    pub st: CBoundedNum<P::Fr, { constants::ST }>,
}
