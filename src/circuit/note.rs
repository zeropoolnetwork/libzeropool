use crate::fawkes_crypto::circuit::{
    bool::CBool,
    num::CNum
};
use crate::fawkes_crypto::core::{
    signal::Signal,
};
use crate::fawkes_crypto::circuit::cs::{RCS, CS};
use crate::circuit::{
    boundednum::CBoundedNum
};


use crate::native::{
    note::Note
};

use crate::constants;

#[derive(Clone, Signal)]
#[Value = "Note<C::Fr>"]
pub struct CNote<C:CS> {
    pub d: CBoundedNum<C, { constants::D }>,
    pub pk_d: CNum<C>,
    pub v: CBoundedNum<C, { constants::V }>,
    pub st: CBoundedNum<C, { constants::ST }>,
}
