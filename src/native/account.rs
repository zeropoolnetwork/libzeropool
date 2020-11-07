use crate::{
    fawkes_crypto::{
        ff_uint::Num
    },
    native::{
        boundednum::BoundedNum,
        params::PoolParams
    },
    constants
};


use std::fmt::Debug;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct Account<P:PoolParams> {
    pub dk: Num<P::Fr>,
    pub interval: BoundedNum<P::Fr, constants::INTA>,
    pub v: BoundedNum<P::Fr, constants::V>,
    pub st: BoundedNum<P::Fr, constants::ST>,
}