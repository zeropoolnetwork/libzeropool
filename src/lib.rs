#[macro_use]
pub extern crate fawkes_crypto;


pub mod constants;
pub mod native;
pub mod circuit;

use crate::native::params::PoolBN256;



use fawkes_crypto::engines::bn256::{JubJubBN256, Fr};
use fawkes_crypto::native::poseidon::PoseidonParams;

use lazy_static::lazy_static;


lazy_static! {
    pub static ref POOL_PARAMS: PoolBN256 = PoolBN256 {
        jubjub: JubJubBN256::new(),
        hash: PoseidonParams::<Fr>::new(2, 8, 53),
        compress: PoseidonParams::<Fr>::new(3, 8, 53),
        note: PoseidonParams::<Fr>::new(5, 8, 54),
        tx: PoseidonParams::<Fr>::new(11, 8, 54),
        eddsa: PoseidonParams::<Fr>::new(4, 8, 53),
    };
}