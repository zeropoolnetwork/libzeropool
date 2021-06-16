#[macro_use]
pub extern crate fawkes_crypto;


pub mod constants;
pub mod native;
pub mod circuit;

use crate::native::params::PoolBN256;



use fawkes_crypto::engines::bn256::{JubJubBN256, Fr};
use fawkes_crypto::native::poseidon::PoseidonParams;

use lazy_static::lazy_static;

fn gen_poseidon_params(n:usize) -> PoseidonParams<Fr> {
    let t = n+1;
    let r_p =  f64::ceil(53.75 + 1.075*f64::log(t as f64, 5.0)) as usize;
    PoseidonParams::<Fr>::new(t, 8, r_p)
}


//TODO recalculate
lazy_static! {
    pub static ref POOL_PARAMS: PoolBN256 = PoolBN256 {
        jubjub: JubJubBN256::new(),
        hash: gen_poseidon_params(1),
        compress: gen_poseidon_params(2),
        note: gen_poseidon_params(4),
        account: gen_poseidon_params(5),
        eddsa: gen_poseidon_params(3),
        sponge: gen_poseidon_params(5),
    };
}