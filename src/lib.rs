#[macro_use]
pub extern crate fawkes_crypto;

use serde_json;

pub mod constants;
pub mod native;
pub mod circuit;
pub mod helpers;


use crate::native::params::PoolBN256;




use fawkes_crypto::engines::bn256::{JubJubBN256, Fr};
use fawkes_crypto::native::poseidon::PoseidonParams;

use lazy_static::lazy_static;


#[cfg(feature="cli_libzeropool_setup")]
pub use clap;


lazy_static! {
    pub static ref POOL_PARAMS: PoolBN256 = {
        let poseidon_params_t_2:PoseidonParams<Fr> = serde_json::from_str(include_str!("../res/poseidon_params_t_2.json")).unwrap();
        let poseidon_params_t_3:PoseidonParams<Fr> = serde_json::from_str(include_str!("../res/poseidon_params_t_3.json")).unwrap();
        let poseidon_params_t_4:PoseidonParams<Fr> = serde_json::from_str(include_str!("../res/poseidon_params_t_4.json")).unwrap();
        let poseidon_params_t_5:PoseidonParams<Fr> = serde_json::from_str(include_str!("../res/poseidon_params_t_5.json")).unwrap();
        let poseidon_params_t_6:PoseidonParams<Fr> = serde_json::from_str(include_str!("../res/poseidon_params_t_6.json")).unwrap();
        
        PoolBN256 {
            jubjub: JubJubBN256::new(),
            hash: poseidon_params_t_2.clone(),
            compress: poseidon_params_t_3,
            note: poseidon_params_t_5,
            account: poseidon_params_t_6.clone(),
            eddsa: poseidon_params_t_4.clone(),
            sponge: poseidon_params_t_6,
            nullifier_intermediate: poseidon_params_t_4
        }
    };
}