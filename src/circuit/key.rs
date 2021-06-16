use fawkes_crypto::circuit::bool::CBool;

use crate::fawkes_crypto::circuit::{
    ecc::CEdwardsPoint,
    num::CNum,
    poseidon::{c_poseidon},
    cs::CS
};
use crate::native::params::PoolParams;



// intermediate key
pub fn c_derive_key_eta<C:CS, P: PoolParams<Fr = C::Fr>>(a: &CNum<C>, params: &P) -> CNum<C> {
    c_poseidon(&[a.clone()], params.hash())
}


pub fn c_derive_key_p_d<C:CS, P: PoolParams<Fr = C::Fr>>(
    d: &CNum<C>,
    eta_bits: &[CBool<C>],
    params: &P,
) -> CEdwardsPoint<C> {
    let d_hash = c_poseidon(&[d.clone()], params.hash());
    CEdwardsPoint::from_scalar(&d_hash, params.jubjub()).mul(&eta_bits, params.jubjub())
}

