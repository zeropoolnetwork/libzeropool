use fawkes_crypto::ff_uint::PrimeField;
use fawkes_crypto::native::{ecc::{EdwardsPoint, JubJubParams}, poseidon::{poseidon}};
use fawkes_crypto::ff_uint::Num;
use crate::native::params::PoolParams;


// intermediate key
pub fn derive_key_a<P:PoolParams>(
    sigma: Num<P::Fs>,
    params: &P,
) -> EdwardsPoint<P::Fr> {
    params.jubjub().edwards_g().mul(sigma, params.jubjub())
}

// intermediate key
pub fn derive_key_eta<P:PoolParams>(a: Num<P::Fr>, params: &P) -> Num<P::Fr> {
    poseidon(&[a], params.hash())
}


pub fn derive_key_p_d<P:PoolParams, Fr:PrimeField>(
    d: Num<P::Fr>,
    eta: Num<Fr>,
    params: &P,
) -> EdwardsPoint<P::Fr> {
    let eta_reduced = eta.to_other_reduced();
    let d_hash = poseidon(&[d], params.hash());
    EdwardsPoint::from_scalar(d_hash, params.jubjub()).mul(eta_reduced, params.jubjub())
}