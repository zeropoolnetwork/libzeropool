use fawkes_crypto::{circuit::{
    bitify::c_from_bits_le,
    bool::CBool,
    num::CNum,
    poseidon::{c_poseidon_merkle_proof_root, CMerkleProof},
    cs::{RCS, CS}
}, native::poseidon::poseidon};
use fawkes_crypto::core::signal::Signal;
use fawkes_crypto::ff_uint::Num;
use crate::native::tree::{TreePub, TreeSec};
use crate::native::params::PoolParams;
use crate::constants::{HEIGHT, OUTLOG};




#[derive(Clone, Signal)]
#[Value = "TreePub<C::Fr>"]
pub struct CTreePub<C:CS> {
    pub root_before: CNum<C>,
    pub root_after: CNum<C>,
    pub leaf: CNum<C>
}

#[derive(Clone, Signal)]
#[Value = "TreeSec<C::Fr>"]
pub struct CTreeSec<C:CS> {
    pub proof_filled:CMerkleProof<C, {HEIGHT - OUTLOG}>,
    pub proof_free:CMerkleProof<C, {HEIGHT - OUTLOG}>,
    pub prev_leaf:CNum<C>
}

pub fn tree_update<C:CS, P:PoolParams<Fr=C::Fr>>(
    p: &CTreePub<C>,
    s: &CTreeSec<C>,
    params: &P,
) {
    let index_filled = c_from_bits_le(s.proof_filled.path.as_slice());
    let index_free = c_from_bits_le(s.proof_free.path.as_slice());

    let mut zero_leaf_value = Num::ZERO;
    for _ in 0..OUTLOG {
        zero_leaf_value = poseidon(&[zero_leaf_value, zero_leaf_value], params.compress());
    }

    let zero_leaf:CNum<C> = p.derive_const(&zero_leaf_value);

    (c_poseidon_merkle_proof_root(&zero_leaf, &s.proof_free, params.compress()) - &p.root_before).assert_zero();
    (c_poseidon_merkle_proof_root(&p.leaf, &s.proof_free, params.compress()) - &p.root_after).assert_zero();

    let index_free_zero = (&index_free-zero_leaf_value).is_zero();

    let prev_proof_expr = (c_poseidon_merkle_proof_root(&s.prev_leaf, &s.proof_filled, params.compress()) - &p.root_before).is_zero();
    let prev_index_expr = (index_filled+Num::ONE-&index_free).is_zero();
    let prev_leaf_expr = !s.prev_leaf.is_zero();
    
    //for non-empty tree previous proof should be valid for nonzero leaf
    ((prev_proof_expr & prev_index_expr & prev_leaf_expr) | index_free_zero).assert_const(&true);


}