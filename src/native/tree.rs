use crate::{
    fawkes_crypto::{
        native::poseidon::MerkleProof,
        ff_uint::{Num, PrimeField},
        borsh::{self, BorshSerialize, BorshDeserialize},
    },
    constants::{HEIGHT, OUTLOG}
};


use std::fmt::Debug;


#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TreePub<Fr:PrimeField> {
    pub root_before: Num<Fr>,
    pub root_after: Num<Fr>,
    pub leaf: Num<Fr>
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TreeSec<Fr:PrimeField> {
    pub proof_filled:MerkleProof<Fr, {HEIGHT - OUTLOG}>,
    pub proof_free:MerkleProof<Fr, {HEIGHT - OUTLOG}>,
    pub prev_leaf:Num<Fr>
}