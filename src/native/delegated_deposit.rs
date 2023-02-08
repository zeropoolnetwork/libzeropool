use fawkes_crypto::ff_uint::{Num, PrimeField};
use crate::native::{boundednum::BoundedNum, note::Note};
use std::fmt::Debug;
use crate::fawkes_crypto::core::sizedvec::SizedVec;
use crate::constants::{DIVERSIFIER_SIZE_BITS, BALANCE_SIZE_BITS, DELEGATED_DEPOSITS_NUM, HEIGHT, OUTPLUSONELOG};
use fawkes_crypto::native::poseidon::MerkleProof;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct DelegatedDeposit<Fr:PrimeField> {
    pub d: BoundedNum<Fr, { DIVERSIFIER_SIZE_BITS }>,
    pub p_d: Num<Fr>,
    pub b: BoundedNum<Fr, { BALANCE_SIZE_BITS }>
}

impl<Fr:PrimeField> DelegatedDeposit<Fr> {
    //convert to a note with zero salt
    pub fn to_note(&self) -> Note<Fr> {
        Note {
            d: self.d,
            p_d: self.p_d,
            b: self.b,
            t: BoundedNum::ZERO
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct DelegatedDepositBatchPub<Fr:PrimeField> {
    pub keccak_sum: Num<Fr>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct DelegatedDepositBatchSec<Fr:PrimeField> {
    pub root_before: Num<Fr>,
    pub root_after: Num<Fr>,
    pub proof_filled:MerkleProof<Fr, {HEIGHT - OUTPLUSONELOG}>,
    pub proof_free:MerkleProof<Fr, {HEIGHT - OUTPLUSONELOG}>,
    pub prev_leaf:Num<Fr>,
    pub deposits: SizedVec<DelegatedDeposit<Fr>, DELEGATED_DEPOSITS_NUM>
}
