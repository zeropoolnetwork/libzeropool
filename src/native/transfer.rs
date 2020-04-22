use fawkes_crypto::core::num::Num;
use fawkes_crypto::native::poseidon::PoseidonParams;
use fawkes_crypto::native::ecc::{EdwardsPoint, JubJubParams};
use ff::{PrimeField};



pub trait PoolParams<Fr:PrimeField> {
    type J: JubJubParams<Fr>;

    const N_INPUTS: usize;
    const N_OUTPUTS: usize;
    const PROOF_LEN: usize;
    fn jubjub(&self) -> &Self::J;
    fn poseidon_hash(&self) -> &PoseidonParams<Fr>;
    fn poseidon_compress(&self) -> &PoseidonParams<Fr>;
    fn poseidon_note(&self) -> &PoseidonParams<Fr>;
    fn poseidon_tx_in(&self) -> &PoseidonParams<Fr>;
    fn poseidon_tx_out(&self) -> &PoseidonParams<Fr>;
    fn eddsa(&self) -> &PoseidonParams<Fr>;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Note<F:PrimeField> {
    pub d: Num<F>,
    pub pk_d: Num<F>,
    pub v: Num<F>,
    pub id: Num<F>,
    pub st: Num<F>
}

