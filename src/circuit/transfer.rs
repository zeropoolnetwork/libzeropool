

use fawkes_crypto::core::signal::Signal;
use fawkes_crypto::core::num::Num;
use fawkes_crypto::core::cs::ConstraintSystem;
use fawkes_crypto::circuit::poseidon::poseidon;
use fawkes_crypto::native::poseidon::PoseidonParams;

use ff::{PrimeField, PrimeFieldRepr};


pub struct UTXO<'a, CS:ConstraintSystem> {
    pub d: Signal<'a, CS>,
    pub owner: Signal<'a, CS>,
    pub asset_id: Signal<'a, CS>,
    pub asset_amount: Signal<'a, CS>,
    pub salt: Signal<'a, CS>
}

pub trait PoolParams<Fr:PrimeField> {
    const N_INPUTS: usize;
    const N_OUTPUTS: usize;
    fn poseidon3(&self) -> &PoseidonParams<Fr>;
    fn poseidon6(&self) -> &PoseidonParams<Fr>;
    fn poseidon_tx_in(&self) -> &PoseidonParams<Fr>;
    fn poseidon_tx_out(&self) -> &PoseidonParams<Fr>;
    
}




pub fn nullfifier<'a, CS:ConstraintSystem, P:PoolParams<CS::F>>(
    note_hash:&Signal<'a, CS>,
    dk:&Signal<'a, CS>,
    params:&P,
) -> Signal<'a, CS>{
    poseidon([note_hash.clone(), dk.clone(), note_hash.derive_const(Num::from_seed(b"nullifier"))].as_ref(), params.poseidon3())
}

pub fn utxo_hash<'a, CS:ConstraintSystem, P:PoolParams<CS::F>>(
    utxo: &UTXO<'a, CS>,
    params: &P
) -> Signal<'a, CS> {
    let c = utxo.d.derive_const(Num::from_seed(b"utxo"));
    let t = [utxo.d.clone(), utxo.owner.clone(), utxo.asset_id.clone(), utxo.asset_amount.clone(), utxo.salt.clone(), c];
    poseidon(t.as_ref(), params.poseidon6())
}

pub fn tx_hash<'a, CS:ConstraintSystem, P:PoolParams<CS::F>>(
    in_utxo_hashes: &[Signal<'a, CS>],
    out_utxo_hashes: &[Signal<'a, CS>],
    params:&P
) -> Signal<'a, CS> {
    let cs = in_utxo_hashes[0].cs;
    let mut in_utxo_hashes = in_utxo_hashes.to_vec();
    in_utxo_hashes.push(Signal::from_const(cs, Num::from_seed(b"in_hash")));

    let mut out_utxo_hashes = out_utxo_hashes.to_vec();
    out_utxo_hashes.push(Signal::from_const(cs, Num::from_seed(b"out_hash")));

    let in_h = poseidon(&in_utxo_hashes, params.poseidon_tx_in());
    let out_h = poseidon(&out_utxo_hashes, params.poseidon_tx_out());

    poseidon([in_h, out_h, Signal::from_const(cs, Num::from_seed(b"tx_hash"))].as_ref(), params.poseidon3())
}
