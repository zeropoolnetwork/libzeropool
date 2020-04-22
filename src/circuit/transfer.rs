use ff::{PrimeField};

use fawkes_crypto::core::signal::{Signal, AbstractSignal};
use fawkes_crypto::core::num::Num;
use fawkes_crypto::core::cs::ConstraintSystem;
use fawkes_crypto::circuit::poseidon::{c_poseidon, c_poseidon_merkle_proof_root, c_poseidon_merkle_tree_root, CMerkleProof};
use fawkes_crypto::circuit::eddsaposeidon::{c_eddsaposeidon_verify};
use fawkes_crypto::circuit::ecc::{CEdwardsPoint};
use fawkes_crypto::circuit::bitify::{c_comp_constant, c_into_bits_le};
use fawkes_crypto::native::ecc::{EdwardsPoint, JubJubParams};

use crate::native::transfer::{PoolParams, Note};

#[derive(Clone)]
pub struct CNote<'a, CS:ConstraintSystem> {
    pub d: Signal<'a, CS>,
    pub pk_d: Signal<'a, CS>,
    pub v: Signal<'a, CS>,
    pub id: Signal<'a, CS>,
    pub st: Signal<'a, CS>
}

impl<'a, CS:ConstraintSystem> AbstractSignal<'a, CS> for CNote<'a, CS> {
    type Value = Note<CS::F>;

    fn get_cs(&self) -> &'a CS {self.d.get_cs()}

    fn from_const(cs:&'a CS, value: Self::Value) -> Self {
        CNote {
            d: Signal::from_const(cs, value.d),
            pk_d: Signal::from_const(cs, value.pk_d),
            v: Signal::from_const(cs, value.v),
            id: Signal::from_const(cs, value.id),
            st: Signal::from_const(cs, value.st)
        }
    }
    
    fn get_value(&self) -> Option<Self::Value> {
        Some(Self::Value {
            d: self.d.get_value()?,
            pk_d: self.pk_d.get_value()?,
            v: self.v.get_value()?,
            id: self.id.get_value()?,
            st: self.st.get_value()?
        })
    }

    fn alloc(cs:&'a CS, value:Option<Self::Value>) -> Self {
        CNote {
            d: Signal::alloc(cs, value.map(|v| v.d)),
            pk_d: Signal::alloc(cs, value.map(|v| v.pk_d)),
            v: Signal::alloc(cs, value.map(|v| v.v)),
            id: Signal::alloc(cs, value.map(|v| v.id)),
            st: Signal::alloc(cs, value.map(|v| v.st))
        }
    }
}


pub fn c_nullfifier<'a, CS:ConstraintSystem, P:PoolParams<CS::F>>(
    note_hash:&Signal<'a, CS>,
    dk:&Signal<'a, CS>,
    params:&P,
) -> Signal<'a, CS>{
    c_poseidon([note_hash.clone(), dk.clone(), note_hash.derive_const(Num::from_seed(b"nullifier"))].as_ref(), params.poseidon_compress())
}

pub fn c_note_hash<'a, CS:ConstraintSystem, P:PoolParams<CS::F>>(
    note: &CNote<'a, CS>,
    params: &P
) -> Signal<'a, CS> {
    let c = note.d.derive_const(Num::from_seed(b"note"));
    let t = [note.d.clone(), note.pk_d.clone(), note.v.clone(), note.id.clone(), note.st.clone(), c];
    c_poseidon(t.as_ref(), params.poseidon_note())
}

pub fn c_tx_hash<'a, CS:ConstraintSystem, P:PoolParams<CS::F>>(
    in_note_hash: &[Signal<'a, CS>],
    out_note_hash: &[Signal<'a, CS>],
    params:&P
) -> Signal<'a, CS> {
    let cs = in_note_hash[0].cs;
    let mut in_note_hash = in_note_hash.to_vec();
    in_note_hash.push(Signal::from_const(cs, Num::from_seed(b"in_note_hashes")));
    let mut out_note_hash = out_note_hash.to_vec();
    out_note_hash.push(Signal::from_const(cs, Num::from_seed(b"out_note_hashes")));
    let in_h = c_poseidon(&in_note_hash, params.poseidon_tx_in());
    let out_h = c_poseidon(&out_note_hash, params.poseidon_tx_out());
    c_poseidon([in_h, out_h, Signal::from_const(cs, Num::from_seed(b"tx_hash"))].as_ref(), params.poseidon_compress())
}




pub fn c_tx<'a, CS:ConstraintSystem, P:PoolParams<CS::F>>(
    root: &Signal<'a, CS>,
    nullifier: &[Signal<'a, CS>],
    out_note_hash_root: &Signal<'a, CS>,
    out_hash: &[Signal<'a, CS>],
    in_note:&[CNote<'a, CS>],
    out_note:&[CNote<'a, CS>],
    delta:&Signal<'a, CS>,
    msg_hash:&Signal<'a, CS>,
    in_proof:&[CMerkleProof<'a, CS>],
    dk:&Signal<'a, CS>,
    eddsa_s:&Signal<'a, CS>,
    eddsa_r:&Signal<'a, CS>,
    eddsa_a:&Signal<'a, CS>,
    params:&P)
{
    assert!(in_note.len()==P::N_INPUTS, "wrong number of inputs");
    assert!(nullifier.len()==P::N_INPUTS, "wrong number of nullifiers");
    assert!(in_proof.len()==P::N_INPUTS, "wrong number of merkle proofs");
    assert!(out_note.len()==P::N_OUTPUTS && out_hash.len()==P::N_OUTPUTS, "wrong number of outputs");

    let cs = root.get_cs();
    let diversifier_hash_salt = Signal::from_const(cs, Num::from_seed(b"diversifier_hash"));
    let decryption_key_hash_salt = Signal::from_const(cs, Num::from_seed(b"decryption_key_hash_salt"));

    for proof in in_proof {
        assert!(proof.sibling.len() == P::PROOF_LEN && proof.path.len() == P::PROOF_LEN, "wrong proof length");
    }

    //build input hashes
    let in_hash = in_note.iter().map(|n| c_note_hash(n, params)).collect::<Vec<_>>();

    //check decryption key
    let dk_bits = c_into_bits_le(dk, <P::J as JubJubParams<CS::F>>::Fs::NUM_BITS as usize);
    c_comp_constant(&dk_bits, Num::<<P::J as JubJubParams<CS::F>>::Fs>::from(-1).into_other()).assert_zero();

    //build input ownership
    for i in 0..P::N_INPUTS {
        let d_hash = c_poseidon(&[in_note[i].d.clone(), diversifier_hash_salt.clone()], params.poseidon_hash());
        let g_d = CEdwardsPoint::from_scalar(&d_hash, params.jubjub());
        (&in_note[i].pk_d - g_d.mul(&dk_bits, params.jubjub()).x).assert_zero();
    }

    //build output hashes
    for i in 0..P::N_OUTPUTS {
        (&out_hash[i] - c_note_hash(&out_note[i], params)).assert_zero();
    }

    //build merkle proofs
    for i in 0..P::N_INPUTS {
        let cur_root = c_poseidon_merkle_proof_root(&in_hash[i], &in_proof[i], params.poseidon_compress());
        ((cur_root-root)*&in_note[i].v).assert_zero();
    }

    //bind msg_hash to the circuit
    (msg_hash+Num::one()).assert_nonzero();

    //build out hash root
    (out_note_hash_root-c_poseidon_merkle_tree_root(out_hash, params.poseidon_compress())).assert_zero();

    //build tx hash
    let tx_hash = c_tx_hash(&in_hash, out_hash, params);

    //check signature
    (c_eddsaposeidon_verify(eddsa_s, eddsa_r, eddsa_a, &tx_hash, params.eddsa(), params.jubjub()) - Num::one()).assert_zero();

    //TODO: check decryption key


    //TODO: check unique nullifier

    //TODO: check balances
    


}