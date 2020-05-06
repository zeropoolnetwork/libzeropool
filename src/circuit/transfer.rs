use typenum::Unsigned;

use fawkes_crypto::core::{signal::Signal, cs::ConstraintSystem, field::PrimeField, sizedvec::SizedVec};
use fawkes_crypto::circuit::{
    num::CNum, bool::CBool,
    poseidon::{c_poseidon_with_salt, c_poseidon_merkle_proof_root, c_poseidon_merkle_tree_root, CMerkleProof},
    eddsaposeidon::{c_eddsaposeidon_verify},
    ecc::CEdwardsPoint,
    bitify::{c_comp_constant, c_into_bits_le, c_into_bits_le_strict, c_from_bits_le}
};
use fawkes_crypto::native::{num::Num, ecc::JubJubParams};



use crate::native::transfer::{PoolParams, Note, TxPub, TxSec};
use crate::constants::{SEED_DIVERSIFIER, SEED_DECRYPTION_KEY, SEED_IN_NOTE_HASH, SEED_OUT_NOTE_HASH, SEED_TX_HASH, SEED_NULLIFIER, SEED_NOTE_HASH};

#[derive(Clone, Signal)]
#[Value="Note<CS::F>"]
pub struct CNote<'a, CS:ConstraintSystem> {
    pub d: CNum<'a, CS>,
    pub pk_d: CNum<'a, CS>,
    pub v: CNum<'a, CS>,
    pub id: CNum<'a, CS>,
    pub st: CNum<'a, CS>
}


#[derive(Clone, Signal)]
#[Value="TxPub<P>"]
pub struct CTxPub<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>> {
    pub root: CNum<'a, CS>,
    pub nullifier: SizedVec<CNum<'a, CS>, P::IN>,
    pub out_note_hash_root: CNum<'a, CS>,
    pub out_hash: SizedVec<CNum<'a, CS>, P::OUT>,
    pub delta: CNum<'a, CS>,
    pub memo: CNum<'a, CS>
}




#[derive(Clone, Signal)]
#[Value="TxSec<P>"]
pub struct CTxSec<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>> {
    pub in_note: SizedVec<CNote<'a, CS>, P::IN>,
    pub out_note: SizedVec<CNote<'a, CS>, P::OUT>,
    pub in_proof: SizedVec<CMerkleProof<'a, CS, P::H>, P::IN>,
    pub dk: CNum<'a, CS>,
    pub eddsa_s: CNum<'a, CS>,
    pub eddsa_r: CNum<'a, CS>,
    pub eddsa_a: CNum<'a, CS>
} 


pub fn c_nullfifier<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(
    note_hash:&CNum<'a, CS>,
    dk:&CNum<'a, CS>,
    params:&P,
) -> CNum<'a, CS>{
    c_poseidon_with_salt([note_hash.clone(), dk.clone()].as_ref(), SEED_NULLIFIER, params.compress())
}

pub fn c_note_hash<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(
    note: &CNote<'a, CS>,
    params: &P
) -> CNum<'a, CS> {
    c_poseidon_with_salt([note.d.clone(), note.pk_d.clone(), note.v.clone(), note.id.clone(), note.st.clone()].as_ref(), SEED_NOTE_HASH, params.note())
}

pub fn c_tx_hash<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(
    in_note_hash: &[CNum<'a, CS>],
    out_note_hash: &[CNum<'a, CS>],
    params:&P
) -> CNum<'a, CS> {
    let in_h = c_poseidon_with_salt(in_note_hash, SEED_IN_NOTE_HASH, params.tx_in());
    let out_h = c_poseidon_with_salt(out_note_hash, SEED_OUT_NOTE_HASH, params.tx_out());
    c_poseidon_with_salt([in_h, out_h].as_ref(), SEED_TX_HASH, params.compress())
}

pub fn c_parse_delta<'a, CS:ConstraintSystem>(
    delta:&CNum<'a, CS>
) -> (CNum<'a, CS>, CNum<'a, CS> , CNum<'a, CS>) {
    let delta_bits = c_into_bits_le(delta, 162);
    let token_amount_bits = &delta_bits[0..65];
    let token_id_bits = &delta_bits[65..97];
    let native_amount_bits = &delta_bits[97..162];

    let token_amount = c_from_bits_le(token_amount_bits) - &token_amount_bits[64].0*num!("36893488147419103232");
    let token_id = c_from_bits_le(token_id_bits);
    let native_amount = c_from_bits_le(native_amount_bits) - &native_amount_bits[64].0*num!("36893488147419103232");

    (&token_amount+num!("18446744073709551616")).assert_nonzero();
    (&native_amount+num!("18446744073709551616")).assert_nonzero();

    (token_amount, token_id, native_amount)
}


pub fn c_tx<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(
    p: &CTxPub<'a, CS, P>,
    s: &CTxSec<'a, CS, P>,
    params: &P)
{
    let cs = p.get_cs();

    //check note value ranges
    for n in s.in_note.iter().chain(s.out_note.iter()) {
        c_into_bits_le(&n.d, 80);
        c_into_bits_le(&n.v, 64);
        c_into_bits_le(&n.id, 32);
        c_into_bits_le(&n.st, 80);
    }

    //build input hashes
    let in_hash = s.in_note.iter().map(|n| c_note_hash(n, params)).collect::<Vec<_>>();

    //check decryption key
    let dk_bits = c_into_bits_le(&s.dk, <P::J as JubJubParams>::Fs::NUM_BITS as usize);
    c_comp_constant(&dk_bits, Num::<<P::J as JubJubParams>::Fs>::from(-1).into_other()).assert_false();

    //build input ownership
    for i in 0..P::IN::USIZE {
        let d_hash = c_poseidon_with_salt(&[s.in_note[i].d.clone()], SEED_DIVERSIFIER, params.hash());
        let g_d = CEdwardsPoint::from_scalar(&d_hash, params.jubjub());
        (&s.in_note[i].pk_d - g_d.mul(&dk_bits, params.jubjub()).x).assert_zero();
    }

    //check nullifier
    for i in 0..P::IN::USIZE {
        (&p.nullifier[i]-c_nullfifier(&in_hash[i], &s.dk, params)).assert_zero();
    }

    //check nullifier unique
    let mut nullifier_unique_acc = CNum::from_const(cs, &Num::one());
    for i in 0..P::IN::USIZE {
        for j in i+1..P::IN::USIZE {
            nullifier_unique_acc *= &p.nullifier[i]-&p.nullifier[j];
        }
    }
    nullifier_unique_acc.assert_nonzero();

    //build output hashes
    for i in 0..P::OUT::USIZE {
        (&p.out_hash[i] - c_note_hash(&s.out_note[i], params)).assert_zero();
    }

    //build merkle proofs
    for i in 0..P::IN::USIZE {
        let cur_root = c_poseidon_merkle_proof_root(&in_hash[i], &s.in_proof[i], params.compress());
        ((cur_root-&p.root)*&s.in_note[i].v).assert_zero();
    }

    //bind msg_hash to the circuit
    (&p.memo+Num::one()).assert_nonzero();

    //build out hash root
    (&p.out_note_hash_root-c_poseidon_merkle_tree_root(&p.out_hash.0, params.compress())).assert_zero();

    //build tx hash
    let tx_hash = c_tx_hash(&in_hash, &p.out_hash.0, params);

    //check signature
    (c_eddsaposeidon_verify(&s.eddsa_s, &s.eddsa_r, &s.eddsa_a, &tx_hash, params.eddsa(), params.jubjub()).0 - Num::one()).assert_zero();

    //check decryption key

    let g = CEdwardsPoint::from_const(cs, params.jubjub().edwards_g());
    let t_dk = c_poseidon_with_salt(&[s.eddsa_a.clone()].as_ref(), SEED_DECRYPTION_KEY, params.hash());
    let t_dk_bits = c_into_bits_le_strict(&t_dk);
    (g.mul(&t_dk_bits, params.jubjub()).x - g.mul(&dk_bits, params.jubjub()).x).assert_zero();

    //parse delta    
    let (token_amount, token_id, native_amount) = c_parse_delta(&p.delta);

    let token_note = CNote{d:CNum::zero(cs), pk_d:CNum::zero(cs), v:token_amount, id:token_id, st:CNum::zero(cs)};
    let native_note = CNote{d:CNum::zero(cs), pk_d:CNum::zero(cs), v:native_amount, id:CNum::zero(cs), st:CNum::zero(cs)};


    //check balances
    let in_note_ex = [&s.in_note.0, [token_note, native_note].as_ref()].concat();

    for id in in_note_ex.iter().chain(s.out_note.iter()).map(|n| &n.id) {
        let mut amount = CNum::zero(cs);
        for n in in_note_ex.iter() {
            amount += &n.v * (&n.id - id).is_zero().0;
        }
        for n in s.out_note.iter() {
            amount -= &n.v * (&n.id - id).is_zero().0;
        }
        amount.assert_zero();
    }
}


