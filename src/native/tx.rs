use crate::{
    fawkes_crypto::{
        native::{
            ecc::{EdwardsPoint, JubJubParams},
            eddsaposeidon::{eddsaposeidon_sign, eddsaposeidon_verify},
            poseidon::{poseidon, MerkleProof},
        },
        core::sizedvec::SizedVec,
        ff_uint::{Num, NumRepr},
        borsh::{self, BorshSerialize, BorshDeserialize},
        typenum::Unsigned
    },
    native::{
        params::PoolParams,
        note::Note,
        account::Account
    },
    constants
};


use std::{collections::btree_set::Intersection, fmt::Debug};



#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct Tx<P: PoolParams> {
    pub input: (Account<P>, SizedVec<Note<P>, constants::IN>),
    pub output: (Account<P>, Note<P>)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct TransferPub<P: PoolParams> {
    pub root: Num<P::Fr>,
    pub nullifier: Num<P::Fr>,
    pub out_commit: Num<P::Fr>,
    pub delta: Num<P::Fr>,
    pub memo: Num<P::Fr>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct TransferSec<P: PoolParams> {
    pub tx: Tx<P>,
    pub in_proof: SizedVec<MerkleProof<P::Fr, constants::H>, constants::INPROOF>,
    pub eddsa_s: Num<P::Fr>,
    pub eddsa_r: Num<P::Fr>,
    pub eddsa_a: Num<P::Fr>,
}


pub fn nullfifier<P: PoolParams>(account_hash: Num<P::Fr>, xsk: Num<P::Fr>, params: &P) -> Num<P::Fr> {
    poseidon(&[account_hash, xsk], params.compress())
}

pub fn note_hash<P: PoolParams>(note: Note<P>, params: &P) -> Num<P::Fr> {
    poseidon(
        &[note.d.to_num(), note.pk_d, note.v.to_num(), note.st.to_num()],
        params.note(),
    )
}

pub fn accout_hash<P: PoolParams>(ac: Account<P>, params: &P) -> Num<P::Fr> {
    let mut inputs = vec![ac.xsk];
    inputs.extend(ac.interval.iter().map(|n| n.to_num()));
    inputs.extend(vec![ac.v.to_num(), ac.st.to_num()]);

    poseidon(
        &inputs,
        params.note(),
    )
}


pub fn tx_hash<P: PoolParams>(
    in_note_hash: &[Num<P::Fr>],
    out_note_hash: &[Num<P::Fr>],
    params: &P,
) -> Num<P::Fr> {
    let notes = in_note_hash
        .iter()
        .chain(out_note_hash.iter())
        .cloned()
        .collect::<Vec<_>>();
    poseidon(&notes, params.tx())
}

pub fn tx_sign<P: PoolParams>(
    sk: Num<P::Fs>,
    tx_hash: Num<P::Fr>,
    params: &P,
) -> (Num<P::Fs>, Num<P::Fr>) {
    eddsaposeidon_sign(sk, tx_hash, params.eddsa(), params.jubjub())
}

pub fn tx_verify<P: PoolParams>(
    s: Num<P::Fs>,
    r: Num<P::Fr>,
    xsk: Num<P::Fr>,
    tx_hash: Num<P::Fr>,
    params: &P,
) -> bool {
    eddsaposeidon_verify(s, r, xsk, tx_hash, params.eddsa(), params.jubjub())
}

pub fn derive_key_xsk<P: PoolParams>(
    sk: Num<P::Fs>,
    params: &P,
) -> EdwardsPoint<P::Fr> {
    params.jubjub().edwards_g().mul(sk, params.jubjub())
}

// receiver decryption key
pub fn derive_key_dk<P: PoolParams>(xsk: Num<P::Fr>, params: &P) -> Num<P::Fs> {
    let t_dk = poseidon(&[xsk], params.hash());
    t_dk.to_other_reduced::<P::Fs>().to_other().unwrap()
}

// sender decryption key 
pub fn derive_key_sdk<P: PoolParams>(xsk: Num<P::Fr>, params: &P) -> Num<P::Fs> {
    let t_dk = poseidon(&[xsk, Num::ZERO], params.compress());
    t_dk.to_other_reduced::<P::Fs>().to_other().unwrap()
}

// account decryption key
pub fn derive_key_adk<P: PoolParams>(xsk: Num<P::Fr>, params: &P) -> Num<P::Fs> {
    let t_dk = poseidon(&[xsk, Num::ONE], params.compress());
    t_dk.to_other_reduced::<P::Fs>().to_other().unwrap()
}

pub fn derive_key_pk_d<P: PoolParams>(
    d: Num<P::Fr>,
    dk: Num<P::Fs>,
    params: &P,
) -> EdwardsPoint<P::Fr> {
    let d_hash = poseidon(&[d], params.hash());
    EdwardsPoint::from_scalar(d_hash, params.jubjub()).mul(dk, params.jubjub())
}

pub fn parse_delta<P:PoolParams>(delta: Num<P::Fr>) -> Num<P::Fr> {
    let delta_num = delta.to_uint();
    let min_neg_amount = NumRepr::ONE << (constants::V::U32 * 8 - 1);
    let limit_amount = NumRepr::ONE << (constants::V::U32 * 8);
    assert!(delta_num < limit_amount);

    if delta_num < min_neg_amount {
        delta
    } else {
        delta - Num::from_uint(limit_amount).unwrap()
    }
}

