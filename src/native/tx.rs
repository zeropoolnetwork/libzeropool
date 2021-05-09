use crate::{
    fawkes_crypto::{
        native::{
            ecc::{EdwardsPoint, JubJubParams},
            eddsaposeidon::{eddsaposeidon_sign, eddsaposeidon_verify},
            poseidon::{poseidon, MerkleProof},
        },
        core::sizedvec::SizedVec,
        ff_uint::{Num, NumRepr, PrimeField},
        borsh::{self, BorshSerialize, BorshDeserialize},
    },
    native::{
        params::PoolParams,
        note::Note,
        account::Account
    },
    constants
};


use std::fmt::Debug;



#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct Tx<Fr:PrimeField> {
    pub input: (Account<Fr>, SizedVec<Note<Fr>, { constants::IN }>),
    pub output: (Account<Fr>, Note<Fr>)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct TransferPub<Fr:PrimeField> {
    pub root: Num<Fr>,
    pub nullifier: Num<Fr>,
    pub out_commit: Num<Fr>,
    pub delta: Num<Fr>,
    pub memo: Num<Fr>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct TransferSec<Fr:PrimeField> {
    pub tx: Tx<Fr>,
    pub in_proof: (MerkleProof<Fr, { constants::H }>, SizedVec<MerkleProof<Fr, { constants::H }>, { constants::IN }>),
    pub eddsa_s: Num<Fr>,
    pub eddsa_r: Num<Fr>,
    pub eddsa_a: Num<Fr>,
}


pub fn nullfifier<P:PoolParams>(account_hash: Num<P::Fr>, xsk: Num<P::Fr>, params: &P) -> Num<P::Fr> {
    poseidon(&[account_hash, xsk], params.compress())
}

pub fn note_hash<P:PoolParams>(note: Note<P::Fr>, params: &P) -> Num<P::Fr> {
    poseidon(
        &[note.d.to_num(), note.pk_d, note.v.to_num(), note.st.to_num()],
        params.note(),
    )
}

pub fn accout_hash<P:PoolParams>(ac: Account<P::Fr>, params: &P) -> Num<P::Fr> {
    let inputs = vec![ac.xsk, ac.interval.to_num(), ac.v.to_num(), ac.st.to_num()];
    poseidon(
        &inputs,
        params.note(),
    )
}


pub fn tx_hash<P:PoolParams>(
    in_hash: &[Num<P::Fr>],
    out_hash: &[Num<P::Fr>],
    params: &P,
) -> Num<P::Fr> {
    let notes = in_hash
        .iter()
        .chain(out_hash.iter())
        .cloned()
        .collect::<Vec<_>>();
    poseidon(&notes, params.tx())
}

pub fn tx_sign<P:PoolParams>(
    sk: Num<P::Fs>,
    tx_hash: Num<P::Fr>,
    params: &P,
) -> (Num<P::Fs>, Num<P::Fr>) {
    eddsaposeidon_sign(sk, tx_hash, params.eddsa(), params.jubjub())
}

pub fn tx_verify<P:PoolParams>(
    s: Num<P::Fs>,
    r: Num<P::Fr>,
    xsk: Num<P::Fr>,
    tx_hash: Num<P::Fr>,
    params: &P,
) -> bool {
    eddsaposeidon_verify(s, r, xsk, tx_hash, params.eddsa(), params.jubjub())
}

pub fn derive_key_xsk<P:PoolParams>(
    sk: Num<P::Fs>,
    params: &P,
) -> EdwardsPoint<P::Fr> {
    params.jubjub().edwards_g().mul(sk, params.jubjub())
}

// receiver decryption key
pub fn derive_key_dk<P:PoolParams>(xsk: Num<P::Fr>, params: &P) -> Num<P::Fs> {
    let t_dk = poseidon(&[xsk], params.hash());
    t_dk.to_other_reduced::<P::Fs>().to_other().unwrap()
}

// sender decryption key 
pub fn derive_key_sdk<P:PoolParams>(xsk: Num<P::Fr>, params: &P) -> Num<P::Fs> {
    let t_dk = poseidon(&[xsk, Num::ZERO], params.compress());
    t_dk.to_other_reduced::<P::Fs>().to_other().unwrap()
}

// account decryption key
pub fn derive_key_adk<P:PoolParams>(xsk: Num<P::Fr>, params: &P) -> Num<P::Fs> {
    let t_dk = poseidon(&[xsk, Num::ONE], params.compress());
    t_dk.to_other_reduced::<P::Fs>().to_other().unwrap()
}

pub fn derive_key_pk_d<P:PoolParams>(
    d: Num<P::Fr>,
    dk: Num<P::Fs>,
    params: &P,
) -> EdwardsPoint<P::Fr> {
    let d_hash = poseidon(&[d], params.hash());
    EdwardsPoint::from_scalar(d_hash, params.jubjub()).mul(dk, params.jubjub())
}

pub fn parse_delta<Fr:PrimeField>(delta: Num<Fr>) -> (Num<Fr>, Num<Fr>, Num<Fr>) {
    let mut delta_num = delta.to_uint();

    let v_limit = NumRepr::ONE << constants::V as u32;
    let v_num = delta_num & (v_limit - NumRepr::ONE);
    let v = if v_num < v_limit >> 1 {
        Num::from_uint(v_num).unwrap()
    } else {
        Num::from_uint(v_num).unwrap() - Num::from_uint(v_limit).unwrap()
    };

    delta_num >>= constants::V as u32;

    let e_limit = NumRepr::ONE << constants::E as u32;
    let e_num = delta_num & (e_limit - NumRepr::ONE);
    let e = if e_num < e_limit >> 1 {
        Num::from_uint(e_num).unwrap()
    } else {
        Num::from_uint(e_num).unwrap() - Num::from_uint(e_limit).unwrap()
    };

    delta_num >>= constants::E as u32;

    let h_limit = NumRepr::ONE << constants::H as u32;

    assert!(delta_num < h_limit, "wrong delta amount");

    let index = Num::from_uint(delta_num).unwrap();

    (v, e, index)
}


pub fn make_delta<Fr:PrimeField>(v:Num<Fr>, e:Num<Fr>, index:Num<Fr>) -> Num<Fr> {
    let v_limit = NumRepr::ONE << constants::V as u32;
    let e_limit = NumRepr::ONE << constants::E as u32;
    
    let v_num = v.to_uint();
    let e_num = e.to_uint();

    assert!(v_num < v_limit>>1 || Num::<Fr>::MODULUS - v_num <= v_limit>>1, "v out of range");
    assert!(e_num < e_limit>>1 || Num::<Fr>::MODULUS - e_num <= e_limit>>1, "v out of range");

    let mut res = index;

    res*=Num::from_uint(e_limit).unwrap();

    if e_num < e_limit >> 1 {
        res+=e;
    } else {
        res+=Num::from_uint(e_limit).unwrap()+e;
    }

    res*=Num::from_uint(v_limit).unwrap();

    if v_num < v_limit >> 1 {
        res+=v;
    } else {
        res+=Num::from_uint(v_limit).unwrap()+v;
    }

    res
}
