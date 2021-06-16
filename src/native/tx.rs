use crate::{
    fawkes_crypto::{
        native::{
            eddsaposeidon::{eddsaposeidon_sign, eddsaposeidon_verify},
            poseidon::{poseidon, poseidon_merkle_tree_root, poseidon_sponge, MerkleProof},
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
    constants::{IN, OUT, BALANCE_SIZE, ENERGY_SIZE, HEIGHT}
};


use std::fmt::Debug;



#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct Tx<Fr:PrimeField> {
    pub input: (Account<Fr>, SizedVec<Note<Fr>, { IN }>),
    pub output: (Account<Fr>, SizedVec<Note<Fr>, { OUT }>)
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
    pub in_proof: (MerkleProof<Fr, { HEIGHT }>, SizedVec<MerkleProof<Fr, { HEIGHT }>, { IN }>),
    pub eddsa_s: Num<Fr>,
    pub eddsa_r: Num<Fr>,
    pub eddsa_a: Num<Fr>,
}


pub fn nullifier<P:PoolParams>(account_hash: Num<P::Fr>, eta: Num<P::Fr>, params: &P) -> Num<P::Fr> {
    poseidon(&[account_hash, eta], params.compress())
}

pub fn note_hash<P:PoolParams>(note: Note<P::Fr>, params: &P) -> Num<P::Fr> {
    poseidon(
        &[note.d.to_num(), note.p_d, note.b.to_num(), note.t.to_num()],
        params.note(),
    )
}

pub fn accout_hash<P:PoolParams>(ac: Account<P::Fr>, params: &P) -> Num<P::Fr> {
    let inputs = vec![ac.eta, ac.i.to_num(), ac.b.to_num(), ac.t.to_num()];
    poseidon(
        &inputs,
        params.note(),
    )
}


pub fn tx_hash<P:PoolParams>(
    in_hash: &[Num<P::Fr>],
    out_commitment: Num<P::Fr>,
    params: &P,
) -> Num<P::Fr> {
    let data = in_hash.iter().chain(core::iter::once(&out_commitment)).cloned().collect::<Vec<_>>();
    poseidon_sponge(&data, params.sponge())
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


pub fn out_commitment_hash<P:PoolParams>(items:&[Num<P::Fr>], params: &P) -> Num<P::Fr> {
    assert!(items.len()==OUT+1);
    poseidon_merkle_tree_root(items, params.compress())
}




pub fn parse_delta<Fr:PrimeField>(delta: Num<Fr>) -> (Num<Fr>, Num<Fr>, Num<Fr>) {
    let mut delta_num = delta.to_uint();

    let v_limit = NumRepr::ONE << BALANCE_SIZE as u32;
    let v_num = delta_num & (v_limit - NumRepr::ONE);
    let v = if v_num < v_limit >> 1 {
        Num::from_uint(v_num).unwrap()
    } else {
        Num::from_uint(v_num).unwrap() - Num::from_uint(v_limit).unwrap()
    };

    delta_num >>= BALANCE_SIZE as u32;

    let e_limit = NumRepr::ONE << ENERGY_SIZE as u32;
    let e_num = delta_num & (e_limit - NumRepr::ONE);
    let e = if e_num < e_limit >> 1 {
        Num::from_uint(e_num).unwrap()
    } else {
        Num::from_uint(e_num).unwrap() - Num::from_uint(e_limit).unwrap()
    };

    delta_num >>= ENERGY_SIZE as u32;

    let h_limit = NumRepr::ONE << HEIGHT as u32;

    assert!(delta_num < h_limit, "wrong delta amount");

    let index = Num::from_uint(delta_num).unwrap();

    (v, e, index)
}


pub fn make_delta<Fr:PrimeField>(v:Num<Fr>, e:Num<Fr>, index:Num<Fr>) -> Num<Fr> {
    let v_limit = NumRepr::ONE << BALANCE_SIZE as u32;
    let e_limit = NumRepr::ONE << ENERGY_SIZE as u32;
    
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
