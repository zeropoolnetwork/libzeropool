use crate::{constants::{BALANCE_SIZE_BITS, ENERGY_SIZE_BITS, HEIGHT, IN, OUT, POOLID_SIZE_BITS}, fawkes_crypto::{
        native::{
            eddsaposeidon::{eddsaposeidon_sign, eddsaposeidon_verify},
            poseidon::{poseidon, poseidon_merkle_tree_root, poseidon_sponge, MerkleProof},
        },
        core::sizedvec::SizedVec,
        ff_uint::{Num, NumRepr, PrimeField, Uint},
        borsh::{self, BorshSerialize, BorshDeserialize},
    }, native::{
        params::PoolParams,
        note::Note,
        account::Account
    }};


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




pub fn parse_delta<Fr:PrimeField>(delta: Num<Fr>) -> (Num<Fr>, Num<Fr>, Num<Fr>, Num<Fr>) {
    fn _parse_uint<U:Uint>(n:&mut NumRepr<U>, len:usize) -> NumRepr<U> {
        let t = *n;
        *n = *n >> len as u32;
        t - (*n << len as u32)
    }

    fn parse_uint<Fr:PrimeField>(n:&mut NumRepr<Fr::Inner>, len:usize) -> Num<Fr> {
        Num::from_uint(_parse_uint(n, len)).unwrap()
    }

    fn parse_int<Fr:PrimeField>(n:&mut NumRepr<Fr::Inner>, len:usize) -> Num<Fr> {
        let two_component_term =  -Num::from_uint(NumRepr::ONE << len as u32).unwrap();
        let r = _parse_uint(n, len);
        if r >> (len as u32 - 1) == NumRepr::ZERO {
            Num::from_uint(r).unwrap()
        } else {
            Num::from_uint(r).unwrap() + two_component_term
        }
    }

    let mut delta_num = delta.to_uint();

    (
        parse_int(&mut delta_num, BALANCE_SIZE_BITS),
        parse_int(&mut delta_num, ENERGY_SIZE_BITS),
        parse_uint(&mut delta_num, HEIGHT),
        parse_uint(&mut delta_num, POOLID_SIZE_BITS),

    )
}


pub fn make_delta<Fr:PrimeField>(v:Num<Fr>, e:Num<Fr>, index:Num<Fr>, poolid:Num<Fr>) -> Num<Fr> {
    fn make_uint<Fr:PrimeField>(s: &mut NumRepr<Fr::Inner>, n:Num<Fr>, len:usize) {
        let r = n.to_uint();
        assert!(r >> len as u32 == NumRepr::ZERO, "out of range");
        *s = (*s << len as u32) + r;
    }

    fn make_int<Fr:PrimeField>(s: &mut NumRepr<Fr::Inner>, n:Num<Fr>, len:usize) {
        let mut r = n.to_uint();
        if r >> (len as u32 - 1) == NumRepr::ZERO {
            *s = (*s << len as u32) + r;
            return;
        }
        r = Num::<Fr>::MODULUS - r;
        if (r - NumRepr::ONE) >> (len as u32 - 1) == NumRepr::ZERO {
            r = (NumRepr::ONE << len as u32) - r;
            *s = (*s << len as u32) + r;
            return;
        }
        
        panic!("out of range");
    }

    let mut s = NumRepr::ZERO;
    make_uint(&mut s, poolid, POOLID_SIZE_BITS);
    make_uint(&mut s, index, HEIGHT);
    make_int(&mut s, e, ENERGY_SIZE_BITS);
    make_int(&mut s, v, BALANCE_SIZE_BITS);

    Num::from_uint(s).unwrap()
}
