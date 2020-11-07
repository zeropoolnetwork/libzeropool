use crate::{
    fawkes_crypto::{
        native::{
            ecc::{EdwardsPoint, JubJubParams},
            eddsaposeidon::{eddsaposeidon_sign, eddsaposeidon_verify},
            poseidon::{poseidon, MerkleProof},
        },
        core::sizedvec::SizedVec,
        ff_uint::{Num, PrimeField, NumRepr, PrimeFieldParams},
        borsh::{BorshSerialize, BorshDeserialize},
        typenum::Unsigned
    },
    native::{
        params::PoolParams,
        note::Note
    },
    constants
};


use std::fmt::Debug;
use sha3::{Digest, Keccak256};


#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct Tx<P: PoolParams> {
    pub input: SizedVec<Note<P>, constants::IN>,
    pub output: SizedVec<Note<P>, constants::OUT>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct TransferPub<P: PoolParams> {
    pub root: Num<P::Fr>,
    pub nullifier: SizedVec<Num<P::Fr>, constants::IN>,
    pub out_hash: SizedVec<Num<P::Fr>, constants::OUT>,
    pub delta: Num<P::Fr>,
    pub memo: Num<P::Fr>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct TransferSec<P: PoolParams> {
    pub tx: Tx<P>,
    pub in_proof: SizedVec<MerkleProof<P::Fr, constants::H>, constants::IN>,
    pub eddsa_s: Num<P::Fr>,
    pub eddsa_r: Num<P::Fr>,
    pub eddsa_a: Num<P::Fr>,
}

fn xor_crypt<D: Digest + Clone>(prefix: &D, data: &[u8]) -> Vec<u8> {
    let mut mask = vec![];

    for i in 0..(data.len() - 1) / 32 + 1 {
        let mut m = prefix.clone();
        m.update([i as u8]);
        mask.extend(m.finalize());
    }
    data.iter().zip(mask.iter()).map(|(&d, &m)| d ^ m).collect()
}

fn dh_prefix<Fr: PrimeField>(dh_x: Num<Fr>, h: &[u8]) -> Keccak256 {
    let mut res = Keccak256::new();
    res.update(dh_x.try_to_vec().unwrap());
    res.update(h);
    res
}

pub fn note_encrypt<P: PoolParams>(
    esk: Num<P::Fs>,
    dk: Num<P::Fs>,
    note: Note<P>,
    params: &P,
) -> Vec<u8> {
    let pk_d = EdwardsPoint::subgroup_decompress(note.pk_d, params.jubjub()).unwrap();
    let dh = pk_d.mul(esk, params.jubjub());

    let note_vec = note.try_to_vec().unwrap();

    let mut hasher = Keccak256::new();
    hasher.update(&note_vec);
    let note_hash = hasher.finalize();

    let note_vec_enc = xor_crypt(&dh_prefix(dh.x, &note_hash), &note_vec);

    let epk = derive_key_pk_d(note.d.to_num(), esk, params);
    let epk2 = dh.mul(dk.checked_inv().unwrap(), params.jubjub());

    let mut res = vec![];

    res.extend(epk.x.try_to_vec().unwrap());
    res.extend(epk2.x.try_to_vec().unwrap());
    res.extend(note_hash);
    res.extend(note_vec_enc);
    res
}

fn note_decrypt<P: PoolParams>(
    dk: Num<P::Fs>,
    epk: Num<P::Fr>,
    note_data: &[u8],
    params: &P,
) -> Option<Note<P>> {
    let epk = EdwardsPoint::subgroup_decompress(epk, params.jubjub())?;
    let dh = epk.mul(dk, params.jubjub());

    let prefix = dh_prefix(dh.x, &note_data[..32]);
    let note_vec = xor_crypt(&prefix, &note_data[32..]);

    let mut hasher = Keccak256::new();
    hasher.update(&note_vec);
    let note_hash = hasher.finalize();

    if note_data[..32]
        .iter()
        .zip(note_hash.iter())
        .any(|(a, b)| a != b)
    {
        None
    } else {
        Note::try_from_slice(&note_vec).ok()
    }
}

pub fn note_decrypt_in<P: PoolParams>(
    dk: Num<P::Fs>,
    msg_data: &[u8],
    params: &P,
) -> Option<Note<P>> {
    let num_size = (P::Fr::MODULUS_BITS as usize - 1) / 8 + 1;
    let note_size = (constants::D::USIZE-1)/8 + (constants::V::USIZE-1)/8 + (constants::ST::USIZE-1)/8+3 + num_size;
    if msg_data.len() != 32 + 2 * num_size + note_size {
        None
    } else {
        let epk = Num::try_from_slice(&msg_data[0..num_size]).ok()?;
        note_decrypt(dk, epk, &msg_data[2 * num_size..], params)
    }
}

pub fn note_decrypt_out<P: PoolParams>(
    dk: Num<P::Fs>,
    msg_data: &[u8],
    params: &P,
) -> Option<Note<P>> {
    let num_size = (P::Fr::MODULUS_BITS as usize - 1) / 8 + 1;
    let note_size = (constants::D::USIZE-1)/8 + (constants::V::USIZE-1)/8 + (constants::ST::USIZE-1)/8+3 + num_size;
    if msg_data.len() != 32 + 2 * num_size + note_size {
        None
    } else {
        let epk = Num::try_from_slice(&msg_data[num_size..num_size * 2]).ok()?;
        note_decrypt(dk, epk, &msg_data[2 * num_size..], params)
    }
}

pub fn nullfifier<P: PoolParams>(note_hash: Num<P::Fr>, xsk: Num<P::Fr>, params: &P) -> Num<P::Fr> {
    poseidon(&[note_hash, xsk], params.compress())
}

pub fn note_hash<P: PoolParams>(note: Note<P>, params: &P) -> Num<P::Fr> {
    poseidon(
        &[note.d.to_num(), note.pk_d, note.v.to_num(), note.st.to_num()],
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

pub fn derive_key_dk<P: PoolParams>(xsk: Num<P::Fr>, params: &P) -> Num<P::Fs> {
    let t_dk = poseidon(&[xsk], params.hash());
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

