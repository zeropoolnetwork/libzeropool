use crate::fawkes_crypto::typenum::Unsigned;

use crate::fawkes_crypto::circuit::{
    bitify::{c_comp_constant, c_into_bits_le, c_into_bits_le_strict},
    bool::CBool,
    ecc::CEdwardsPoint,
    eddsaposeidon::c_eddsaposeidon_verify,
    num::CNum,
    poseidon::{c_poseidon_merkle_proof_root, c_poseidon, CMerkleProof},
};
use crate::fawkes_crypto::core::{
    signal::Signal, sizedvec::SizedVec,
};
use crate::fawkes_crypto::native::{ecc::JubJubParams};
use crate::fawkes_crypto::ff_uint::{Num, NumRepr, PrimeField, PrimeFieldParams};
use crate::fawkes_crypto::circuit::cs::RCS;
use crate::circuit::boundednum::CBoundedNum;


use crate::native::{
    tx::{TransferPub, TransferSec, Tx},
    params::PoolParams,
    note::Note
};

use crate::constants;

#[derive(Clone, Signal)]
#[Field = "P::Fr"]
#[Value = "Note<P>"]
pub struct CNote<P:PoolParams> {
    pub d: CBoundedNum<P::Fr, constants::D>,
    pub pk_d: CNum<P::Fr>,
    pub v: CBoundedNum<P::Fr, constants::V>,
    pub st: CBoundedNum<P::Fr, constants::ST>,
}

#[derive(Clone, Signal)]
#[Value = "TransferPub<P>"]
#[Field = "P::Fr"]
pub struct CTransferPub<P: PoolParams> {
    pub root: CNum<P::Fr>,
    pub nullifier: SizedVec<CNum<P::Fr>, constants::IN>,
    pub out_hash: SizedVec<CNum<P::Fr>, constants::OUT>,
    pub delta: CNum<P::Fr>,
    pub memo: CNum<P::Fr>,
}

#[derive(Clone, Signal)]
#[Value = "Tx<P>"]
#[Field = "P::Fr"]
pub struct CTx<P: PoolParams> {
    pub input: SizedVec<CNote<P>, constants::IN>,
    pub output: SizedVec<CNote<P>, constants::OUT>,
}

#[derive(Clone, Signal)]
#[Value = "TransferSec<P>"]
#[Field = "P::Fr"]
pub struct CTransferSec<P:PoolParams> {
    pub tx: CTx<P>,
    pub in_proof: SizedVec<CMerkleProof<P::Fr, constants::H>, constants::IN>,
    pub eddsa_s: CNum<P::Fr>,
    pub eddsa_r: CNum<P::Fr>,
    pub eddsa_a: CNum<P::Fr>,
}

pub fn c_nullfifier<Fr:PrimeField, P: PoolParams<Fr = Fr>>(
    note_hash: &CNum<Fr>,
    xsk: &CNum<Fr>,
    params: &P,
) -> CNum<Fr> {
    c_poseidon(
        [note_hash.clone(), xsk.clone()].as_ref(),
        params.compress(),
    )
}

pub fn c_note_hash<P: PoolParams>(
    note: &CNote<P>,
    params: &P,
) -> CNum<P::Fr> {
    c_poseidon(
        [
            note.d.as_num().clone(),
            note.pk_d.clone(),
            note.v.as_num().clone(),
            note.st.as_num().clone(),
        ]
        .as_ref(),
        params.note(),
    )
}

pub fn c_tx_hash<Fr:PrimeField, P: PoolParams<Fr = Fr>>(
    in_note_hash: &[CNum<Fr>],
    out_note_hash: &[CNum<Fr>],
    params: &P,
) -> CNum<Fr> {
    let notes = in_note_hash
        .iter()
        .chain(out_note_hash.iter())
        .cloned()
        .collect::<Vec<_>>();
    c_poseidon(&notes, params.tx())
}

pub fn c_tx_verify<Fr:PrimeField, P: PoolParams<Fr = Fr>>(
    s: &CNum<Fr>,
    r: &CNum<Fr>,
    xsk: &CNum<Fr>,
    tx_hash: &CNum<Fr>,
    params: &P,
) -> CBool<Fr> {
    c_eddsaposeidon_verify(s, r, xsk, tx_hash, params.eddsa(), params.jubjub())
}

pub fn c_derive_key_dk<Fr:PrimeField, P: PoolParams<Fr = Fr>>(
    xsk: &CNum<Fr>,
    params: &P,
) -> Vec<CBool<Fr>> {
    let cs = xsk.get_cs();
    let t_dk = c_poseidon(&[xsk.clone()], params.hash());
    let dk_value = t_dk
        .get_value()
        .map(|v| v.to_other_reduced::<P::Fs>().to_other().unwrap());
    let dk = CNum::alloc(cs, dk_value.as_ref());

    let g = CEdwardsPoint::from_const(cs, params.jubjub().edwards_g());

    let t_dk_bits = c_into_bits_le_strict(&t_dk);
    let dk_bits = c_into_bits_le(&dk, P::Fs::MODULUS_BITS as usize);
    c_comp_constant(
        &dk_bits,
        Num::<P::Fs>::from(-1).to_other().unwrap(),
    )
    .assert_const(&false);
    (g.mul(&t_dk_bits, params.jubjub()).x - g.mul(&dk_bits, params.jubjub()).x).assert_zero();

    dk_bits
}

pub fn c_derive_key_pk_d<Fr:PrimeField, P: PoolParams<Fr = Fr>>(
    d: &CNum<Fr>,
    dk: &[CBool<Fr>],
    params: &P,
) -> CNum<Fr> {
    let d_hash = c_poseidon(&[d.clone()], params.hash());
    CEdwardsPoint::from_scalar(&d_hash, params.jubjub())
        .mul(dk, params.jubjub())
        .x
}

pub fn c_parse_delta<P:PoolParams>(delta: &CNum<P::Fr>) -> CNum<P::Fr> {
    let delta_bits = c_into_bits_le(delta, 64);
    delta - &delta_bits[63].to_num() * Num::from_uint(NumRepr::ONE << constants::V::U32).unwrap()
}

pub fn c_transfer<P:PoolParams>(
    p: &CTransferPub<P>,
    s: &CTransferSec<P>,
    params: &P,
) {
    let cs = p.get_cs();

    //check note value ranges
    for n in s.tx.input.iter().chain(s.tx.output.iter()) {
        c_into_bits_le(n.d.as_num(), constants::D::USIZE);
        c_into_bits_le(n.v.as_num(), constants::V::USIZE);
        c_into_bits_le(n.st.as_num(), constants::ST::USIZE);
    }

    //build input hashes
    let in_hash =
        s.tx.input
            .iter()
            .map(|n| c_note_hash(n, params))
            .collect::<Vec<_>>();

    //check decryption key
    let dk_bits = c_derive_key_dk(&s.eddsa_a, params);

    //build input ownership
    for i in 0..constants::IN::USIZE {
        (&s.tx.input[i].pk_d - c_derive_key_pk_d(&s.tx.input[i].d.as_num(), &dk_bits, params)).assert_zero();
    }

    //check nullifier
    for i in 0..constants::IN::USIZE {
        (&p.nullifier[i] - c_nullfifier(&in_hash[i], &s.eddsa_a, params)).assert_zero();
    }

    //check nullifier unique
    let mut nullifier_unique_acc = CNum::from_const(cs, &Num::ONE);
    for i in 0..constants::IN::USIZE {
        for j in i + 1..constants::IN::USIZE {
            nullifier_unique_acc *= &p.nullifier[i] - &p.nullifier[j];
        }
    }
    nullifier_unique_acc.assert_nonzero();

    //check output unique
    let mut output_unique_acc = CNum::from_const(cs, &Num::ONE);
    for i in 0..constants::OUT::USIZE {
        for j in i + 1..constants::OUT::USIZE {
            output_unique_acc *= &p.out_hash[i] - &p.out_hash[j];
        }
    }
    output_unique_acc.assert_nonzero();

    //build output hashes
    for i in 0..constants::OUT::USIZE {
        (&p.out_hash[i] - c_note_hash(&s.tx.output[i], params)).assert_zero();
    }

    //build merkle proofs
    for i in 0..constants::IN::USIZE {
        let cur_root = c_poseidon_merkle_proof_root(&in_hash[i], &s.in_proof[i], params.compress());
        ((cur_root - &p.root) * s.tx.input[i].v.as_num()).assert_zero();
    }

    //bind msg_hash to the circuit
    (&p.memo + Num::ONE).assert_nonzero();

    //build tx hash
    let tx_hash = c_tx_hash(&in_hash, p.out_hash.as_slice(), params);

    //check signature
    c_tx_verify(&s.eddsa_s, &s.eddsa_r, &s.eddsa_a, &tx_hash, params).assert_const(&true);

    //parse delta
    let delta_amount = c_parse_delta::<P>(&p.delta);

    //check balances
    let mut amount = delta_amount;

    for note in s.tx.input.iter() {
        amount += note.v.as_num();
    }

    for note in s.tx.output.iter() {
        amount -= note.v.as_num();
    }

    amount.assert_zero();
}

