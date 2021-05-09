use crate::fawkes_crypto::circuit::{
    bitify::{c_comp_constant, c_into_bits_le, c_into_bits_le_strict, c_comp, c_from_bits_le},
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
use crate::fawkes_crypto::ff_uint::{Num, NumRepr, PrimeFieldParams};
use crate::fawkes_crypto::circuit::cs::{RCS, CS};
use crate::circuit::{
    account::CAccount,
    note::CNote
};


use crate::native::{
    tx::{TransferPub, TransferSec, Tx},
    params::PoolParams
};

use crate::constants;


#[derive(Clone, Signal)]
#[Value = "TransferPub<C::Fr>"]
pub struct CTransferPub<C:CS> {
    pub root: CNum<C>,
    pub nullifier: CNum<C>,
    pub out_commit: CNum<C>,
    pub delta: CNum<C>, // int64 token delta, int96 energy delta, uint32 blocknumber
    pub memo: CNum<C>,
}

#[derive(Clone, Signal)]
#[Value = "Tx<C::Fr>"]
pub struct CTx<C:CS> {
    pub input: (CAccount<C>, SizedVec<CNote<C>, { constants::IN }>),
    pub output: (CAccount<C>, CNote<C>)
}

#[derive(Clone, Signal)]
#[Value = "TransferSec<C::Fr>"]
pub struct CTransferSec<C:CS> {
    pub tx: CTx<C>,
    pub in_proof: (CMerkleProof<C, { constants::H }>, SizedVec<CMerkleProof<C, { constants::H }>, { constants::IN }>),
    pub eddsa_s: CNum<C>,
    pub eddsa_r: CNum<C>,
    pub eddsa_a: CNum<C>,
}

pub fn c_nullfifier<C:CS, P: PoolParams<Fr = C::Fr>>(
    account_hash: &CNum<C>,
    xsk: &CNum<C>,
    params: &P,
) -> CNum<C> {
    c_poseidon(
        [account_hash.clone(), xsk.clone()].as_ref(),
        params.compress(),
    )
}


pub fn c_note_hash<C:CS, P: PoolParams<Fr = C::Fr>>(
    note: &CNote<C>,
    params: &P,
) -> CNum<C> {
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

pub fn c_accout_hash<C:CS, P: PoolParams<Fr = C::Fr>>(ac: &CAccount<C>, params: &P) -> CNum<C> {
    let inputs = vec![ac.xsk.clone(), ac.interval.as_num().clone(), ac.v.as_num().clone(), ac.e.as_num().clone(), ac.st.as_num().clone()];
    c_poseidon(
        &inputs,
        params.account(),
    )
}


pub fn c_tx_hash<C:CS, P: PoolParams<Fr = C::Fr>>(
    in_hash: &[CNum<C>],
    out_hash: &[CNum<C>],
    params: &P,
) -> CNum<C> {
    let notes = in_hash
        .iter()
        .chain(out_hash.iter())
        .cloned()
        .collect::<Vec<_>>();
    c_poseidon(&notes, params.tx())
}

pub fn c_tx_verify<C:CS, P: PoolParams<Fr = C::Fr>>(
    s: &CNum<C>,
    r: &CNum<C>,
    xsk: &CNum<C>,
    tx_hash: &CNum<C>,
    params: &P,
) -> CBool<C> {
    c_eddsaposeidon_verify(s, r, xsk, tx_hash, params.eddsa(), params.jubjub())
}

pub fn c_derive_key_dk<C:CS, P: PoolParams<Fr = C::Fr>>(
    xsk: &CNum<C>,
    params: &P,
) -> Vec<CBool<C>> {
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

pub fn c_derive_key_pk_d<C:CS, P: PoolParams<Fr = C::Fr>>(
    d: &CNum<C>,
    dk: &[CBool<C>],
    params: &P,
) -> CNum<C> {
    let d_hash = c_poseidon(&[d.clone()], params.hash());
    CEdwardsPoint::from_scalar(&d_hash, params.jubjub())
        .mul(dk, params.jubjub())
        .x
}

pub fn c_parse_delta<C:CS, P:PoolParams<Fr=C::Fr>>(delta: &CNum<C>) -> (CNum<C>, CNum<C>, CNum<C>) {
    let cv = constants::V;
    let ce = constants::E;
    let ch = constants::H;
    let delta_bits = c_into_bits_le(delta, cv+ce+ch);

    let v = c_from_bits_le(&delta_bits[0..cv]) - &delta_bits[cv-1].to_num() * Num::from_uint(NumRepr::ONE << cv as u32).unwrap();
    let e = c_from_bits_le(&delta_bits[cv..cv+ce]) - &delta_bits[cv+ce-1].to_num() * Num::from_uint(NumRepr::ONE << ce as u32).unwrap();
    let index = c_from_bits_le(&delta_bits[cv+ce..cv+ce+ch]);

    (v, e, index)
}

pub fn c_transfer<C:CS, P:PoolParams<Fr=C::Fr>>(
    p: &CTransferPub<C>,
    s: &CTransferSec<C>,
    params: &P,
) {
    //parse delta
    let (delta_value, delta_energy, index) = c_parse_delta::<C,P>(&p.delta);
    let mut total_value = delta_value;
    let mut total_enegry = delta_energy;

    

    //build input hashes
    let account_hash = c_accout_hash(&s.tx.input.0, params);
    let note_hash = s.tx.input.1.iter().map(|n| c_note_hash(n, params)).collect::<Vec<_>>();

    let mut in_hash = vec![account_hash.clone()];
    in_hash.extend(note_hash.clone());


    //check decryption key
    let dk_bits = c_derive_key_dk(&s.eddsa_a, params);

    //build ownership
    (&s.tx.input.0.xsk - &s.eddsa_a).assert_zero();
    (&s.tx.output.0.xsk - &s.eddsa_a).assert_zero();

    for i in 0..constants::IN {
        (&s.tx.input.1[i].pk_d - c_derive_key_pk_d(&s.tx.input.1[i].d.as_num(), &dk_bits, params)).assert_zero();
    }

    //check nullifier
    (&p.nullifier - c_nullfifier(&account_hash, &s.eddsa_a, params)).assert_zero();



    //build output hashes
    let out_account_hash = c_accout_hash(&s.tx.output.0, params);
    let out_note_hash = c_note_hash(&s.tx.output.1, params);
    let out_commitment_hash = c_poseidon([out_account_hash.clone(), out_note_hash.clone()].as_ref(), params.compress());
    (&out_commitment_hash - &p.out_commit).assert_zero();


    //build merkle proofs
    {
        let cur_root = c_poseidon_merkle_proof_root(&account_hash, &s.in_proof.0, params.compress());
        //root is correct or value==0 && interval==0 && salt is zero 
        ((cur_root - &p.root) * (s.tx.input.0.v.as_num()+s.tx.input.0.st.as_num()+s.tx.input.0.interval.as_num())).assert_zero();

        //input.interval <= output.interval
        c_comp(s.tx.input.0.interval.as_num(), s.tx.output.0.interval.as_num(), constants::H).assert_const(&false);

        //output_interval <= index
        c_comp(s.tx.output.0.interval.as_num(), &index, constants::H).assert_const(&false);

        //compute enegry
        total_enegry += s.tx.input.0.v.as_num() * (s.tx.output.0.interval.as_num() - s.tx.input.0.interval.as_num());
    }

    //let account_index = c_from_bits_le(s.in_proof.0.path.as_slice());

    for i in 0..constants::IN {
        let note_value = s.tx.input.1[i].v.as_num();
        let ref note_index = c_from_bits_le(s.in_proof.1[i].path.as_slice());

        let cur_root = c_poseidon_merkle_proof_root(&note_hash[i], &s.in_proof.1[i], params.compress());
        ((cur_root - &p.root) * note_value).assert_zero();

        //note_index >= account_in.interval && note_index < account_out.interval || note_index == 0 && value == 0
        ((c_comp(s.tx.input.0.interval.as_num(), note_index, constants::H).as_num() + Num::ONE -
        c_comp(s.tx.output.0.interval.as_num(), note_index, constants::H).as_num()) *
        (note_index+note_value)).assert_const(&Num::ZERO);

        //compute enegry
        total_enegry += note_value * (s.tx.output.0.interval.as_num() - note_index);
    }

    //bind msg_hash to the circuit
    (&p.memo + Num::ONE).assert_nonzero();

    //build tx hash
    let tx_hash = c_tx_hash(&in_hash, [out_account_hash, out_note_hash].as_ref(), params);

    //check signature
    c_tx_verify(&s.eddsa_s, &s.eddsa_r, &s.eddsa_a, &tx_hash, params).assert_const(&true);

    //check balances
    total_value += s.tx.input.0.v.as_num() - s.tx.output.0.v.as_num() - s.tx.output.1.v.as_num();

    for note in s.tx.input.1.iter() {
        total_value += note.v.as_num();
    }
    total_value.assert_zero();

    //final check energy
    total_enegry += s.tx.input.0.e.as_num();
    total_enegry -= s.tx.output.0.e.as_num();
    total_enegry.assert_zero();

}

