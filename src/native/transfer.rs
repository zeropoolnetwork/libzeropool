use fawkes_crypto::native::num::Num;
use fawkes_crypto::native::poseidon::{PoseidonParams, poseidon, MerkleProof, poseidon_with_salt};
use fawkes_crypto::native::ecc::{JubJubParams};

use fawkes_crypto::core::sizedvec::SizedVec;

use fawkes_crypto::core::field::Field;
use num::bigint::{BigUint, BigInt, ToBigInt};
use typenum::Unsigned;
use std::fmt::Debug;
use std::marker::PhantomData;
use crate::constants::{SEED_DIVERSIFIER, SEED_DECRYPTION_KEY, SEED_IN_NOTE_HASH, SEED_OUT_NOTE_HASH, SEED_TX_HASH, SEED_NULLIFIER, SEED_NOTE_HASH};


pub trait PoolParams : Clone+Sized {
    type F: Field;
    type J: JubJubParams<Fr=Self::F>;
    type IN:Unsigned;
    type OUT:Unsigned;
    type H:Unsigned;

    fn jubjub(&self) -> &Self::J;
    fn hash(&self) -> &PoseidonParams<Self::F>;
    fn compress(&self) -> &PoseidonParams<Self::F>;
    fn note(&self) -> &PoseidonParams<Self::F>;
    fn tx_in(&self) -> &PoseidonParams<Self::F>;
    fn tx_out(&self) -> &PoseidonParams<Self::F>;
    fn eddsa(&self) -> &PoseidonParams<Self::F>;
}

#[derive(Clone)]
pub struct PoolBN256<F:Field, J:JubJubParams<Fr=F>, IN:Unsigned, OUT:Unsigned, H:Unsigned>{
    pub jubjub:J,
    pub hash: PoseidonParams<F>,
    pub compress: PoseidonParams<F>,
    pub note: PoseidonParams<F>,
    pub tx_in: PoseidonParams<F>,
    pub tx_out: PoseidonParams<F>,
    pub eddsa: PoseidonParams<F>,
    pub phantom: PhantomData<(IN, OUT, H)>
}

impl<F:Field, J:JubJubParams<Fr=F>, IN:Unsigned, OUT:Unsigned, H:Unsigned> PoolParams for PoolBN256<F,J,IN, OUT, H> {
    type F = F;
    type J = J;
    type IN = IN;
    type OUT = OUT;
    type H = H;

    fn jubjub(&self) -> &Self::J {
        &self.jubjub
    }

    fn hash(&self) -> &PoseidonParams<Self::F> {
        &self.hash
    }

    fn compress(&self) -> &PoseidonParams<Self::F> {
        &self.compress
    }

    fn note(&self) -> &PoseidonParams<Self::F> {
        &self.note
    }

    fn tx_in(&self) -> &PoseidonParams<Self::F> {
        &self.tx_in
    }

    fn tx_out(&self) -> &PoseidonParams<Self::F> {
        &self.tx_out
    }

    fn eddsa(&self) -> &PoseidonParams<Self::F> {
        &self.eddsa
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Note<F:Field> {
    pub d: Num<F>,
    pub pk_d: Num<F>,
    pub v: Num<F>,
    pub id: Num<F>,
    pub st: Num<F>
}


#[derive(Debug, Clone)]
pub struct TxPub<P:PoolParams> {
    pub root: Num<P::F>,
    pub nullifier: SizedVec<Num<P::F>, P::IN>,
    pub out_note_hash_root: Num<P::F>,
    pub out_hash: SizedVec<Num<P::F>, P::OUT>,
    pub delta: Num<P::F>,
    pub memo: Num<P::F>
}

#[derive(Debug, Clone)]
pub struct TxSec<P:PoolParams> {
    pub in_note: SizedVec<Note<P::F>, P::IN>,
    pub out_note: SizedVec<Note<P::F>, P::OUT>,
    pub in_proof: SizedVec<MerkleProof<P::F,P::H>, P::IN>,
    pub dk: Num<P::F>,
    pub eddsa_s: Num<P::F>,
    pub eddsa_r: Num<P::F>,
    pub eddsa_a: Num<P::F>
} 



pub fn nullfifier<P:PoolParams>(note_hash:Num<P::F>, dk:Num<P::F>, params:&P) -> Num<P::F>{
    poseidon_with_salt(&[note_hash, dk], SEED_NULLIFIER, params.compress())
}

pub fn note_hash<P:PoolParams>(note: Note<P::F>, params: &P) -> Num<P::F> {
    poseidon_with_salt(&[note.d, note.pk_d, note.v, note.id, note.st], SEED_NOTE_HASH, params.note())
}

pub fn tx_hash<P:PoolParams>(in_note_hash: &[Num<P::F>], out_note_hash: &[Num<P::F>], params:&P) -> Num<P::F> {
    let in_h = poseidon_with_salt(&in_note_hash, SEED_IN_NOTE_HASH, params.tx_in());
    let out_h = poseidon_with_salt(&out_note_hash, SEED_OUT_NOTE_HASH, params.tx_out());
    poseidon_with_salt(&[in_h, out_h], SEED_TX_HASH, params.compress())
}

pub fn parse_delta<F:Field>(delta:Num<F>) -> (Num<F>, Num<F>, Num<F>) {
    let delta_repr = delta.into_inner().into_repr();
    let delta_ref = delta_repr.as_ref();

    let token_amount_neg = (delta_ref[1] & 1u64) == 1u64;
    let native_amount_neg = (delta_ref[2] & 0x400000000u64) == 0x400000000u64;

    let mut token_amount = num!(delta_ref[0]);
    let token_id = num!((delta_ref[1]>>1) & 0xffffffffu64);
    let mut native_amount = num!((delta_ref[1]>>33) + ((delta_ref[2] & 0x3ffffffffu64) << 31));
    assert!(!(token_amount_neg && token_amount.is_zero()) && !(native_amount_neg && native_amount.is_zero()), "Too big negative value");

    if token_amount_neg {
        token_amount -= num!("18446744073709551616");
    }

    if native_amount_neg {
        native_amount -= num!("18446744073709551616");
    }

    (token_amount, token_id, native_amount)
}


