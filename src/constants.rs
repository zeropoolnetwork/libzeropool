use fawkes_crypto::{
    typenum::{U2, U32, U8, U80, U64, U160, Unsigned},
    engines::bn256::Fr,
    ff_uint::PrimeFieldParams
};

use std::ops::Add;

pub const SEED_DIVERSIFIER: &'static [u8]= b"diversifier";
pub const SEED_DECRYPTION_KEY: &'static [u8] = b"decryption_key";
pub const SEED_IN_NOTE_HASH: &'static [u8] = b"in_note_hash";
pub const SEED_OUT_NOTE_HASH: &'static [u8] = b"out_note_hash";
pub const SEED_TX_HASH: &'static [u8] = b"tx_hash";
pub const SEED_NULLIFIER: &'static [u8] = b"nullifier";
pub const SEED_NOTE_HASH: &'static [u8] = b"note";



pub type IN = U8;
pub type OUT = U2;
pub type H = U32;
pub type D = U80;
pub type V = U64;
pub type E = <V as Add<H>>::Output;
pub type ST = U80;
pub type X = U160;

pub const CHECKSUM_SIZE: usize = 4;
pub const NUM_SIZE: usize = (Fr::MODULUS_BITS as usize-1)/8+1;
pub const NOTE_SIZE: usize = (D::USIZE + V::USIZE + ST::USIZE)/8+NUM_SIZE;
pub const ACCOUNT_SIZE: usize = (V::USIZE + ST::USIZE + E::USIZE + H::USIZE)/8+NUM_SIZE;
pub const COMMITMENT_TOTAL_SIZE: usize = NOTE_SIZE + ACCOUNT_SIZE + CHECKSUM_SIZE*2 + NUM_SIZE*2;
