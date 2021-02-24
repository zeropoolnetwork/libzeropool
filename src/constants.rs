use fawkes_crypto::typenum::{U1, U2, U32, U8, U80, U128, Unsigned};
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
pub type V = U128;
pub type ST = U80;
pub type INTL = U32;
pub type INTN = U8;
pub type INPROOF = <IN as Add<U1>>::Output;

pub const CHECKSUM_SIZE: usize = 4;
pub const NUM_SIZE: usize = 32;
pub const NOTE_SIZE: usize = (D::USIZE + V::USIZE + ST::USIZE)/8 + NUM_SIZE;
pub const ACCOUNT_SIZE: usize = (V::USIZE + ST::USIZE + INTN::USIZE*H::USIZE)/8 + NUM_SIZE;
pub const COMMITMENT_TOTAL_SIZE: usize = NOTE_SIZE + ACCOUNT_SIZE + CHECKSUM_SIZE*2 + NUM_SIZE*2;