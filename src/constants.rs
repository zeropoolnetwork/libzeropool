use fawkes_crypto::typenum::{U2, U4, U32, U8, U80, U128, U224};

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
pub type INTN = U4;
pub type INTA = U224;