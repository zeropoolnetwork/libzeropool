pub const SEED_DIVERSIFIER: &'static [u8]= b"diversifier";
pub const SEED_DECRYPTION_KEY: &'static [u8] = b"decryption_key";
pub const SEED_IN_NOTE_HASH: &'static [u8] = b"in_note_hash";
pub const SEED_OUT_NOTE_HASH: &'static [u8] = b"out_note_hash";
pub const SEED_TX_HASH: &'static [u8] = b"tx_hash";
pub const SEED_NULLIFIER: &'static [u8] = b"nullifier";
pub const SEED_NOTE_HASH: &'static [u8] = b"note";



pub const IN: usize = 8;
pub const OUT: usize = 2;
pub const H: usize = 32;
pub const D: usize = 80;
pub const V: usize = 64;
pub const E: usize = 96; // E = V + H
pub const ST: usize = 80;


pub const CHECKSUM_SIZE: usize = 4;
pub const NUM_SIZE: usize = 32;
pub const NOTE_SIZE: usize = (D + V + ST)/8 + NUM_SIZE;
pub const ACCOUNT_SIZE: usize = (V + ST + E + H)/8 + NUM_SIZE;
pub const COMMITMENT_TOTAL_SIZE: usize = NOTE_SIZE + ACCOUNT_SIZE + CHECKSUM_SIZE*2 + NUM_SIZE*2;
