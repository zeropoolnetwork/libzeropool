pub const SEED_DIVERSIFIER: &'static [u8]= b"diversifier";
pub const SEED_DECRYPTION_KEY: &'static [u8] = b"decryption_key";
pub const SEED_IN_NOTE_HASH: &'static [u8] = b"in_note_hash";
pub const SEED_OUT_NOTE_HASH: &'static [u8] = b"out_note_hash";
pub const SEED_TX_HASH: &'static [u8] = b"tx_hash";
pub const SEED_NULLIFIER: &'static [u8] = b"nullifier";
pub const SEED_NOTE_HASH: &'static [u8] = b"note";



pub const IN: usize = 8;
pub const OUTLOG: usize = 1;
pub const OUT: usize = (1<<OUTLOG)-1;
pub const HEIGHT: usize = 32;
pub const DIVERSIFIER_SIZE: usize = 80;
pub const BALANCE_SIZE: usize = 64;
pub const ENERGY_SIZE: usize = BALANCE_SIZE+HEIGHT;
pub const SALT_SIZE: usize = 80;


pub const POLY_1305_TAG_SIZE: usize = 16;
pub const NUM_SIZE: usize = 32;
pub const NOTE_SIZE: usize = (DIVERSIFIER_SIZE + BALANCE_SIZE + SALT_SIZE)/8 + NUM_SIZE;
pub const ACCOUNT_SIZE: usize = (BALANCE_SIZE + SALT_SIZE + ENERGY_SIZE + HEIGHT)/8 + NUM_SIZE;
pub const COMMITMENT_TOTAL_SIZE: usize = NOTE_SIZE + ACCOUNT_SIZE + POLY_1305_TAG_SIZE*2 + NUM_SIZE*2;
