pub const IN: usize = 3;
pub const INPLUSONELOGCEIL:usize = 2;
pub const OUTPLUSONELOG: usize = 7;
pub const OUT: usize = (1<<OUTPLUSONELOG)-1;
pub const HEIGHT: usize = 48;
pub const DIVERSIFIER_SIZE_BITS: usize = 80;
pub const BALANCE_SIZE_BITS: usize = 64;
pub const ENERGY_SIZE_BITS: usize = 64;
pub const SALT_SIZE_BITS: usize = 80;


pub const POLY_1305_TAG_SIZE: usize = 16;
pub const NUM_SIZE: usize = 32;
pub const NOTE_SIZE: usize = (DIVERSIFIER_SIZE_BITS + BALANCE_SIZE_BITS + SALT_SIZE_BITS)/8 + NUM_SIZE;
pub const ACCOUNT_SIZE: usize = (BALANCE_SIZE_BITS + SALT_SIZE_BITS + ENERGY_SIZE_BITS + HEIGHT)/8 + NUM_SIZE;
pub const COMMITMENT_TOTAL_SIZE: usize = NOTE_SIZE + ACCOUNT_SIZE + POLY_1305_TAG_SIZE*2 + NUM_SIZE*2;
