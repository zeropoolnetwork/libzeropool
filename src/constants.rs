pub const IN: usize = 3;
pub const OUTLOG: usize = 7;
pub const OUT: usize = (1<<OUTLOG)-1;
pub const HEIGHT: usize = 48;
pub const DIVERSIFIER_SIZE: usize = 80;
pub const BALANCE_SIZE: usize = 64;
pub const ENERGY_SIZE: usize = BALANCE_SIZE+HEIGHT;
pub const SALT_SIZE: usize = 80;


pub const POLY_1305_TAG_SIZE: usize = 16;
pub const NUM_SIZE: usize = 32;
pub const NOTE_SIZE: usize = (DIVERSIFIER_SIZE + BALANCE_SIZE + SALT_SIZE)/8 + NUM_SIZE;
pub const ACCOUNT_SIZE: usize = (BALANCE_SIZE + SALT_SIZE + ENERGY_SIZE + HEIGHT)/8 + NUM_SIZE;
pub const COMMITMENT_TOTAL_SIZE: usize = NOTE_SIZE + ACCOUNT_SIZE + POLY_1305_TAG_SIZE*2 + NUM_SIZE*2;
