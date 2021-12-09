use fawkes_crypto::ff_uint::{PrimeFieldParams, Uint};

pub const IN: usize = 3;
pub const INPLUSONELOGCEIL:usize = 2;
pub const OUTPLUSONELOG: usize = 7;
pub const OUT: usize = (1<<OUTPLUSONELOG)-1;
pub const HEIGHT: usize = 48;
pub const DIVERSIFIER_SIZE_BITS: usize = 80;
pub const BALANCE_SIZE_BITS: usize = 64;
pub const ENERGY_SIZE_BITS: usize = BALANCE_SIZE_BITS+HEIGHT;
pub const SALT_SIZE_BITS: usize = 80;
pub const POOLID_SIZE_BITS: usize = 24;

pub const POLY_1305_TAG_SIZE: usize = 16;
pub const U256_SIZE:usize = 32;
// pub const NUM_SIZE: usize = 32;
// pub const NOTE_SIZE: usize = (DIVERSIFIER_SIZE_BITS + BALANCE_SIZE_BITS + SALT_SIZE_BITS)/8 + NUM_SIZE;
// pub const ACCOUNT_SIZE: usize = (BALANCE_SIZE_BITS + DIVERSIFIER_SIZE_BITS + ENERGY_SIZE_BITS + HEIGHT)/8 + NUM_SIZE;
// pub const COMMITMENT_TOTAL_SIZE: usize = NOTE_SIZE + ACCOUNT_SIZE + POLY_1305_TAG_SIZE*2 + NUM_SIZE*2;


pub fn num_size_bits<Fp:PrimeFieldParams+Sized>() -> usize {
    Fp::Inner::NUM_WORDS*Fp::Inner::WORD_BITS
}

pub fn note_size_bits<Fp:PrimeFieldParams>() -> usize {
    DIVERSIFIER_SIZE_BITS + BALANCE_SIZE_BITS + SALT_SIZE_BITS + num_size_bits::<Fp>()
}

pub fn account_size_bits<Fp:PrimeFieldParams>() -> usize {
    BALANCE_SIZE_BITS + DIVERSIFIER_SIZE_BITS + ENERGY_SIZE_BITS + HEIGHT + num_size_bits::<Fp>()
}

// pub const fn commitment_total_size_bits<Fp:PrimeFieldParams>() -> usize {
//     note_size_bits::<Fp>() + account_size_bits::<Fp>() + POLY_1305_TAG_SIZE*16 + num_size_bits::<Fp>()*2
// }

//fist 12 bytes from keccak256("ZeroPool")
pub const ENCRYPTION_NONCE: [u8;12] = [0x5b, 0xbd, 0xff, 0xc6, 0xfe, 0x73, 0xc4, 0x60, 0xf1, 0xb2, 0xb8, 0x5d];