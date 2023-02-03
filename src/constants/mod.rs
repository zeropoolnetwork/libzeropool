use fawkes_crypto::ff_uint::{PrimeFieldParams, Uint};

#[cfg_attr(feature="in1out127", path = "in1out127.rs")]
#[cfg_attr(feature="in3out127", path = "in3out127.rs")]
#[cfg_attr(feature="in7out127", path = "in7out127.rs")]
#[cfg_attr(feature="in15out127", path = "in15out127.rs")]
mod constants_inner;

pub use constants_inner::*;

pub const HEIGHT: usize = 48;
pub const DIVERSIFIER_SIZE_BITS: usize = 80;
pub const BALANCE_SIZE_BITS: usize = 64;
pub const ENERGY_SIZE_BITS: usize = BALANCE_SIZE_BITS+HEIGHT;
pub const SALT_SIZE_BITS: usize = 80;
pub const POOLID_SIZE_BITS: usize = 24;

pub const DELEGATED_DEPOSITS_NUM:usize = 16;

pub const POLY_1305_TAG_SIZE: usize = 16;
pub const U256_SIZE:usize = 32;

pub fn num_size_bits<Fp:PrimeFieldParams+Sized>() -> usize {
    Fp::Inner::NUM_WORDS*Fp::Inner::WORD_BITS
}

pub fn note_size_bits<Fp:PrimeFieldParams>() -> usize {
    DIVERSIFIER_SIZE_BITS + BALANCE_SIZE_BITS + SALT_SIZE_BITS + num_size_bits::<Fp>()
}

pub fn account_size_bits<Fp:PrimeFieldParams>() -> usize {
    BALANCE_SIZE_BITS + DIVERSIFIER_SIZE_BITS + ENERGY_SIZE_BITS + HEIGHT + num_size_bits::<Fp>()
}


//fist 12 bytes from keccak256("ZeroPool")
pub const ENCRYPTION_NONCE: [u8;12] = [0x5b, 0xbd, 0xff, 0xc6, 0xfe, 0x73, 0xc4, 0x60, 0xf1, 0xb2, 0xb8, 0x5d];