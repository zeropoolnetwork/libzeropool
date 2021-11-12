use crate::native::account::Account;
use crate::native::boundednum::BoundedNum;
use crate::native::note::Note;
use crate::native::key::derive_key_p_d;
use crate::native::params::PoolParams;
use crate::constants;
use fawkes_crypto::ff_uint::{Num, NumRepr, PrimeField, PrimeFieldParams, Uint};


impl<Fr:PrimeField> Account<Fr>
{
    #[inline]
    pub fn sample<R: fawkes_crypto::rand::Rng + ?Sized, P:PoolParams<Fr=Fr>>(rng: &mut R, params:&P) -> Account<Fr> {
        let n_bits = (<Fr as PrimeFieldParams>::Inner::NUM_WORDS*<Fr as PrimeFieldParams>::Inner::WORD_BITS) as u32;
        let b_num = rng.gen::<NumRepr<<Fr as PrimeFieldParams>::Inner>>()>>(n_bits - constants::BALANCE_SIZE_BITS as u32/2);
        let e_num = rng.gen::<NumRepr<<Fr as PrimeFieldParams>::Inner>>()>>(n_bits - constants::ENERGY_SIZE_BITS as u32/2);

        let b = BoundedNum::new(Num::from_uint(b_num).unwrap());
        let e = BoundedNum::new(Num::from_uint(e_num).unwrap());

        let d:BoundedNum<_, {constants::DIVERSIFIER_SIZE_BITS}> = rng.gen();
        let p_d = derive_key_p_d::<P, Fr>(d.to_num(), rng.gen(), params).x;

        Account {
            d,
            p_d,
            i: rng.gen(),
            b,
            e,
        }
    }
}


impl<Fr:PrimeField, const L: usize> fawkes_crypto::rand::distributions::Distribution<BoundedNum<Fr, L>>
    for fawkes_crypto::rand::distributions::Standard
{
    #[inline]
    fn sample<R: fawkes_crypto::rand::Rng + ?Sized>(&self, rng: &mut R) -> BoundedNum<Fr, L> {
        let mut t : NumRepr<Fr::Inner> = rng.gen();
        t >>= (Fr::Inner::NUM_WORDS*Fr::Inner::WORD_BITS) as u32 - L as u32;
        BoundedNum::new(Num::from_uint_unchecked(t))
    }
}


impl<Fr:PrimeField> Note<Fr> {
    #[inline]
    pub fn sample<R: fawkes_crypto::rand::Rng + ?Sized, P:PoolParams<Fr=Fr>>(rng: &mut R, params:&P) -> Note<Fr> {
        let n_bits = (<Fr as PrimeFieldParams>::Inner::NUM_WORDS*<Fr as PrimeFieldParams>::Inner::WORD_BITS) as u32;
        let b_num = rng.gen::<NumRepr<<Fr as PrimeFieldParams>::Inner>>() >> (n_bits - constants::BALANCE_SIZE_BITS as u32/2);
        let b = BoundedNum::new(Num::from_uint(b_num).unwrap());
        let d:BoundedNum<_, {constants::DIVERSIFIER_SIZE_BITS}> = rng.gen();
        let p_d = derive_key_p_d::<P, Fr>(d.to_num(), rng.gen(), params).x;

        Note {
            d,
            p_d,
            b,
            t: rng.gen()
        }
    }
}