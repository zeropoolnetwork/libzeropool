use crate::fawkes_crypto::circuit::{
    bool::CBool,
    num::CNum,
    bitify::{c_into_bits_le_strict, c_into_bits_le}
};
use crate::fawkes_crypto::core::signal::Signal;
use crate::fawkes_crypto::circuit::cs::{RCS, CS};
use crate::circuit::{boundednum::CBoundedNum, note::CNote};
use crate::native::delegated_deposit::{DelegatedDeposit, DelegatedDepositBatchPub, DelegatedDepositBatchSec};
use crate::fawkes_crypto::ff_uint::{PrimeFieldParams, Num};
use crate::constants::{DIVERSIFIER_SIZE_BITS, BALANCE_SIZE_BITS, OUT};
use crate::fawkes_crypto::core::sizedvec::SizedVec;
use crate::native::params::PoolParams;
use crate::circuit::account::CAccount;
use crate::circuit::tx::c_out_commitment_hash;


use fawkes_crypto_keccak256::circuit::hash::c_keccak256_reduced;

#[derive(Clone, Signal)]
#[Value = "DelegatedDeposit<C::Fr>"]
pub struct CDelegatedDeposit<C:CS> {
    pub d: CBoundedNum<C, { DIVERSIFIER_SIZE_BITS }>,
    pub p_d: CNum<C>,
    pub b: CBoundedNum<C, { BALANCE_SIZE_BITS }>,
}



fn num_to_iter_bits_be<C:CS>(n:&CNum<C>) -> impl Iterator<Item=CBool<C>> {
    assert!(C::Fr::MODULUS_BITS <= 256);
    let bits = c_into_bits_le_strict(n);
    let zero = n.derive_const(&false);
    std::iter::repeat(zero).take(256 - bits.len()).chain(bits.into_iter().rev())
}


fn boundednum_to_iter_bits_be<C:CS, const L:usize>(n:&CBoundedNum<C, L>) -> impl Iterator<Item=CBool<C>> {
    assert!(L < C::Fr::MODULUS_BITS as usize);
    let bits = c_into_bits_le(n.as_num(), L);
    bits.into_iter().rev()
}

impl<C:CS> CDelegatedDeposit<C> {
    pub fn to_note(&self) -> CNote<C> {
        let cs = self.d.get_cs();
        CNote {
            d: self.d.clone(),
            p_d: self.p_d.clone(),
            b: self.b.clone(),
            t: CBoundedNum::new(&CNum::from_const(cs, &Num::ZERO))
        }
    }

    // convert to iter over bits be
    pub fn to_iter_bits_be(&self) -> impl Iterator<Item=CBool<C>> {
        boundednum_to_iter_bits_be(&self.d)
        .chain(num_to_iter_bits_be(&self.p_d))
        .chain(boundednum_to_iter_bits_be(&self.b))
    }

}

#[derive(Clone, Signal)]
#[Value = "DelegatedDepositBatchPub<C::Fr>"]
pub struct CDelegatedDepositBatchPub<C:CS> {
    pub keccak_sum: CNum<C>
}

#[derive(Clone, Signal)]
#[Value = "DelegatedDepositBatchSec<C::Fr>"]
pub struct CDelegatedDepositBatchSec<C:CS> {
    pub out_account: CAccount<C>,
    pub out_commitment_hash: CNum<C>,
    pub deposits: SizedVec<CDelegatedDeposit<C>, { OUT}>,
}

pub fn check_delegated_deposit_batch<C:CS, P:PoolParams<Fr=C::Fr>>(
    p: &CDelegatedDepositBatchPub<C>,
    s: &CDelegatedDepositBatchSec<C>,
    params: &P
) {
    let cs = p.get_cs();
    let bits:Vec<_> = num_to_iter_bits_be(&s.out_commitment_hash).chain(
    s.deposits.iter().flat_map(
        |d| d.to_iter_bits_be()
    )).collect();

    c_keccak256_reduced(cs, &bits).assert_eq(&p.keccak_sum);

    let out_account_hash = s.out_account.hash(params);
    let out_note_hash:Vec<_> = s.deposits.iter().map(|d| d.to_note())
        .map(|n| n.hash(params)).collect();

    let out_hash = [[out_account_hash].as_ref(), out_note_hash.as_slice()].concat();
    c_out_commitment_hash(&out_hash, params).assert_eq(&s.out_commitment_hash);
}