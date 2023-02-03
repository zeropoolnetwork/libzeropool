use crate::fawkes_crypto::circuit::{
    bool::CBool,
    num::CNum,
    bitify::{c_into_bits_le_strict, c_into_bits_le, c_from_bits_le}
};
use crate::fawkes_crypto::core::signal::Signal;
use crate::fawkes_crypto::circuit::cs::{RCS, CS};
use crate::circuit::{boundednum::CBoundedNum, note::CNote};
use crate::native::delegated_deposit::{DelegatedDeposit, DelegatedDepositBatchPub, DelegatedDepositBatchSec};
use crate::fawkes_crypto::ff_uint::{PrimeFieldParams, Num};
use crate::constants::{DIVERSIFIER_SIZE_BITS, BALANCE_SIZE_BITS, DELEGATED_DEPOSITS_NUM, OUT};
use crate::fawkes_crypto::core::sizedvec::SizedVec;
use crate::native::params::PoolParams;
use crate::native::note::Note;
use crate::native::boundednum::BoundedNum;
use crate::circuit::account::CAccount;
use crate::circuit::tx::c_out_commitment_hash;


use fawkes_crypto_keccak256::circuit::hash::c_keccak256;

#[derive(Clone, Signal)]
#[Value = "DelegatedDeposit<C::Fr>"]
pub struct CDelegatedDeposit<C:CS> {
    pub d: CBoundedNum<C, { DIVERSIFIER_SIZE_BITS }>,
    pub p_d: CNum<C>,
    pub b: CBoundedNum<C, { BALANCE_SIZE_BITS }>,
}



pub fn num_to_iter_bits_be<C:CS>(n:&CNum<C>) -> impl Iterator<Item=CBool<C>> {
    assert!(C::Fr::MODULUS_BITS <= 256);
    let bits = c_into_bits_le_strict(n);
    let zero = n.derive_const(&false);
    let bits_le = bits.into_iter().chain(std::iter::repeat(zero)).take(256).collect::<Vec<_>>();
    let bits_be = bits_le.chunks(8).rev().flatten().cloned().collect::<Vec<_>>();
    bits_be.into_iter()
}


pub fn boundednum_to_iter_bits_be<C:CS, const L:usize>(n:&CBoundedNum<C, L>) -> impl Iterator<Item=CBool<C>> {
    assert!(L < C::Fr::MODULUS_BITS as usize);
    assert!(L%8 == 0);
    let bits_le = c_into_bits_le(n.as_num(), L);
    let bits_be = bits_le.chunks(8).rev().flatten().cloned().collect::<Vec<_>>();
    bits_be.into_iter()
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
    pub deposits: SizedVec<CDelegatedDeposit<C>, { DELEGATED_DEPOSITS_NUM}>,
}

pub fn check_delegated_deposit_batch<C:CS, P:PoolParams<Fr=C::Fr>>(
    p: &CDelegatedDepositBatchPub<C>,
    s: &CDelegatedDepositBatchSec<C>,
    params: &P
) {
    assert!(DELEGATED_DEPOSITS_NUM <= OUT);
    let cs = p.get_cs();
    let out_account_hash = s.out_account.hash(params);

    let bits:Vec<_> = num_to_iter_bits_be(&s.out_commitment_hash)
    .chain(num_to_iter_bits_be(&out_account_hash)).chain(
        s.deposits.iter().flat_map(
            |d| d.to_iter_bits_be()
    )).collect();

    let keccak_bits_be = c_keccak256(cs, &bits);
    let keccak_bits_le = keccak_bits_be.as_slice().chunks(8).rev().flatten().cloned().collect::<Vec<_>>();
    c_from_bits_le(&keccak_bits_le).assert_eq(&p.keccak_sum);
    
    let zero_note_hash = (Note {
        d:BoundedNum::new(Num::ZERO),
        p_d:Num::ZERO,
        b:BoundedNum::new(Num::ZERO),
        t:BoundedNum::new(Num::ZERO)
    }).hash(params);

    let c_zero_note_hash = CNum::from_const(cs, &zero_note_hash);

    
    let out_note_hash:Vec<_> = s.deposits.iter().map(|d| d.to_note())
        .map(|n| n.hash(params)).chain(std::iter::repeat(c_zero_note_hash)).take(OUT).collect();

    let out_hash = [[out_account_hash].as_ref(), out_note_hash.as_slice()].concat();
    c_out_commitment_hash(&out_hash, params).assert_eq(&s.out_commitment_hash);
}

