use crate::fawkes_crypto::circuit::{
    bool::CBool,
    num::CNum,
    bitify::{c_into_bits_le_strict, c_into_bits_le, c_from_bits_le},
    cs::{RCS, CS}
};
use crate::fawkes_crypto::ff_uint::{PrimeFieldParams, Num};
use crate::fawkes_crypto::core::{
    signal::Signal,
    sizedvec::SizedVec
};
use crate::circuit::{
    boundednum::CBoundedNum, 
    note::CNote,
    tx::c_out_commitment_hash,
};
use crate::native::{
    params::PoolParams,
    note::Note,
    boundednum::BoundedNum,
    account::Account,
    delegated_deposit::{DelegatedDeposit, DelegatedDepositBatchPub, DelegatedDepositBatchSec}
};
use crate::constants::{DIVERSIFIER_SIZE_BITS, BALANCE_SIZE_BITS, DELEGATED_DEPOSITS_NUM, OUT};
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
    pub out_commitment_hash: CNum<C>,
    pub deposits: SizedVec<CDelegatedDeposit<C>, DELEGATED_DEPOSITS_NUM>
}

fn c_keccak256_be_reduced<C:CS>(cs:&RCS<C>, bits:&[CBool<C>]) -> CNum<C> {
    let keccak_bits_be = c_keccak256(cs, &bits);
    let keccak_bits_le = keccak_bits_be.as_slice().chunks(8).rev().flatten().cloned().collect::<Vec<_>>();
    c_from_bits_le(&keccak_bits_le)
}

pub fn check_delegated_deposit_batch<C:CS, P:PoolParams<Fr=C::Fr>>(
    p: &CDelegatedDepositBatchPub<C>,
    s: &CDelegatedDepositBatchSec<C>,
    params: &P
) {
    assert!(DELEGATED_DEPOSITS_NUM <= OUT);
    let cs = p.get_cs();
    let bits:Vec<_> = num_to_iter_bits_be(&s.out_commitment_hash)
    .chain(
        s.deposits.iter().flat_map(
            |d| d.to_iter_bits_be()
    )).collect();

    c_keccak256_be_reduced(cs, &bits).assert_eq(&p.keccak_sum);
    
    let c_zero_account_hash = CNum::from_const(cs, &Account {
        d:BoundedNum::ZERO,
        p_d:Num::ZERO,
        i:BoundedNum::ZERO,
        b:BoundedNum::ZERO,
        e:BoundedNum::ZERO,
    }.hash(params));

    let c_zero_note_hash = CNum::from_const(cs, &Note {
        d:BoundedNum::ZERO,
        p_d:Num::ZERO,
        b:BoundedNum::ZERO,
        t:BoundedNum::ZERO
    }.hash(params));


    let out_hash = std::iter::once(c_zero_account_hash)
    .chain(s.deposits.iter().map(|d| d.to_note().hash(params)))
    .chain(std::iter::repeat(c_zero_note_hash)).take(OUT+1).collect::<Vec<_>>();

    c_out_commitment_hash(&out_hash, params).assert_eq(&s.out_commitment_hash);
    
}

