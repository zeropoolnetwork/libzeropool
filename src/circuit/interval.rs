use crate::{
    fawkes_crypto::{
        typenum::Unsigned,
        circuit::{
            bitify::{c_into_bits_le, c_from_bits_le},
            bool::CBool,
            num::CNum
        },
        core::{
            signal::Signal, sizedvec::SizedVec,
        },
        ff_uint::{Num, NumRepr, PrimeField}
    },
    circuit::boundednum::CBoundedNum
};




// a < b
fn lt<Fr:PrimeField, L:Unsigned>(a:&CBoundedNum<Fr, L>, b:&CBoundedNum<Fr, L>) -> CBool<Fr> {
    assert!(L::U32 < Fr::MODULUS_BITS);
    let acc_init = (NumRepr::<Fr::Inner>::ONE << L::U32) - NumRepr::<Fr::Inner>::ONE;
    
    let s = a.derive_const::<CNum<_>>(&Num::from_uint_unchecked(acc_init)) + b.as_num() - a.as_num();
    c_into_bits_le(&s, L::USIZE+1)[L::USIZE].clone()
}

// a >= b
fn gte<Fr:PrimeField, L:Unsigned>(a:&CBoundedNum<Fr, L>, b:&CBoundedNum<Fr, L>) -> CBool<Fr> {
    assert!(L::U32 < Fr::MODULUS_BITS);
    let acc_init = NumRepr::<Fr::Inner>::ONE << L::U32;
    let s = a.derive_const::<CNum<_>>(&Num::from_uint_unchecked(acc_init)) - b.as_num() + a.as_num();
    c_into_bits_le(&s, L::USIZE+1)[L::USIZE].clone()
}

pub type CInterval<Fr,L> = (CBoundedNum<Fr,L>, CBoundedNum<Fr,L>);
pub type CIntervalSet<Fr,L,N> = SizedVec<CInterval<Fr,L>, N>;

fn c_interval_is_zero<Fr:PrimeField, L:Unsigned>(a:&CInterval<Fr,L>) -> CBool<Fr> {
    gte(&a.0, &a.1)
}

// a \subset b
fn c_interval_in<Fr:PrimeField, L:Unsigned>(a:&CInterval<Fr,L>, b:&CInterval<Fr,L>) -> CBool<Fr> {
    !c_interval_is_zero(b) & (c_interval_is_zero(a) | (gte(&b.0, &a.0) & gte(&a.1, &b.1)))
}

// x \in it
fn c_element_in_interval<Fr:PrimeField, L:Unsigned>(x:&CBoundedNum<Fr,L>, it:&CInterval<Fr,L>) -> CBool<Fr> {
    gte(x, &it.0) & lt(x, &it.1)
}

// a \subset \b
pub fn c_interval_set_in<Fr:PrimeField, L:Unsigned, N:Unsigned>(a:&CIntervalSet<Fr,L,N>, b:&CIntervalSet<Fr,L,N>) -> CBool<Fr> {
    let cs = a[0].get_cs();
    let mut res = CBool::from_const(cs, &true);
    for alpha in a.iter() {
        let mut t = CBool::from_const(cs, &false);
        for beta in b.iter() {
            t = t | c_interval_in(alpha, beta);
        }
        res = res & t;
    }
    res
}

// x \in it
pub fn c_element_in_interval_set<Fr:PrimeField, L:Unsigned, N:Unsigned>(x:&CBoundedNum<Fr,L>, it:&CIntervalSet<Fr,L,N>) -> CBool<Fr> {
    let mut res = it[0].derive_const(&false);
    for i in it.iter() {
        res = res | c_element_in_interval(x, i);
    }
    res

}



pub fn c_interval_set_from_num<Fr:PrimeField, L:Unsigned, N:Unsigned, O:Unsigned>(n:&CBoundedNum<Fr,O>) -> CIntervalSet<Fr,L,N> {
    assert!(Fr::MODULUS_BITS > L::U32*N::U32);
    let bits = c_into_bits_le(n.as_num(), L::USIZE*(2*N::USIZE-1));

    let x = n.derive_const(&Num::ZERO);
    let y = c_from_bits_le(&bits[0..L::USIZE]);
    let mut res = vec![];
    res.push((CBoundedNum::new_unchecked(&x), CBoundedNum::new_unchecked(&y)));

    for i in 1..N::USIZE {
        let x = c_from_bits_le(&bits[L::USIZE*(2*i-1)..L::USIZE*2*i]);
        let y = c_from_bits_le(&bits[L::USIZE*2*i..L::USIZE*(2*i+1)]);
        res.push((CBoundedNum::new_unchecked(&x), CBoundedNum::new_unchecked(&y)));
    }

    SizedVec::from_slice(&res)
}

pub fn c_interval_set_to_num<Fr:PrimeField, L:Unsigned, N:Unsigned, O:Unsigned>(it:CIntervalSet<Fr,L,N>) -> CBoundedNum<Fr, O> {
    assert!(Fr::MODULUS_BITS > L::U32*(2*N::U32-1));
    assert!(it[0].0.as_const().unwrap().to_num() == Num::ZERO);
    
    let mut res = it[0].1.as_num().clone();

    for i in 1..N::USIZE {
        res = res + it[i].0.as_num() * Num::from_uint_unchecked(NumRepr::ONE << L::U32*(2*i as u32 - 1)) +
            it[i].1.as_num() * Num::from_uint_unchecked(NumRepr::ONE << L::U32*2*(i as u32));
    }
    CBoundedNum::new_unchecked(&res)

}
