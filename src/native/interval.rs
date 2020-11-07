use crate::{
    fawkes_crypto::{
        typenum::Unsigned,
        core::{
            sizedvec::SizedVec,
        },
        ff_uint::{Num, NumRepr, PrimeField}
    },
    native::boundednum::BoundedNum
};





pub type Interval<Fr,L> = (BoundedNum<Fr,L>, BoundedNum<Fr,L>);
pub type IntervalSet<Fr,L,N> = SizedVec<Interval<Fr,L>, N>;

fn interval_is_zero<Fr:PrimeField, L:Unsigned>(a:&Interval<Fr,L>) -> bool {
    a.0.as_num().to_uint() >= a.1.as_num().to_uint()
}

// a \subset b
fn interval_in<Fr:PrimeField, L:Unsigned>(a:&Interval<Fr,L>, b:&Interval<Fr,L>) -> bool {
    !interval_is_zero(b) && (interval_is_zero(a) || ((b.0.as_num().to_uint() >= a.0.as_num().to_uint()) && (a.1.as_num().to_uint() >= b.1.as_num().to_uint())))
}

// x \in it
fn element_in_interval<Fr:PrimeField, L:Unsigned>(x:&BoundedNum<Fr,L>, it:&Interval<Fr,L>) -> bool {
    (x.as_num().to_uint() >= it.0.as_num().to_uint()) && (x.as_num().to_uint() < it.1.as_num().to_uint())
}

// a \subset \b
pub fn interval_set_in<Fr:PrimeField, L:Unsigned, N:Unsigned>(a:&IntervalSet<Fr,L,N>, b:&IntervalSet<Fr,L,N>) -> bool {
    let mut res = true;
    for alpha in a.iter() {
        let mut t = false;
        for beta in b.iter() {
            t = t || interval_in(alpha, beta);
        }
        res = res && t;
    }
    res
}

// x \in it
pub fn element_in_interval_set<Fr:PrimeField, L:Unsigned, N:Unsigned>(x:&BoundedNum<Fr,L>, it:&IntervalSet<Fr,L,N>) -> bool {
    let mut res = false;
    for i in it.iter() {
        res = res || element_in_interval(x, i);
    }
    res

}


pub fn interval_set_from_num<Fr:PrimeField, L:Unsigned, N:Unsigned, O:Unsigned>(n:BoundedNum<Fr,O>) -> IntervalSet<Fr,L,N> {
    let mut n_repr = n.as_num().to_uint();
    assert!(O::USIZE == L::USIZE*(N::USIZE+1));
    assert!(Fr::MODULUS_BITS > L::U32*N::U32);
    let mask = (NumRepr::ONE << L::U32) - NumRepr::ONE;
    let x = NumRepr::ZERO;
    let y = n_repr & mask;
    n_repr >>= L::U32;
    let mut res = vec![];
    res.push((BoundedNum::new_unchecked(Num::from_uint_unchecked(x)), BoundedNum::new_unchecked(Num::from_uint_unchecked(y))));
    
    for _ in 1..N::USIZE {
        let x = n_repr & mask;
        n_repr >>= L::U32;
        let y = n_repr & mask;
        n_repr >>= L::U32;
        res.push((BoundedNum::new_unchecked(Num::from_uint_unchecked(x)), BoundedNum::new_unchecked(Num::from_uint_unchecked(y))));
    }

    SizedVec::from_slice(&res)
}

pub fn interval_set_to_num<Fr:PrimeField, L:Unsigned, N:Unsigned, O:Unsigned>(it:IntervalSet<Fr,L,N>) -> BoundedNum<Fr,O> {
    assert!(Fr::MODULUS_BITS > L::U32*(2*N::U32-1));
    assert!(O::USIZE == L::USIZE*(N::USIZE+1));
    assert!(it[0].0.to_num() == Num::ZERO);
    
    let mut n_repr = NumRepr::ZERO;

    for i in (1..N::USIZE).rev() {
        n_repr += it[i].1.as_num().to_uint();
        n_repr <<= L::U32;
        n_repr += it[i].0.as_num().to_uint();
        n_repr <<= L::U32;
    }

    n_repr += it[0].1.as_num().to_uint();

    BoundedNum::new_unchecked(Num::from_uint_unchecked(n_repr))

}