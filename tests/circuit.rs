use libzeropool::{
    fawkes_crypto::{
        circuit::cs::CS, 
        core::signal::Signal,
        ff_uint::Num
    },
    native::{account::Account, params::PoolBN256}
};
    
use libzeropool::POOL_PARAMS;
use libzeropool::circuit::tx::{CTransferPub, CTransferSec, c_transfer};
use libzeropool::native::params::PoolParams;
use libzeropool::native::note::Note;
use std::time::Instant;

#[test]
fn test_circuit_tx() {
    let ref cs = CS::rc_new(true);
    let ref p = CTransferPub::alloc(cs, None);
    let ref s = CTransferSec::alloc(cs, None);

    
    let mut n_constraints = cs.borrow().num_constraints();
    let start = Instant::now();
    c_transfer(p, s, &*POOL_PARAMS);
    let duration = start.elapsed();
    n_constraints=cs.borrow().num_constraints()-n_constraints;

    println!("tx constraints = {}", n_constraints);
    println!("Time elapsed in c_transfer() is: {:?}", duration);

}    

struct State {
    items:Vec<(Account<PoolBN256>, Note<PoolBN256>)>,
    default_hashes:Vec<Num<<PoolBN256 as PoolParams>::Fr>>
}

impl State {
    // fn new() -> Self {
    //     let mut default_hashes = vec![];
    //     let mut t = <Num<<PoolBN256 as PoolParams>::Fr>>::ZERO;
    //     let mut default_hashes = vec![t];

    //     std::unimplemented!()
    // }
}


#[test]
fn test_make_proof() {

}