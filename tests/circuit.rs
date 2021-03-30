use libzeropool::{
    fawkes_crypto::{
        circuit::cs::CS, 
        core::signal::Signal,
    }
};
    
use libzeropool::POOL_PARAMS;
use libzeropool::circuit::tx::{CTransferPub, CTransferSec, c_transfer};
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
