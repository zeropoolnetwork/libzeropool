use fawkes_crypto::circuit::cs::CS;
use libzeropool::{
    fawkes_crypto::{
        circuit::cs::DebugCS, 
        core::signal::Signal,
    }
};
    
use libzeropool::POOL_PARAMS;
use libzeropool::circuit::tx::{CTransferPub, CTransferSec, c_transfer};
use std::time::Instant;

#[test]
fn test_circuit_tx() {
    let ref cs = DebugCS::rc_new();
    let ref p = CTransferPub::alloc(cs, None);
    let ref s = CTransferSec::alloc(cs, None);

    
    let mut n_gates = cs.borrow().num_gates();
    let start = Instant::now();
    c_transfer(p, s, &*POOL_PARAMS);
    let duration = start.elapsed();
    n_gates=cs.borrow().num_gates()-n_gates;

    println!("tx constraints = {}", n_gates);
    println!("Time elapsed in c_transfer() is: {:?}", duration);

}    
