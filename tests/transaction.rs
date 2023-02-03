use libzeropool::{POOL_PARAMS, circuit::tx::{CTransferPub, CTransferSec, c_transfer},
    fawkes_crypto::{
        circuit::{
            cs::{CS, DebugCS}
        }, 
        core::signal::Signal,
        rand::thread_rng,
        backend::bellman_groth16::{
            engines::Bn256,
            setup::setup,
            prover,
            verifier
        }
    }, 
};

use libzeropool::fawkes_crypto::engines::bn256::Fr;
use std::time::Instant;
    

use libzeropool::helpers::sample_data::State;

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

#[test]
fn test_circuit_tx_fullfill() {
    let mut rng = thread_rng();
    let state = State::random_sample_state(&mut rng, &*POOL_PARAMS);
    let (p, s) = state.random_sample_transfer(&mut rng, &*POOL_PARAMS);

    let ref cs = DebugCS::rc_new();
    let ref p = CTransferPub::alloc(cs, Some(&p));
    let ref s = CTransferSec::alloc(cs, Some(&s));

    
    let mut num_gates = cs.borrow().num_gates();
    let start = Instant::now();
    c_transfer(p, s, &*POOL_PARAMS);
    let duration = start.elapsed();
    num_gates=cs.borrow().num_gates()-num_gates;

    println!("tx gates = {}", num_gates);
    println!("Time elapsed in c_transfer() is: {:?}", duration);
}


#[test]
fn test_circuit_tx_setup_and_prove() {
    fn circuit<C:CS<Fr=Fr>>(public: CTransferPub<C>, secret: CTransferSec<C>) {
        c_transfer(&public, &secret, &*POOL_PARAMS);
    }

    let mut rng = thread_rng();
    let state = State::random_sample_state(&mut rng, &*POOL_PARAMS);
    let (public, secret) = state.random_sample_transfer(&mut rng, &*POOL_PARAMS);

    let ts_setup = Instant::now();
    let params = setup::<Bn256, _, _, _>(circuit);
    let duration = ts_setup.elapsed();
    println!("Time elapsed in setup() is: {:?}", duration);

    let ts_prove = Instant::now();
    let (inputs, snark_proof) = prover::prove(&params, &public, &secret, circuit);
    let duration = ts_prove.elapsed();
    println!("Time elapsed in prove() is: {:?}", duration);

    let ts_verify = Instant::now();
    let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);
    let duration = ts_verify.elapsed();
    println!("Time elapsed in verify() is: {:?}", duration);

    assert!(res, "Verifier result should be true");
}

