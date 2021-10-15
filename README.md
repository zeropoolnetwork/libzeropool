# libzeropool (WIP)

This is library with circuits and cryptography of ZeroPool. 

Description of protocol https://hackmd.io/_Xm5DjqUTyykcBtDgMxLwA

JS binding available at https://github.com/zeropoolnetwork/libzeropool-rs


## Benchmark

```bash
cargo test --release -- --nocapture test_circuit_tx_setup_and_prove
```

Benchmark result on Intel Core i9-9880H

```
Time elapsed in setup() is: 48.573000645s
Time elapsed in prove() is: 6.915143894s
Time elapsed in verify() is: 5.104347ms
```


## Functions

### Generation of keys and proof

Example of key generation of keys and proof

```rust

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

```

### Encryption

```rust
#[test]
fn test_encryption() {
    let mut rng = thread_rng();
    let sender_eta = rng.gen();
    let receiver_eta = rng.gen();
    let mut account: Account<Fr> = rng.gen();
    let mut note:Vec<Note<Fr>> = (0..2).map(|_| Note::sample(&mut rng, &*POOL_PARAMS)).collect();
    account.eta = sender_eta;
    note[0].p_d = derive_key_p_d(note[0].d.as_num().clone(), receiver_eta, &*POOL_PARAMS).x;
    let ciphertext = cipher::encrypt(&(0..32).map(|_| rng.gen()).collect::<Vec<_>>(), sender_eta, account, &note, &*POOL_PARAMS);
    let result_out = cipher::decrypt_out(sender_eta, &ciphertext, &*POOL_PARAMS);

    assert!(result_out.is_some(), "Could not decrypt outgoing data.");
        let (account_out, note_out) = result_out.unwrap();
        assert!(note.len()==note_out.len() && 
        note.iter().zip(note_out.iter()).all(|(l,r)| l==r) &&
        account == account_out, "Wrong outgoing data decrypted");

    let result_out = cipher::decrypt_in(receiver_eta, &ciphertext, &*POOL_PARAMS);
    assert!(result_out.len()==2 && result_out[0].is_some() && result_out[0].unwrap()==note[0] && result_out[1].is_none(), "Wrong incoming data decrypted");
}

```