use fawkes_crypto::native::poseidon::MerkleProof;
use libzeropool::{POOL_PARAMS, circuit::tx::{CTransferPub, CTransferSec, c_transfer}, constants, 
    fawkes_crypto::{
        circuit::{
            cs::CS
        }, 
        core::signal::Signal,
        ff_uint::Num,
        native::poseidon::poseidon, 
        rand::{self, thread_rng, Rng},
        typenum::Unsigned,
        backend::bellman_groth16::{
            engines::Bn256,
            setup::setup,
            prover,
            verifier
        }
    }, 
    native::{
        account::Account, 
        boundednum::BoundedNum, 
        note::Note, 
        params::{PoolBN256, PoolParams}, 
        tx::{derive_key_dk, derive_key_pk_d, derive_key_xsk, make_delta, Tx, TransferPub, TransferSec, nullfifier, tx_hash, tx_sign}
    }
};

use std::time::Instant;
    

const N_ITEMS:usize = 1000;


struct State<P:PoolParams> {
    hashes:Vec<Vec<Num<P::Fr>>>,
    items:Vec<(Account<P>, Note<P>)>,
    default_hashes:Vec<Num<P::Fr>>,
    sk:Num<P::Fs>,
    account_id:usize,
    note_id:Vec<usize>
}

impl<P:PoolParams> State<P> {
    fn random_sample_state<R:Rng>(rng:&mut R, params:&P) -> Self {
        let sk = rng.gen();
        let xsk = derive_key_xsk(sk, params).x;
        let dk = derive_key_dk(xsk, params);


        let account_id = rng.gen_range(0, N_ITEMS);
        let note_id = rand::seq::index::sample(rng, N_ITEMS, constants::IN::USIZE).into_vec();


        let mut items:Vec<(Account<_>, Note<_>)> = (0..N_ITEMS).map(|_| (rng.gen(), rng.gen())).collect();

        for i in note_id.iter().cloned() {
            items[i].1.pk_d = derive_key_pk_d(items[i].1.d.to_num(), dk, params).x;
        }

        items[account_id].0.xsk = xsk;
        items[account_id].0.interval = BoundedNum::new(Num::ZERO);

        let mut default_hashes = vec![Num::ZERO;constants::H::USIZE+1];
        let mut hashes = vec![];

        for i in 0..constants::H::USIZE {
            let t = default_hashes[i];
            default_hashes[i+1] = poseidon([t,t].as_ref(), params.compress());
        }

        {
            let mut t = vec![];
            for j in 0..N_ITEMS {
                let (a, n) = items[j].clone();
                t.push(a.hash(params));
                t.push(n.hash(params));
            }
            if t.len() & 1 == 1 {
                t.push(default_hashes[0]);
            }
            hashes.push(t);
        }

        for i in 0..constants::H::USIZE {
            let mut t = vec![];
            for j in 0..hashes[i].len()>>1 {
                t.push(poseidon([hashes[i][2*j],hashes[i][2*j+1]].as_ref(), params.compress()));
            }
            if t.len() & 1 == 1 {
                t.push(default_hashes[i+1]);
            }
            hashes.push(t);
        }

        Self {
            hashes,
            items,
            default_hashes,
            sk,
            account_id,
            note_id
        }
    }

    

    fn random_sample_transfer<R:Rng>(&self, rng:&mut R, params:&P) -> (TransferPub<P>, TransferSec<P>) {
        let root = self.root();
        let index = N_ITEMS*2;
        let xsk = derive_key_xsk(self.sk, params).x;
        let nullifier = nullfifier(self.hashes[0][self.account_id*2] , xsk, params);
        let memo = rng.gen();

        
        let mut input_value = self.items[self.account_id].0.v.to_num();
        for &i in self.note_id.iter() {
            input_value+=self.items[i].1.v.to_num();
        }

        let mut input_energy = self.items[self.account_id].0.e.to_num();
        input_energy += self.items[self.account_id].0.v.to_num()*(Num::from(index as u32) - self.items[self.account_id].0.interval.to_num()) ;


        for &i in self.note_id.iter() {
            input_energy+=self.items[i].1.v.to_num()*Num::from((index-(2*i+1)) as u32);
        }

        let mut out_account: Account<P> = rng.gen();
        out_account.v = BoundedNum::new(input_value);
        out_account.e = BoundedNum::new(input_energy);
        out_account.interval = BoundedNum::new(Num::from(index as u32));
        out_account.xsk = xsk;

        
        let mut out_note: Note<P> = rng.gen();
        out_note.v = BoundedNum::new(Num::ZERO);

        let mut input_hashes = vec![self.items[self.account_id].0.hash(params)];
        for &i in self.note_id.iter() {
            input_hashes.push(self.items[i].1.hash(params));
        }

        let output_hashes = vec![out_account.hash(params), out_note.hash(params)];
        let tx_hash = tx_hash(&input_hashes, &output_hashes, params);
        let (eddsa_s,eddsa_r) = tx_sign(self.sk, tx_hash, params);

        let out_commit = poseidon(&output_hashes, params.compress());
        let delta = make_delta::<P>(Num::ZERO, Num::ZERO, Num::from(index as u32));
        
        let p = TransferPub::<P> {
            root,
            nullifier,
            out_commit,
            delta,
            memo,  
        };

        let tx = Tx {
            input: (self.items[self.account_id].0.clone(), self.note_id.iter().map(|&i| self.items[i].1.clone()).collect()),
            output: (out_account, out_note)
        };


        
        let s = TransferSec::<P> {
            tx,
            in_proof: (
                self.merkle_proof(self.account_id*2),
                self.note_id.iter().map(|&i| self.merkle_proof(i*2+1) ).collect()
            ),
            eddsa_s:eddsa_s.to_other().unwrap(),
            eddsa_r,
            eddsa_a:xsk
        };

        (p, s)
    }

    fn cell(&self, i:usize, j:usize) -> Num<P::Fr> {
        if self.hashes[i].len() <= j {
            self.default_hashes[i]
        } else {
            self.hashes[i][j]
        }
    }

    fn merkle_proof(&self, id:usize) -> MerkleProof<P::Fr, constants::H> {
        let sibling = (0..constants::H::USIZE).map(|i| self.cell(i, (id>>i)^1)).collect();
        let path =  (0..constants::H::USIZE).map(|i| (id>>i)&1==1).collect();
        MerkleProof {sibling, path}
    }

    fn root(&self) -> Num<P::Fr> {
        return self.hashes[constants::H::USIZE][0]
    }

}

#[test]
fn test_circuit_tx_fullfill() {
    let mut rng = thread_rng();
    let state = State::random_sample_state(&mut rng, &*POOL_PARAMS);
    let (p, s) = state.random_sample_transfer(&mut rng, &*POOL_PARAMS);

    let ref cs = CS::rc_new(true);
    let ref p = CTransferPub::alloc(cs, Some(&p));
    let ref s = CTransferSec::alloc(cs, Some(&s));

    
    let mut n_constraints = cs.borrow().num_constraints();
    let start = Instant::now();
    c_transfer(p, s, &*POOL_PARAMS);
    let duration = start.elapsed();
    n_constraints=cs.borrow().num_constraints()-n_constraints;

    println!("tx constraints = {}", n_constraints);
    println!("Time elapsed in c_transfer() is: {:?}", duration);
}


#[test]
fn test_circuit_tx_setup_and_prove() {
    fn circuit(public: CTransferPub<PoolBN256>, secret: CTransferSec<PoolBN256>) {
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





    // use super::*;
    // use crate::circuit::num::CNum;
    // use crate::circuit::poseidon::{c_poseidon_merkle_proof_root, CMerkleProof};
    // use crate::core::signal::Signal;
    // use crate::core::sizedvec::SizedVec;
    // use crate::engines::bn256::Fr;
    // use crate::native::poseidon::{poseidon_merkle_proof_root, MerkleProof, PoseidonParams};
    // use crate::typenum::U32;
    // use crate::rand::{thread_rng, Rng};
    // use ff_uint::PrimeField;

    // #[test]
    // fn test_circuit_poseidon_merkle_root() {
    //     fn circuit<Fr: PrimeField>(public: CNum<Fr>, secret: (CNum<Fr>, CMerkleProof<Fr, U32>)) {
    //         let poseidon_params = PoseidonParams::<Fr>::new(3, 8, 53);
    //         let res = c_poseidon_merkle_proof_root(&secret.0, &secret.1, &poseidon_params);
    //         res.assert_eq(&public);
    //     }
    //     let params = setup::<Bn256, _, _, _>(circuit);

    //     const PROOF_LENGTH: usize = 32;
    //     let mut rng = thread_rng();
    //     let poseidon_params = PoseidonParams::<Fr>::new(3, 8, 53);
    //     let leaf = rng.gen();
    //     let sibling = (0..PROOF_LENGTH)
    //         .map(|_| rng.gen())
    //         .collect::<SizedVec<_, U32>>();
    //     let path = (0..PROOF_LENGTH)
    //         .map(|_| rng.gen())
    //         .collect::<SizedVec<bool, U32>>();
    //     let proof = MerkleProof { sibling, path };
    //     let root = poseidon_merkle_proof_root(leaf, &proof, &poseidon_params);

    //     let (inputs, snark_proof) = prover::prove(&params, &root, &(leaf, proof), circuit);

    //     let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);
    //     assert!(res, "Verifier result should be true");
    // }

