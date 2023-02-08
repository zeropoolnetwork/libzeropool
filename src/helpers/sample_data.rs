
use fawkes_crypto::{BorshSerialize, ff_uint::PrimeField};

use crate::{constants, 
    fawkes_crypto::{
        ff_uint::Num,
        native::poseidon::{poseidon, MerkleProof}, 
        rand::{self, Rng},
        core::sizedvec::SizedVec
    }, 
    native::{
        account::Account, 
        boundednum::BoundedNum, 
        note::Note, 
        params::{PoolParams}, 
        tx::{make_delta, Tx, TransferPub, TransferSec, nullifier, tx_hash, tx_sign, out_commitment_hash},
        key::{derive_key_a, derive_key_eta, derive_key_p_d},
        tree::{TreePub, TreeSec},
        delegated_deposit::{DelegatedDepositBatchPub, DelegatedDepositBatchSec, DelegatedDeposit}
    }
};

use fawkes_crypto_keccak256::native::hash::keccak256;


pub const N_ITEMS:usize = 1000;

pub struct HashTreeState<P:PoolParams> {
    pub hashes:Vec<Vec<Num<P::Fr>>>,
    pub default_hashes: Vec<Num<P::Fr>>
}

impl<P:PoolParams> HashTreeState<P> {
    pub fn new(params:&P) -> Self {
        let default_hashes = {
            std::iter::successors(Some(Num::ZERO), |t| 
                Some(poseidon([*t,*t].as_ref(), params.compress()))
            ).skip(constants::OUTPLUSONELOG).take(constants::HEIGHT - constants::OUTPLUSONELOG+1).collect()
        };
        
        let hashes = (0..constants::HEIGHT - constants::OUTPLUSONELOG+1).map(|_| vec![]).collect();

        Self {hashes, default_hashes}
    }

    pub fn push(&mut self, n:Num<P::Fr>, params:&P) {
        let mut p = self.hashes[0].len();
        self.hashes[0].push(n);

        for i in 0..constants::HEIGHT - constants::OUTPLUSONELOG {
            p >>= 1;
            if self.hashes[i+1].len() <= p {
                self.hashes[i+1].push(self.default_hashes[i+1]);
            }
            let left = self.cell(i, 2*p);
            let right = self.cell(i, 2*p+1);
            self.hashes[i+1][p] = poseidon([left, right].as_ref(), params.compress());
        }
    }

    pub fn cell(&self, i:usize, j:usize) -> Num<P::Fr> {
        if self.hashes[i].len() <= j {
            self.default_hashes[i]
        } else {
            self.hashes[i][j]
        }
    }

    pub fn merkle_proof(&self, id:usize) -> MerkleProof<P::Fr, { constants::HEIGHT - constants::OUTPLUSONELOG }> {
        let sibling = (0..constants::HEIGHT - constants::OUTPLUSONELOG).map(|i| self.cell(i, (id>>i)^1)).collect();
        let path =  (0..constants::HEIGHT - constants::OUTPLUSONELOG).map(|i| (id>>i)&1==1).collect();
        MerkleProof {sibling, path}
    }

    pub fn root(&self) -> Num<P::Fr> {
        return self.cell(constants::HEIGHT - constants::OUTPLUSONELOG, 0)
    }
}

pub struct State<P:PoolParams> {
    pub hashes:Vec<Vec<Num<P::Fr>>>,
    pub items:Vec<(Account<P::Fr>, Note<P::Fr>)>,
    pub default_hashes:Vec<Num<P::Fr>>,
    pub sigma:Num<P::Fs>,
    pub account_id:usize,
    pub note_id:Vec<usize>
}

impl<P:PoolParams> State<P> {
    pub fn random_sample_state<R:Rng>(rng:&mut R, params:&P) -> Self {
        let sigma = rng.gen();
        let a = derive_key_a(sigma, params);
        let eta = derive_key_eta(a.x, params);


        let account_id = rng.gen_range(0, N_ITEMS);
        let note_id = rand::seq::index::sample(rng, N_ITEMS, constants::IN).into_vec();


        let mut items:Vec<(Account<_>, Note<_>)> = (0..N_ITEMS).map(|_| (Account::sample(rng, params), Note::sample(rng, params) )).collect();

        for i in note_id.iter().cloned() {
            items[i].1.p_d = derive_key_p_d(items[i].1.d.to_num(), eta, params).x;
        }

        items[account_id].0.p_d = derive_key_p_d(items[account_id].0.d.to_num(), eta, params).x;
        items[account_id].0.i = BoundedNum::ZERO;

        let mut default_hashes = vec![Num::ZERO;constants::HEIGHT+1];
        let mut hashes = vec![];

        for i in 0..constants::HEIGHT {
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

        for i in 0..constants::HEIGHT {
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
            sigma,
            account_id,
            note_id
        }
    }


    pub fn random_sample_transfer<R:Rng>(&self, rng:&mut R, params:&P) -> (TransferPub<P::Fr>, TransferSec<P::Fr>) {

        let zero_note = Note {
            d: BoundedNum::ZERO,
            p_d: Num::ZERO,
            b: BoundedNum::ZERO,
            t: BoundedNum::ZERO,
        };

        let root = self.root();
        let index = N_ITEMS*2;
        let a = derive_key_a(self.sigma, params);
        let eta = derive_key_eta(a.x, params);
        let nullifier = nullifier(self.hashes[0][self.account_id*2], eta, Num::from(self.account_id as u32 * 2), params);
        let memo:Num<P::Fr> = rng.gen();

        
        let mut input_value = self.items[self.account_id].0.b.to_num();
        for &i in self.note_id.iter() {
            input_value+=self.items[i].1.b.to_num();
        }

        let mut input_energy = self.items[self.account_id].0.e.to_num();
        input_energy += self.items[self.account_id].0.b.to_num()*(Num::from((index-self.account_id*2) as u32)) ;


        for &i in self.note_id.iter() {
            input_energy+=self.items[i].1.b.to_num()*Num::from((index-(2*i+1)) as u32);
        }

        let mut out_account: Account<P::Fr> = Account::sample(rng, params);
        out_account.b = BoundedNum::new(input_value);
        out_account.e = BoundedNum::new(input_energy);
        out_account.i = BoundedNum::new(Num::from(index as u32));
        out_account.p_d = derive_key_p_d(out_account.d.to_num(), eta, params).x;

        
        let mut out_note: Note<P::Fr> = Note::sample(rng, params);
        out_note.b = BoundedNum::ZERO;

        let mut input_hashes = vec![self.items[self.account_id].0.hash(params)];
        for &i in self.note_id.iter() {
            input_hashes.push(self.items[i].1.hash(params));
        }

        let out_notes:Vec<_> = std::iter::once(out_note).chain(core::iter::repeat(zero_note).take(constants::OUT-1)).collect();
        let out_hashes:Vec<_> = std::iter::once(out_account.hash(params)).chain(out_notes.iter().map(|n| n.hash(params))).collect();
        let out_commit = out_commitment_hash(&out_hashes, params);
        let tx_hash = tx_hash(&input_hashes, out_commit, params);
        let (eddsa_s,eddsa_r) = tx_sign(self.sigma, tx_hash, params);


        let delta = make_delta::<P::Fr>(Num::ZERO, Num::ZERO, Num::from(index as u32), Num::ZERO);
        
        let p = TransferPub::<P::Fr> {
            root,
            nullifier,
            out_commit,
            delta,
            memo,  
        };



        
    
        let tx = Tx {
            input: (self.items[self.account_id].0.clone(), self.note_id.iter().map(|&i| self.items[i].1.clone()).collect()),
            output: (out_account, out_notes.iter().cloned().collect() )
        };


        
        let s = TransferSec::<P::Fr> {
            tx,
            in_proof: (
                self.merkle_proof(self.account_id*2),
                self.note_id.iter().map(|&i| self.merkle_proof(i*2+1) ).collect()
            ),
            eddsa_s:eddsa_s.to_other().unwrap(),
            eddsa_r,
            eddsa_a:a.x
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

    fn merkle_proof(&self, id:usize) -> MerkleProof<P::Fr, { constants::HEIGHT }> {
        let sibling = (0..constants::HEIGHT).map(|i| self.cell(i, (id>>i)^1)).collect();
        let path =  (0..constants::HEIGHT).map(|i| (id>>i)&1==1).collect();
        MerkleProof {sibling, path}
    }

    fn root(&self) -> Num<P::Fr> {
        return self.cell(constants::HEIGHT, 0)
    }

}


pub fn random_sample_tree_update<P:PoolParams,R:Rng>(rng:&mut R, params:&P) -> (TreePub<P::Fr>, TreeSec<P::Fr>) {
    use std::collections::HashMap;

    let index_filled:usize = rng.gen_range(0, N_ITEMS);
    let index_free = index_filled + 1;

    const PATH_LENGTH:usize = constants::HEIGHT-constants::OUTPLUSONELOG;
    
    let mut cell = HashMap::new();

    let zero_leaf_value = {
        let mut c = Num::ZERO;
        for _ in 0..constants::OUTPLUSONELOG {
            c = poseidon(&[c, c], params.compress());
        }
        c
    };

    let cell_defaults = {
        let mut c = zero_leaf_value;
        let mut res = vec![c;PATH_LENGTH+1];
        for i in 1..PATH_LENGTH {
            c = poseidon(&[c,c], params.compress());
            res[i] = c;
        }
        res
    };

    macro_rules! cell_get {
        ($h:expr, $i:expr) => { cell.get(&(($h),($i))).unwrap_or_else(||&cell_defaults[($h)]).clone() }
    }

    macro_rules! cell_set {
        ($h:expr, $i:expr, $v:expr) => { cell.insert((($h),($i)), ($v)); }
    }


    
    let prev_leaf:Num<P::Fr> = rng.gen();
    cell_set!(0, index_filled, prev_leaf);
    for h in 0..PATH_LENGTH {
        let index_level = index_filled>>h;
        if index_level & 1 == 1 {
            cell_set!(h, index_level^1, rng.gen());
        }
    }

    for h in 1..PATH_LENGTH+1 {
        let index = index_filled>>h;
        let left = cell_get!(h-1, index*2);
        let right = cell_get!(h-1, index*2+1);
        let hash = poseidon(&[left,right], params.compress());
        cell_set!(h, index, hash);
    }




    let path_filled = (0..PATH_LENGTH).map(|i| (index_filled>>i)&1==1).collect();
    let sibling_filled:SizedVec<Num<P::Fr>, PATH_LENGTH> = (0..PATH_LENGTH).map(|h| cell_get!(h, (index_filled>>h)^1 )).collect();
    

    let proof_filled = MerkleProof {
        sibling: sibling_filled,
        path: path_filled
    };

    let root_before = cell_get!(PATH_LENGTH, 0);

    let path_free = (0..PATH_LENGTH).map(|i| (index_free>>i)&1==1).collect();
    let sibling_free:SizedVec<Num<P::Fr>, PATH_LENGTH> = (0..PATH_LENGTH).map(|h| cell_get!(h, (index_free>>h)^1 )).collect();

    let leaf = rng.gen();
    cell_set!(0, index_free, leaf);

    for h in 1..PATH_LENGTH+1 {
        let index = index_free>>h;
        let left = cell_get!(h-1, index*2);
        let right = cell_get!(h-1, index*2+1);
        let hash = poseidon(&[left,right], params.compress());
        cell_set!(h, index, hash);
    }

    let root_after = cell_get!(PATH_LENGTH, 0);

    let proof_free = MerkleProof {
        sibling: sibling_free,
        path: path_free
    };

    let p = TreePub {
        root_before,
        root_after,
        leaf
    };

    let s = TreeSec {
        proof_filled,
        proof_free,
        prev_leaf
    };

    (p,s)

}

pub fn serialize_scalars_and_delegated_deposits_be<Fr:PrimeField>(scalars:&[Num<Fr>], deposits:&[DelegatedDeposit<Fr>]) -> Vec<u8> {
    deposits.iter().rev().flat_map(|d| {
        let mut res = d.b.try_to_vec().unwrap();
        res.extend(d.p_d.try_to_vec().unwrap());
        res.extend(d.d.try_to_vec().unwrap());
        res
        
    })
    .chain(scalars.iter().rev().flat_map(|s| s.try_to_vec().unwrap()))
    .rev().collect::<Vec<_>>()
}


pub fn random_sample_delegated_deposit<P:PoolParams,R:Rng>(rng:&mut R, params:&P) -> (DelegatedDepositBatchPub<P::Fr>, DelegatedDepositBatchSec<P::Fr>) {
    
    let deposits:SizedVec<_,{constants::DELEGATED_DEPOSITS_NUM}> = (0..constants::DELEGATED_DEPOSITS_NUM).map(|_| {
        let n = Note::sample(rng, params);
        DelegatedDeposit {
            d:n.d,
            p_d:n.p_d,
            b:n.b,
        }
    }).collect();

    let zero_note_hash = Note {
        d:BoundedNum::ZERO,
        p_d:Num::ZERO,
        b:BoundedNum::ZERO,
        t:BoundedNum::ZERO
    }.hash(params);

    let zero_account_hash = Account {
        d: BoundedNum::ZERO,
        p_d: Num::ZERO,
        i: BoundedNum::ZERO,
        b: BoundedNum::ZERO,
        e: BoundedNum::ZERO,
    }.hash(params);

    let out_hash = std::iter::once(zero_account_hash)
    .chain(deposits.iter().map(|d| d.to_note().hash(params)))
    .chain(std::iter::repeat(zero_note_hash)).take(constants::OUT+1).collect::<Vec<_>>();    

    let _out_commitment_hash = out_commitment_hash(&out_hash, params);

 

    let data = serialize_scalars_and_delegated_deposits_be(
        &[_out_commitment_hash], deposits.as_slice());


    
    let keccak_sum = {
        let t = keccak256(&data);
        let mut res = Num::ZERO;
        for limb in t.iter() {
            res = res * Num::from(256) + Num::from(*limb);
        }
        res
    };

    let p = DelegatedDepositBatchPub {keccak_sum};

    let s = DelegatedDepositBatchSec {
        out_commitment_hash:_out_commitment_hash,
        deposits
    };
    (p,s)

}