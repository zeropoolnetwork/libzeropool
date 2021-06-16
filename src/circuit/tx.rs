use fawkes_crypto::circuit::{
    bitify::{c_into_bits_le, c_into_bits_le_strict, c_comp, c_from_bits_le},
    bool::CBool,
    eddsaposeidon::c_eddsaposeidon_verify,
    num::CNum,
    poseidon::{c_poseidon_merkle_proof_root, c_poseidon, c_poseidon_merkle_tree_root, c_poseidon_sponge, CMerkleProof},
    cs::{RCS, CS}
};
use fawkes_crypto::core::{signal::Signal, sizedvec::SizedVec,};
use fawkes_crypto::ff_uint::{Num, NumRepr};
use crate::circuit::{account::CAccount, note::CNote, key::{c_derive_key_eta, c_derive_key_p_d}};
use crate::native::tx::{TransferPub, TransferSec, Tx};
use crate::native::params::PoolParams;
use crate::constants::{HEIGHT, IN, OUT, BALANCE_SIZE, ENERGY_SIZE};


#[derive(Clone, Signal)]
#[Value = "TransferPub<C::Fr>"]
pub struct CTransferPub<C:CS> {
    pub root: CNum<C>,
    pub nullifier: CNum<C>,
    pub out_commit: CNum<C>,
    pub delta: CNum<C>, // int64 token delta, int96 energy delta, uint32 blocknumber
    pub memo: CNum<C>,
}

#[derive(Clone, Signal)]
#[Value = "Tx<C::Fr>"]
pub struct CTx<C:CS> {
    pub input: (CAccount<C>, SizedVec<CNote<C>, { IN }>),
    pub output: (CAccount<C>, SizedVec<CNote<C>, { OUT}>)
}

#[derive(Clone, Signal)]
#[Value = "TransferSec<C::Fr>"]
pub struct CTransferSec<C:CS> {
    pub tx: CTx<C>,
    pub in_proof: (CMerkleProof<C, { HEIGHT }>, SizedVec<CMerkleProof<C, { HEIGHT }>, { IN }>),
    pub eddsa_s: CNum<C>,
    pub eddsa_r: CNum<C>,
    pub eddsa_a: CNum<C>,
}

pub fn c_nullfifier<C:CS, P: PoolParams<Fr = C::Fr>>(
    in_account_hash: &CNum<C>,
    eta: &CNum<C>,
    params: &P,
) -> CNum<C> {
    c_poseidon(
        [in_account_hash.clone(), eta.clone()].as_ref(),
        params.compress(),
    )
}

pub fn c_tx_hash<C:CS, P: PoolParams<Fr = C::Fr>>(
    in_hash: &[CNum<C>],
    out_commitment: &CNum<C>,
    params: &P,
) -> CNum<C> {
    let data = in_hash.iter().chain(core::iter::once(out_commitment)).cloned().collect::<Vec<_>>();
    c_poseidon_sponge(&data, params.sponge())
}

pub fn c_tx_verify<C:CS, P: PoolParams<Fr = C::Fr>>(
    s: &CNum<C>,
    r: &CNum<C>,
    a: &CNum<C>,
    tx_hash: &CNum<C>,
    params: &P,
) -> CBool<C> {
    c_eddsaposeidon_verify(s, r, a, tx_hash, params.eddsa(), params.jubjub())
}


pub fn c_out_commitment_hash<C:CS, P:PoolParams<Fr=C::Fr>>(items:&[CNum<C>], params: &P) -> CNum<C> {
    assert!(items.len()==OUT+1);
    c_poseidon_merkle_tree_root(items, params.compress())
}

pub fn c_parse_delta<C:CS, P:PoolParams<Fr=C::Fr>>(delta: &CNum<C>) -> (CNum<C>, CNum<C>, CNum<C>) {
    let cv = BALANCE_SIZE;
    let ce = ENERGY_SIZE;
    let ch = HEIGHT;
    let delta_bits = c_into_bits_le(delta, cv+ce+ch);

    let v = c_from_bits_le(&delta_bits[0..cv]) - &delta_bits[cv-1].to_num() * Num::from_uint(NumRepr::ONE << cv as u32).unwrap();
    let e = c_from_bits_le(&delta_bits[cv..cv+ce]) - &delta_bits[cv+ce-1].to_num() * Num::from_uint(NumRepr::ONE << ce as u32).unwrap();
    let index = c_from_bits_le(&delta_bits[cv+ce..cv+ce+ch]);

    (v, e, index)
}



pub fn c_transfer<C:CS, P:PoolParams<Fr=C::Fr>>(
    p: &CTransferPub<C>,
    s: &CTransferSec<C>,
    params: &P,
) {
    //parse delta
    let (delta_value, delta_energy, current_index) = c_parse_delta::<C,P>(&p.delta);
    let mut total_value = delta_value;
    let mut total_enegry = delta_energy;

    let input_index = s.tx.input.0.i.as_num();
    let output_index = s.tx.output.0.i.as_num();
    
    
    //build input hashes
    let in_account_hash = s.tx.input.0.hash(params);
    let in_note_hash = s.tx.input.1.iter().map(|n| n.hash(params)).collect::<Vec<_>>();
    let in_hash = [[in_account_hash.clone()].as_ref(), in_note_hash.as_slice()].concat();

    //assert input notes are unique
    let mut t:CNum<C> = p.derive_const(&Num::ZERO);
    for i in 0..OUT {
        for j in i+1..OUT {
            t+=(&in_note_hash[i]-&in_note_hash[j]).is_zero().as_num();
        }
    }
    t.assert_zero();



    //build output hashes
    let out_account_hash = s.tx.output.0.hash(params);
    let out_note_hash = s.tx.output.1.iter().map(|e| e.hash(params)).collect::<Vec<_>>();
    let out_hash = [[out_account_hash].as_ref(), out_note_hash.as_slice()].concat();

    //assert out notes are unique or zero
    let mut t:CNum<C> = p.derive_const(&Num::ZERO);
    let mut out_note_zero_num:CNum<C> = p.derive_const(&Num::ZERO);
    for i in 0..OUT {
        out_note_zero_num+=s.tx.output.1[i].is_zero().as_num();
        for j in i+1..OUT {
            t+=(&out_note_hash[i]-&out_note_hash[j]).is_zero().as_num();
        }
    }
    t -= &out_note_zero_num*(&out_note_zero_num-Num::ONE)/Num::from(2u64);
    t.assert_zero();

    //check output     
    let out_ch = c_out_commitment_hash(&out_hash, params);
    (&out_ch - &p.out_commit).assert_zero();


    //build decryption key
    let eta = c_derive_key_eta(&s.eddsa_a, params);
    let eta_bits = c_into_bits_le_strict(&eta);

    //check ownership
    (&s.tx.input.0.eta - &eta).assert_zero();
    (&s.tx.output.0.eta - &eta).assert_zero();

    for i in 0..IN {
        (&s.tx.input.1[i].p_d - c_derive_key_p_d(&s.tx.input.1[i].d.as_num(), &eta_bits, params).x).assert_zero();
    }

    //check nullifier
    (&p.nullifier - c_nullfifier(&in_account_hash, &eta, params)).assert_zero();


    //build merkle proofs
    {
        let cur_root = c_poseidon_merkle_proof_root(&in_account_hash, &s.in_proof.0, params.compress());
        //assert root == cur_root || account.is_dummy()
        ((cur_root - &p.root) * s.tx.input.0.is_dummy_raw()).assert_zero();

        //output_index > input_index
        c_comp(output_index, input_index, HEIGHT).assert_const(&true);

        //output_index <= current_index
        c_comp(output_index, &current_index, HEIGHT).assert_const(&false);

        //compute enegry
        total_enegry += s.tx.input.0.b.as_num() * (output_index- input_index);
    }

    //let account_index = c_from_bits_le(s.in_proof.0.path.as_slice());

    for i in 0..IN {
        let note_value = s.tx.input.1[i].b.as_num();
        let ref note_index = c_from_bits_le(s.in_proof.1[i].path.as_slice());

        let cur_root = c_poseidon_merkle_proof_root(&in_note_hash[i], &s.in_proof.1[i], params.compress());
        ((cur_root - &p.root) * note_value).assert_zero();

        //note_index >= account_in.interval && note_index < account_out.interval || note_index == 0 && value == 0

        //input_index <= note_index && note_index < output_index || note_is_dummy
        let note_index_ok = (!c_comp(input_index, note_index, HEIGHT)) & c_comp(output_index, note_index, HEIGHT);
        let note_dummy = s.tx.input.1[i].is_dummy_raw().is_zero();
        (note_index_ok | note_dummy).assert_const(&true);

        //compute enegry
        total_enegry += note_value * (output_index - note_index);
    }

    //bind msg_hash to the circuit
    (&p.memo + Num::ONE).assert_nonzero();

    //build tx hash
    let tx_hash = c_tx_hash(&in_hash, &out_ch, params);

    //check signature
    c_tx_verify(&s.eddsa_s, &s.eddsa_r, &s.eddsa_a, &tx_hash, params).assert_const(&true);

    //check balances
    total_value += s.tx.input.0.b.as_num() - s.tx.output.0.b.as_num();

    for note in s.tx.input.1.iter() {
        total_value += note.b.as_num();
    }

    for note in s.tx.output.1.iter() {
        total_value -= note.b.as_num();
    }

    total_value.assert_zero();

    //final check energy
    total_enegry += s.tx.input.0.e.as_num();
    total_enegry -= s.tx.output.0.e.as_num();
    total_enegry.assert_zero();

}

