use crate::{
    fawkes_crypto::{
        ff_uint::{Num, PrimeField},
        borsh::{BorshSerialize, BorshDeserialize},
        native::ecc::{EdwardsPoint}
    },
    native::{
        account::Account,
        note::Note,
        params::PoolParams,
        tx::{derive_key_pk_d}
    },
    constants::{CHECKSUM_SIZE, ACCOUNT_SIZE, NOTE_SIZE, COMMITMENT_TOTAL_SIZE, NUM_SIZE}
};

use sha3::{Digest, Keccak256};


fn xor_crypt<D: Digest + Clone>(prefix: &D, data: &[u8]) -> Vec<u8> {
    let mut mask = vec![];

    for i in 0..(data.len() - 1) / 32 + 1 {
        let mut m = prefix.clone();
        m.update([i as u8]);
        mask.extend(m.finalize());
    }
    data.iter().zip(mask.iter()).map(|(&d, &m)| d ^ m).collect()
}

fn dh_prefix<Fr: PrimeField>(dh_x: Num<Fr>) -> Keccak256 {
    let mut res = Keccak256::new();
    res.update(dh_x.try_to_vec().unwrap());
    res
}

fn checksum(buf:&[u8])->Vec<u8> {
    let mut h = Keccak256::new();
    h.update(buf);
    h.finalize().into_iter().take(CHECKSUM_SIZE).collect()
}

fn checksum_filter(buf:&[u8]) -> Option<&[u8]> {
    let l = buf.len();
    if l < CHECKSUM_SIZE {
        None
    } else {
        let cs = checksum(&buf[0..l-CHECKSUM_SIZE]);
        if cs.iter().zip(buf[l-CHECKSUM_SIZE..l].iter()).any(|(&a, &b)| a != b) {
            None
        } else {
            Some(&buf[0..l-CHECKSUM_SIZE])
        }
    }
}


pub fn encrypt<P: PoolParams>(
    esk: Num<P::Fs>,
    sdk: Num<P::Fs>,
    adk: Num<P::Fs>,
    item: (Account<P::Fr>, Note<P::Fr>),
    params: &P,
) -> Vec<u8> {
    let pk_d = EdwardsPoint::subgroup_decompress(item.1.pk_d, params.jubjub()).unwrap();
    let dh_note = pk_d.mul(esk, params.jubjub());
    let receiver_epk = derive_key_pk_d(item.1.d.to_num(), esk, params);
    let sender_epk = dh_note.mul(sdk.checked_inv().unwrap(), params.jubjub());
    let dh_account = sender_epk.mul(adk, params.jubjub());

    let mut account_vec = item.0.try_to_vec().unwrap();
    account_vec.extend(checksum(&account_vec));
    let account_vec_enc = xor_crypt(&dh_prefix(dh_account.x), &account_vec);

    let mut note_vec = item.1.try_to_vec().unwrap();
    note_vec.extend(checksum(&note_vec));
    let note_vec_enc = xor_crypt(&dh_prefix(dh_note.x), &note_vec);
    
    let mut res = vec![];
    res.extend(receiver_epk.x.try_to_vec().unwrap());
    res.extend(sender_epk.x.try_to_vec().unwrap());
    res.extend(account_vec_enc);
    res.extend(note_vec_enc);
    res
}

fn decrypt<P: PoolParams>(
    dk: Num<P::Fs>,
    epk: Num<P::Fr>,
    data: &[u8],
    params: &P,
) -> Option<Vec<u8>> {
    let epk = EdwardsPoint::subgroup_decompress(epk, params.jubjub())?;
    let dh = epk.mul(dk, params.jubjub());

    let prefix = dh_prefix(dh.x);
    let v = xor_crypt(&prefix, data);

    Some(checksum_filter(&v)?.to_vec())
}




pub fn decrypt_in<P: PoolParams>(
    dk: Num<P::Fs>,
    msg_data: &[u8],
    params: &P,
) -> Option<Note<P::Fr>> {
    if msg_data.len() != COMMITMENT_TOTAL_SIZE {
        None
    } else {
        let receiver_epk = Num::try_from_slice(&msg_data[0..NUM_SIZE]).ok()?;
        let decr = decrypt(dk, receiver_epk, &msg_data[COMMITMENT_TOTAL_SIZE - NOTE_SIZE - CHECKSUM_SIZE..], params)?;
        let note = Note::try_from_slice(&decr).ok()?;
        if derive_key_pk_d(note.d.to_num(), dk, params).x != note.pk_d {
            None
        } else {
            Some(note)
        }
    }
}

pub fn decrypt_out<P: PoolParams>(
    xsk: Num<P::Fr>,
    adk: Num<P::Fs>,
    sdk: Num<P::Fs>,
    msg_data: &[u8],
    params: &P,
) -> Option<(Account<P::Fr>, Note<P::Fr>)> {
    if msg_data.len() != COMMITMENT_TOTAL_SIZE {
        None
    } else {
        let sender_epk = Num::try_from_slice(&msg_data[NUM_SIZE..2*NUM_SIZE]).ok()?;
        let decr_account = decrypt(adk, sender_epk, &msg_data[2*NUM_SIZE..2*NUM_SIZE+ACCOUNT_SIZE+CHECKSUM_SIZE], params)?;
        let decr_note = decrypt(sdk, sender_epk, &msg_data[COMMITMENT_TOTAL_SIZE - NOTE_SIZE - CHECKSUM_SIZE..], params)?;
        let account = Account::try_from_slice(&decr_account).ok()?;
        let note = Note::try_from_slice(&decr_note).ok()?;
        if account.xsk != xsk {
            None
        } else {
            Some((account, note))
        }
    }
}