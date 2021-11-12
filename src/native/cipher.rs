use crate::{
    fawkes_crypto::{
        ff_uint::{Num,  PrimeFieldParams, Uint, seedbox::{SeedboxBlake2, SeedBox, SeedBoxGen}},
        borsh::{BorshSerialize, BorshDeserialize},
        native::ecc::{EdwardsPoint},

    },
    native::{
        account::Account,
        note::Note,
        params::PoolParams,
        key::{derive_key_a, derive_key_p_d}
    },
    constants::{self, POLY_1305_TAG_SIZE}
};

use sha3::{Digest, Keccak256};

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};

fn keccak256(data:&[u8])->[u8;32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut res = [0u8;32];
    res.iter_mut().zip(hasher.finalize().into_iter()).for_each(|(l,r)| *l=r);
    res
}

//key stricly assumed to be unique for all messages. Using this function with multiple messages and one key is insecure!
fn symcipher_encode(key:&[u8], data:&[u8])->Vec<u8> {
    assert!(key.len()==32);
    let nonce = Nonce::from_slice(&constants::ENCRYPTION_NONCE);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.encrypt(nonce, data.as_ref()).unwrap()
}

//key stricly assumed to be unique for all messages. Using this function with multiple messages and one key is insecure!
fn symcipher_decode(key:&[u8], data:&[u8])->Option<Vec<u8>> {
    assert!(key.len()==32);
    let nonce = Nonce::from_slice(&constants::ENCRYPTION_NONCE);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(nonce, data).ok()

}



pub fn encrypt<P: PoolParams>(
    entropy: &[u8],
    eta:Num<P::Fr>,
    account: Account<P::Fr>,
    note: &[Note<P::Fr>],
    params:&P
) -> Vec<u8> {
    let nozero_notes_num = note.len();
    let nozero_items_num = nozero_notes_num+1;
    

    let mut sb = SeedboxBlake2::new_with_salt(entropy);

    let account_data = {
        let mut account_key = [0u8;32];
        sb.fill_bytes(&mut account_key);
        let account_ciphertext = symcipher_encode(&account_key, &account.try_to_vec().unwrap());
        (account_key, account_ciphertext)
    };
    
    
    let notes_data = note.iter().map(|e|{
        let a:Num<P::Fs> = sb.gen();
        let p_d = EdwardsPoint::subgroup_decompress(e.p_d, params.jubjub()).unwrap();
        let ecdh =  p_d.mul(a, params.jubjub());
        let key = keccak256(&ecdh.x.try_to_vec().unwrap());
        let ciphertext = symcipher_encode(&key, &e.try_to_vec().unwrap());
        let a_pub = derive_key_p_d(e.d.to_num(), a, params); 
        (a_pub.x, key, ciphertext)
        
    }).collect::<Vec<_>>();

    let shared_secret_data = {
        let a_p_pub = derive_key_a(sb.gen(), params);
        let ecdh = a_p_pub.mul(eta.to_other_reduced(), params.jubjub());
        let key = keccak256(&ecdh.x.try_to_vec().unwrap());
        let text:Vec<u8> = core::iter::once(&account_data.0[..]).chain(notes_data.iter().map(|e| &e.1[..])).collect::<Vec<_>>().concat();
        let ciphertext = symcipher_encode(&key, &text);
        (a_p_pub.x, ciphertext)
    };

    let mut res = vec![];

    (nozero_items_num as u32).serialize(&mut res).unwrap();
    account.hash(params).serialize(&mut res).unwrap();

    for e in note.iter() {
        e.hash(params).serialize(&mut res).unwrap();
    }
    shared_secret_data.0.serialize(&mut res).unwrap();
    res.extend(&shared_secret_data.1);

    res.extend(&account_data.1);

    notes_data.iter().for_each(|nd|{
        nd.0.serialize(&mut res).unwrap();
        res.extend(&nd.2);
    });

    res
}


fn buf_take<'a>(memo: &mut &'a[u8], size:usize) -> Option<&'a[u8]> {
    if memo.len() < size {
        None
    } else {
        let res = &memo[0..size];
        *memo = &memo[size..];
        Some(res)
    }
}

pub fn decrypt_out<P: PoolParams>(eta:Num<P::Fr>, mut memo:&[u8], params:&P)->Option<(Account<P::Fr>, Vec<Note<P::Fr>>)> {
    let fr_size = <P::Fr as PrimeFieldParams>::Inner::NUM_WORDS * <P::Fr as PrimeFieldParams>::Inner::WORD_BITS / 8;
    let account_size = fr_size +  (constants::HEIGHT + constants::BALANCE_SIZE_BITS + constants::ENERGY_SIZE_BITS + constants::DIVERSIFIER_SIZE_BITS)/8;
    let note_size = fr_size + (constants::DIVERSIFIER_SIZE_BITS + constants::BALANCE_SIZE_BITS+constants::SALT_SIZE_BITS)/8;
    let u256_size = 32;

    let nozero_items_num = u32::deserialize(&mut memo).ok()? as usize;
    if nozero_items_num == 0 {
        return None;
    }

    let nozero_notes_num = nozero_items_num - 1;
    let shared_secret_ciphertext_size = nozero_items_num * u256_size + POLY_1305_TAG_SIZE;

    let account_hash = Num::deserialize(&mut memo).ok()?;
    let note_hash = (0..nozero_notes_num).map(|_| Num::deserialize(&mut memo)).collect::<Result<Vec<_>, _>>().ok()?;

    let shared_secret_text = {
        let a_p = EdwardsPoint::subgroup_decompress(Num::deserialize(&mut memo).ok()?, params.jubjub())?;
        let ecdh = a_p.mul(eta.to_other_reduced(), params.jubjub());
        let key = keccak256(&ecdh.x.try_to_vec().unwrap());
        let ciphertext = buf_take(&mut memo, shared_secret_ciphertext_size)?;
        symcipher_decode(&key, ciphertext)?
    };
    let mut shared_secret_text_ptr =&shared_secret_text[..];

    let account_key= <[u8;32]>::deserialize(&mut shared_secret_text_ptr).ok()?;
    let note_key = (0..nozero_notes_num).map(|_| <[u8;32]>::deserialize(&mut shared_secret_text_ptr)).collect::<Result<Vec<_>,_>>().ok()?;

    let account_ciphertext = buf_take(&mut memo, account_size+POLY_1305_TAG_SIZE)?;
    let account_text = symcipher_decode(&account_key, account_ciphertext)?;
    let account = Account::try_from_slice(&account_text).ok()?;

    if account.hash(params)!= account_hash {
        return None;
    }

    let note = (0..nozero_notes_num).map(|i| {
        buf_take(&mut memo, fr_size)?;
        let ciphertext = buf_take(&mut memo, note_size+POLY_1305_TAG_SIZE)?;
        let text = symcipher_decode(&note_key[i], ciphertext)?;
        let note = Note::try_from_slice(&text).ok()?;
        if note.hash(params) != note_hash[i] {
            None
        } else {
            Some(note)
        }
    }).collect::<Option<Vec<_>>>()?;
    
    Some((account, note))
}

fn _decrypt_in<P: PoolParams>(eta:Num<P::Fr>, mut memo:&[u8], params:&P)->Option<Vec<Option<Note<P::Fr>>>> {
    let fr_size = <P::Fr as PrimeFieldParams>::Inner::NUM_WORDS * <P::Fr as PrimeFieldParams>::Inner::WORD_BITS / 8;
    let account_size = fr_size +  (constants::HEIGHT + constants::BALANCE_SIZE_BITS + constants::ENERGY_SIZE_BITS + constants::DIVERSIFIER_SIZE_BITS)/8;
    let note_size = fr_size + (constants::DIVERSIFIER_SIZE_BITS + constants::BALANCE_SIZE_BITS+constants::SALT_SIZE_BITS)/8;
    let u256_size = 32;

    let nozero_items_num = u32::deserialize(&mut memo).ok()? as usize;
    if nozero_items_num == 0 {
        return None;
    }

    let nozero_notes_num = nozero_items_num - 1;
    let shared_secret_ciphertext_size = nozero_items_num * u256_size + POLY_1305_TAG_SIZE;

    buf_take(&mut memo, fr_size)?;
    let note_hash = (0..nozero_notes_num).map(|_| Num::deserialize(&mut memo)).collect::<Result<Vec<_>, _>>().ok()?;

    buf_take(&mut memo, fr_size)?;
    buf_take(&mut memo, shared_secret_ciphertext_size)?;
    buf_take(&mut memo, account_size+POLY_1305_TAG_SIZE)?;


    let note = (0..nozero_notes_num).map(|i| {
        let a_pub = EdwardsPoint::subgroup_decompress(Num::deserialize(&mut memo).ok()?, params.jubjub())?;
        let ecdh = a_pub.mul(eta.to_other_reduced(), params.jubjub());
        let key = keccak256(&ecdh.x.try_to_vec().unwrap());

        let ciphertext = buf_take(&mut memo, note_size+POLY_1305_TAG_SIZE)?;
        let text = symcipher_decode(&key, ciphertext)?;
        let note = Note::try_from_slice(&text).ok()?;
        if note.hash(params) != note_hash[i] {
            None
        } else {
            Some(note)
        }
    }).collect::<Vec<Option<_>>>();

    Some(note)
}

pub fn decrypt_in<P: PoolParams>(eta:Num<P::Fr>, memo:&[u8], params:&P)->Vec<Option<Note<P::Fr>>> {
    if let Some(res) = _decrypt_in(eta, memo, params) {
        res
    } else {
        vec![]
    }
}
