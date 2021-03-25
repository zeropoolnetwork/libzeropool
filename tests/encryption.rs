use libzeropool::{POOL_PARAMS, native::{params::PoolBN256, tx::{derive_key_adk, derive_key_dk, derive_key_sdk}}};

use libzeropool::fawkes_crypto::rand::{thread_rng, Rng};
use libzeropool::native::{
    note::Note,
    account::Account,
    tx::{derive_key_pk_d},
    cypher
};


#[test]
fn test_encryption() {
    let mut rng = thread_rng();
    let sender_xsk = rng.gen();
    let sender_sdk = derive_key_sdk(sender_xsk, &*POOL_PARAMS);
    let sender_adk = derive_key_adk(sender_xsk, &*POOL_PARAMS);

    let receiver_xsk = rng.gen();
    let receiver_dk = derive_key_dk(receiver_xsk, &*POOL_PARAMS);


    let mut account: Account<PoolBN256> = rng.gen();
    let mut note: Note<PoolBN256> = rng.gen();
    
    account.xsk = sender_xsk;
    note.pk_d = derive_key_pk_d(note.d.as_num().clone(), receiver_dk, &*POOL_PARAMS).x;
    

    let esk = rng.gen();

    let data = cypher::encrypt(esk, sender_sdk, sender_adk, (account.clone(), note.clone()), &*POOL_PARAMS);

    let decr_in = cypher::decrypt_in(receiver_dk, &data, &*POOL_PARAMS);
    assert!(decr_in.is_some(), "Could not decrypt incoming data");
    assert!(decr_in.unwrap()==note, "Wrong note decryption");

    let decr_out = cypher::decrypt_out(sender_xsk, sender_adk, sender_sdk, &data, &*POOL_PARAMS);
    assert!(decr_out.is_some(), "Could not decrypt outgoing data.");
    let (decr_account, decr_note) = decr_out.unwrap();
    assert!(decr_account==account && decr_note==note, "Wrong (account, note) decryption.");

}