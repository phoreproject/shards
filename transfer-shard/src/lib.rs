#![no_std]

extern crate wee_alloc;

extern crate alloc;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate hex_literal;

extern crate phore;

use phore::*;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

lazy_static!{
    static ref PREMINE: BTreeMap<[u8; 20], u64> = [
        (hex!("ff6faaf7b1ca750f7d76fc2c739e34e4cb8e3599"), 100000000),
    ].iter().copied().collect();
}

fn bytes_to_u64(b: &[u8]) -> u64 {
    if b.len() != 8 {
        panic!("bytes_to_u64 called with improper size")
    }

    return u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[no_mangle]
pub extern fn redeem_premine() -> u64 {
    // load the user's address
    let mut to_pubkey_hash: [u8; 20] = [0; 20];
    to_pubkey_hash.copy_from_slice(&load_argument(0, 20));

    // ensure the user has a premined balance
    if !PREMINE.contains_key(&to_pubkey_hash) {
        return 1;
    }

    // get the status of the redemption at "redeem/{ADDRESS}"
    let redemption_path = get_storage_hash_path(&[b"redeem", &to_pubkey_hash]);
    let redemption_status = hash_to_num(load_from_storage(redemption_path));

    // ensure it isn't redeemed
    if redemption_status != 0 {
        return 2;
    }

    // get the user's balance
    let to_balance_path = get_storage_hash_path(&[b"balance", &to_pubkey_hash]);
    let old_balance = hash_to_num(load_from_storage(to_balance_path));

    // add to the user's balance
    let redemption_amount = PREMINE.get(&to_pubkey_hash).unwrap();
    save_to_storage(to_balance_path, num_to_hash(old_balance + redemption_amount));

    // mark the premine as redeemed
    save_to_storage(redemption_path, num_to_hash(1));

    return 0;
}

#[no_mangle]
pub extern fn transfer_to_address() -> u64 {
    // transaction data including: version, amount, nonce, to_pubkey_hash
    let mut tx_data: [u8; 33] = [0; 33];
    let test = &load_argument(0, 33);
    tx_data.copy_from_slice(test);

    // signature of hash of tx_data
    let mut signature: [u8; 65] = [0; 65];
    signature.copy_from_slice(&load_argument(1, 65));

    // from_pubkey_hash: sender's address
    let mut from_pubkey_hash: [u8; 20] = [0; 20];
    from_pubkey_hash.copy_from_slice(&load_argument(2, 20));

    // from_storage_nonces is the storage address where the nonce for the transaction is kept. If it's not 0, we
    // know that the nonce is already used and we should reject the transaction.
    let from_storage_nonces: [u8; 32] = get_storage_hash_path(&[b"nonce", &from_pubkey_hash, &tx_data[1 .. 5]]);

    let nonce_used = hash_to_num(load_from_storage(from_storage_nonces));
    if nonce_used != 0 {
        return 1;
    }

    // extract the hash of the pubkey we're sending to
    let to_pubkey_hash = &tx_data[5 .. 25];

    // extract the amount we're sending
    let amount = bytes_to_u64(&tx_data[25 .. 33]);

    // get the hash of the transaction data which should be the message signed
    let message_hash = hash_bytes(&tx_data);

    // recover the public key from the message and signature. This is cryptographically secure as long as
    // an attacker can't efficiently generate a signature such that they can predict the public key. This is
    // the case as long as message_hash is a random oracle (like a hash)
    let (signature_output, expected_pubkey) = validate_ecdsa(message_hash, signature);

    // ensure the signature validates
    if signature_output != 0 {
        return 2;
    }

    // get the shard number being executed
    let shard_bytes = i32::to_be_bytes(get_shard_number());

    // calculate the expected address given the recovered public key and the shard number
    let mut expected_pubkey_and_shard = Vec::with_capacity(37);
    expected_pubkey_and_shard.extend_from_slice(&shard_bytes);
    expected_pubkey_and_shard.extend_from_slice(&expected_pubkey);
    let expected_pubkey_hash = hash_bytes(expected_pubkey_and_shard.as_slice());

    // verify the expected address matches the given address
    if !expected_pubkey_hash[0 .. 20].iter().eq(from_pubkey_hash.iter()) {
        return 3;
    }

    // get the storage addresses of the sender and recipient
    let from_storage: [u8; 32] = get_storage_hash_path(&[b"balance", &from_pubkey_hash]);
    let to_storage: [u8; 32] = get_storage_hash_path(&[b"balance", &to_pubkey_hash]);

    // ensure the user has sufficient balance
    let old_balance = hash_to_num(load_from_storage(from_storage));
    if old_balance < amount {
        return 4;
    }

    // update the sender's balance
    save_to_storage(from_storage, num_to_hash(old_balance - amount));

    // mark the nonce as used
    save_to_storage(from_storage_nonces, num_to_hash(1));

    // update the recipient's balance
    let to_balance = hash_to_num(load_from_storage(to_storage));
    save_to_storage(to_storage, num_to_hash(to_balance + amount));

    return 0;
}
