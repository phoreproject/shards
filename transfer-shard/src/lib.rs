extern crate phore;

use std::fmt::Write;

use phore::load_argument;
use phore::hash_bytes;
use phore::validate_ecdsa;
use phore::hash_to_num;
use phore::num_to_hash;
use phore::load_from_storage;
use phore::save_to_storage;

#[no_mangle]
pub extern fn transfer_to_address() -> u64 {
    let mut from_pubkey: [u8; 33] = [0; 33];
    from_pubkey.copy_from_slice(&load_argument(0, 33));
    let mut signature: [u8; 65] = [0; 65];
    signature.copy_from_slice(&load_argument(1, 65));
    let mut to_pubkey_hash: [u8; 32] = [0; 32];
    to_pubkey_hash.copy_from_slice(&load_argument(2, 32));
    let mut amount_bytes: [u8; 8] = [0; 8];
    amount_bytes.copy_from_slice(&load_argument(3, 8));

    let amount = u64::from_be_bytes(amount_bytes);

    let from_pubkey_hash = hash_bytes(&from_pubkey);

    let mut message_to_sign = format!("transfer {} PHR to ", amount);
    for &byte in to_pubkey_hash.iter() {
        write!(&mut message_to_sign, "{:02x}", byte).ok();
    }

    let message_hash = hash_bytes(message_to_sign.as_bytes());

    let (signature_output, expected_pubkey) = validate_ecdsa(message_hash, signature);

    if signature_output != 0 || !expected_pubkey.iter().eq(from_pubkey.iter()) {
        return 1;
    }

    let old_balance = hash_to_num(load_from_storage(from_pubkey_hash));

    if old_balance < amount {
        return 2;
    }

    let new_balance = old_balance - amount;

    let balance_hash = num_to_hash(new_balance);

    save_to_storage(from_pubkey_hash, balance_hash);

    let to_balance = hash_to_num(load_from_storage(to_pubkey_hash));

    let to_balance_hash = num_to_hash(to_balance + amount);

    save_to_storage(to_pubkey_hash, to_balance_hash);

    return 0;
}
