use std::ffi;
use std::fmt::Write;

#[link(wasm_import_module = "phore")]
extern {
    pub fn load(addr: &[u8; 32]) -> [u8; 32];
    pub fn store(addr: &[u8; 32], val: &[u8; 32]);
    pub fn validateECDSA(hashAddr: &[u8; 32], signatureAddr: &[u8; 65], out: &mut[u8; 33]) -> i64;
    pub fn hash(data: *const u8, length: usize) -> [u8; 32];
    pub fn loadArgument(arg_num: i32, out: *mut ffi::c_void);
    pub fn write_log(msg: *const u8, length: usize);
}

pub fn hash_to_num(hash: &[u8; 32]) -> u64 {
    u64::from_be_bytes([hash[24], hash[25], hash[26], hash[27], hash[28], hash[29], hash[30], hash[31]])
}

pub fn num_to_hash(num: u64) -> [u8; 32] {
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ((num >> 56) & 0xFF) as u8, ((num >> 48) & 0xFF) as u8, ((num >> 40) & 0xFF) as u8, ((num >> 32) & 0xFF) as u8,
    ((num >> 24) & 0xFF) as u8, ((num >> 16) & 0xFF) as u8, ((num >> 8) & 0xFF) as u8, (num & 0xFF) as u8]
}

pub unsafe fn load64(addr: &[u8; 32]) -> u64 {
    return hash_to_num(&load(addr));
}

pub unsafe fn log_message(msg: String) {
    write_log(msg.as_ptr(), msg.len());
}

#[no_mangle]
pub unsafe extern fn transfer_to_address() -> u64 {
    let mut from_pubkey: [u8; 33] = [0; 33];
    loadArgument(0, from_pubkey.as_mut_ptr() as *mut ffi::c_void);

    let mut signature: [u8; 65] = [0; 65];
    loadArgument(1, signature.as_mut_ptr() as *mut ffi::c_void);

    let mut to_pubkey_hash: [u8; 32] = [0; 32];
    loadArgument(2, to_pubkey_hash.as_mut_ptr() as *mut ffi::c_void);

    let mut amount_bytes: [u8; 8] = [0; 8];
    loadArgument(3, amount_bytes.as_mut_ptr() as *mut ffi::c_void);

    let amount = u64::from_be_bytes(amount_bytes);

    let from_pubkey_hash = hash(from_pubkey.as_ptr(), 33);

    let mut message_to_sign = format!("transfer {} PHR to ", amount);

    for &byte in &to_pubkey_hash {
        write!(&mut message_to_sign, "{:02x}", byte).ok();
    }

    let message_hash = hash(message_to_sign.as_ptr(), message_to_sign.len());

    let expected_pubkey: &mut[u8; 33] = &mut [0; 33];

    let signature_output = validateECDSA(&message_hash, &signature, expected_pubkey);

    if signature_output != 0 || !expected_pubkey.iter().eq(from_pubkey.iter()) {
        return 1;
    }

    let old_balance = hash_to_num(&load(&from_pubkey_hash));

    if old_balance < amount {
        return 2;
    }

    let new_balance = old_balance - amount;

    let balance_hash = num_to_hash(new_balance);

    store(&from_pubkey_hash, &balance_hash);

    let to_balance = hash_to_num(&load(&to_pubkey_hash));

    let to_balance_hash = num_to_hash(to_balance + amount);

    store(&to_pubkey_hash, &to_balance_hash);

    return 0;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
