extern crate hex_literal;

use hex_literal::hex;
use std::ffi;

static SIGNATURE: &[u8; 65] = &hex!("1cfa7cdbd9243b99889b033e88ae2ddf55cc189efd5ae64dfa77655f01fc48e800045ec2f0dfebc7891d31b40d1ed686ca0e33c7c1b1b693e0fb305e6fc4d84a6a");

static HASH: &[u8; 32] = &hex!("3f0a377ba0a4a460ecb616f6507ce0d8cfa3e704025d4fda3ed0c5ca05468728");

static PUBKEY: [u8; 33] = hex!("02a673638cb9587cb68ea08dbef685c6f2d2a751a8b3c6f2a7e9a4999e6e4bfaf5");

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
pub unsafe extern fn run() {
    let mut pubkey = PUBKEY;
    let out = validateECDSA(HASH, SIGNATURE, &mut pubkey);

    let to_hash = vec![1u8, 2, 3, 4];

    let hashed = hash(to_hash.as_ptr(), to_hash.len());

    store(&num_to_hash(1), &num_to_hash(hashed[0] as u64));

    if pubkey.iter().eq(PUBKEY.iter()) && out == 1 {
        store(&num_to_hash(0), &num_to_hash(1));
    } else {
        store(&num_to_hash(0), &num_to_hash(0));
    }
}
