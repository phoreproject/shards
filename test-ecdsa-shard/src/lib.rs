extern crate hex_literal;

use hex_literal::hex;

static SIGNATURE: &[u8; 65] = &hex!("1cfa7cdbd9243b99889b033e88ae2ddf55cc189efd5ae64dfa77655f01fc48e800045ec2f0dfebc7891d31b40d1ed686ca0e33c7c1b1b693e0fb305e6fc4d84a6a");

static HASH: &[u8; 32] = &hex!("3f0a377ba0a4a460ecb616f6507ce0d8cfa3e704025d4fda3ed0c5ca05468728");

static PUBKEY: [u8; 33] = hex!("02a673638cb9587cb68ea08dbef685c6f2d2a751a8b3c6f2a7e9a4999e6e4bfaf5");

#[link(wasm_import_module = "phore")]
extern {
    pub fn load(a: i64) -> i64;
    pub fn store(a: i64, val: i64);
    pub fn validateECDSA(hashAddr: &[u8; 32], signatureAddr: &[u8; 65], out: &mut[u8; 33]) -> i64;
}

#[no_mangle]
pub unsafe extern fn run() {
    let mut pubkey1 = PUBKEY;
    let mut pubkey = PUBKEY;
    let out = validateECDSA(HASH, SIGNATURE, &mut pubkey);

    if pubkey.iter().eq(PUBKEY.iter()) && out == 1 {
        store(0, 1);
    } else {
        store(0, 0);
    }
}
