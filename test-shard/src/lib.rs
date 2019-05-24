use std::ffi;


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
    let a = hash_to_num(&load(&num_to_hash(0))) + 1;
    store(&num_to_hash(0), &num_to_hash(a));
}
