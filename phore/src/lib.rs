use std::ffi;

#[link(wasm_import_module = "phore")]
extern {
    fn load(addr: &[u8; 32]) -> [u8; 32];
    fn store(addr: &[u8; 32], val: &[u8; 32]);
    fn validateECDSA(hashAddr: &[u8; 32], signatureAddr: &[u8; 65], out: &mut[u8; 33]) -> i64;
    fn hash(data: *const u8, length: usize) -> [u8; 32];
    fn loadArgument(arg_num: i32, out: *mut ffi::c_void);
    fn write_log(msg: *const u8, length: usize);
}

type Hash = [u8; 32];
type PublicKey = [u8; 33];
type Signature = [u8; 65];

pub fn load_from_storage(addr: Hash) -> Hash {
    let out: Hash = unsafe {
        load(&addr)
    };
    return out;
}

pub fn save_to_storage(addr: Hash, val: Hash) {
    unsafe {
        store(&addr, &val);
    }
}

pub fn validate_ecdsa(hash: Hash, signature: Signature) -> (i64, PublicKey) {
    let mut public_key: PublicKey = [0; 33];

    let output = unsafe {
        validateECDSA(&hash, &signature, &mut public_key)
    };

    return (output, public_key);
}

pub fn hash_bytes(to_hash: &[u8]) -> [u8; 32] {
    let out_hash = unsafe {
        hash(to_hash.as_ptr(), to_hash.len())
    };

    out_hash
}

pub fn load_argument(arg_num: i32, arg_size: usize) -> Box<[u8]> {
    let out = vec![0; arg_size];

    unsafe {
        loadArgument(arg_num, out.as_ptr() as *mut ffi::c_void);
    }

    return out.into_boxed_slice();
}

pub fn log_message(msg: String) {
    unsafe {
        write_log(msg.as_ptr(), msg.len());
    }
}

pub fn hash_to_num(hash: Hash) -> u64 {
    u64::from_be_bytes([hash[24], hash[25], hash[26], hash[27], hash[28], hash[29], hash[30], hash[31]])
}

pub fn num_to_hash(num: u64) -> Hash {
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ((num >> 56) & 0xFF) as u8, ((num >> 48) & 0xFF) as u8, ((num >> 40) & 0xFF) as u8, ((num >> 32) & 0xFF) as u8,
    ((num >> 24) & 0xFF) as u8, ((num >> 16) & 0xFF) as u8, ((num >> 8) & 0xFF) as u8, (num & 0xFF) as u8]
}
