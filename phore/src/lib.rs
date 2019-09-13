#![no_std]

// Required to use the `alloc` crate and its types, the `abort` intrinsic, and a
// custom panic handler.
#![feature(core_intrinsics, lang_items, alloc_error_handler)]

#[macro_use]
extern crate alloc;

use alloc::vec::Vec;

use core::ffi;

// Use `wee_alloc` as the global allocator.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// Need to provide a tiny `panic` implementation for `#![no_std]`.
// This translates into an `unreachable` instruction that will
// raise a `trap` the WebAssembly execution if we panic at runtime.
#[panic_handler]
#[no_mangle]
pub fn panic(info: &::core::panic::PanicInfo) -> ! {
    log_message(&format!("Panic: {}", info));

    unsafe {
        ::core::intrinsics::abort();
    }
}

// Need to provide an allocation error handler which just aborts
// the execution with trap.
#[alloc_error_handler]
#[no_mangle]
pub extern "C" fn oom(_: ::core::alloc::Layout) -> ! {
    // log_message("outy");

    unsafe {
        ::core::intrinsics::abort();
    }
}

#[link(wasm_import_module = "phore")]
extern {
    fn load(addr: &[u8; 32]) -> [u8; 32];
    fn store(addr: &[u8; 32], val: &[u8; 32]);
    fn validateECDSA(hashAddr: &[u8; 32], signatureAddr: &[u8; 65], out: &mut[u8; 33]) -> i64;
    fn hash(data: *const u8, length: usize) -> [u8; 32];
    fn loadArgument(arg_num: i32, arg_len: usize, out: *mut ffi::c_void);
    fn write_log(msg: *const u8, length: usize);
    fn shard_number() -> i32;
}

type Hash = [u8; 32];
type PublicKey = [u8; 33];
type Signature = [u8; 65];

pub fn get_shard_number() -> i32 {
    let out: i32 = unsafe {
        shard_number()
    };
    return out;
}

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

pub fn load_argument(arg_num: i32, arg_size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(arg_size);
    out.resize(arg_size, 0);

    unsafe {
        loadArgument(arg_num, arg_size, out.as_ptr() as *mut ffi::c_void);
    }

    out
}

pub fn log_message(msg: &str) {
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

pub fn concat_bytes<'a>(args: &'a [&[u8]]) -> Vec<u8> {
    let total_length = args.iter().fold(0usize, |sum, val| sum + val.len());

    let mut out = Vec::with_capacity(total_length);
    for arg in args.iter() {
        out.extend_from_slice(arg);
    }

    out
}

pub fn get_storage_hash_path(path: &[&[u8]]) -> [u8; 32] {
    match path {
        [] => hash_bytes(&[0; 32]),
        [one] => hash_bytes(one),
        _ => hash_bytes(&concat_bytes(&[path[0], &get_storage_hash_path(&path[1 ..])]))
    }
}
