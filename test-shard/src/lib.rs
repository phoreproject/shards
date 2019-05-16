
#[link(wasm_import_module = "phore")]
extern {
    pub fn load(a: i64) -> i64;
    pub fn store(a: i64, val: i64);
}

#[no_mangle]
pub unsafe extern fn run() {
    let a = load(0) + 1;
    store(0, a);
}
