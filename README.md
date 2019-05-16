# Shards

This repository will hold code for all of the shard types Phore develops.

## Building

Go into one of the shard directories and run:

```bash
cargo build --target wasm32-unknown-unknown
```

The result will be in: `target/debug/*_shard.wasm`.

## Building for Release

For release, we optimize the wasm file for size by running:

```bash
cargo build --release --target wasm32-unknown-unknown
```

The result will be in: `target/release/*_shard.wasm`.

To strip the resulting wasm files of the wasm file, install the [wabt](https://github.com/WebAssembly/wabt) package run:

```bash
wasm-strip target/wasm32-unknown-unknown/release/*_shard.wasm
```

## Importing Phore functions

To import functions from the Phore package, add this to the top of any shard code:

```rust
#[link(wasm_import_module = "phore")]
extern {
    pub fn load(a: i64) -> i64;
    pub fn store(a: i64, val: i64);
    pub fn validateECDSA(hashAddr: &[u8; 32], signatureAddr: &[u8; 65], out: &mut[u8; 33]) -> i64;
    pub fn hash(data: *const u8, length: usize) -> [u8; 32];
}
```
