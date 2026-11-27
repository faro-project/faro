//! UniFFI's documented `uniffi-bindgen` binary: `build-rust.sh` runs
//! `generate --library <libfaro_mobile.a> --language swift`.
fn main() {
    uniffi::uniffi_bindgen_main()
}
