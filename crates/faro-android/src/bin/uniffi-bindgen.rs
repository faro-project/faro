//! UniFFI's bindings generator, the version this crate's library uses
//! (`cargo run -p faro-android --features bindgen --bin uniffi-bindgen --
//! generate --library <libfaro_android.so> --language kotlin --out-dir <dir>`;
//! build-android.sh runs it).

fn main() {
    uniffi::uniffi_bindgen_main()
}
