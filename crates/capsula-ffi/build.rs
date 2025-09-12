use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    let output_dir = target_dir()
        .join("include")
        .join(&package_name);

    std::fs::create_dir_all(&output_dir).expect("Couldn't create output directory");

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .with_pragma_once(true)
        .with_include_guard("CAPSULA_FFI_H")
        .with_tab_width(4)
        .with_documentation(true)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(output_dir.join("capsula.h"));

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=build.rs");
}

fn target_dir() -> PathBuf {
    if let Ok(target) = env::var("CARGO_TARGET_DIR") {
        PathBuf::from(target)
    } else {
        PathBuf::from(env::var("OUT_DIR").unwrap())
            .ancestors()
            .nth(3)
            .unwrap()
            .to_path_buf()
    }
}