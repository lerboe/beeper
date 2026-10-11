use std::{ffi::OsString, path::Path};
use xbpf::build::{Builder, default_header_dir, export_headers};

fn main() {
    let include_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("include");
    println!("cargo:rerun-if-changed={}", include_dir.display());

    let hdrs = Some(vec![include_dir.clone()]);
    export_headers(hdrs, default_header_dir());

    let args = vec![OsString::from("-I"), OsString::from(include_dir)];
    Builder::new()
        .clang_arg(args.iter())
        .export_headers()
        .build();
}
