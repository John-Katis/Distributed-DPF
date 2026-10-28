//! Compiles the C++ shims (emp-ot, libOTe, SCI with its sources) and links
//! libOTe's static libraries, OpenSSL and OpenMP (SCI). The libraries live in `third_party/` at the repo root (run
//! `crates/ot-sys/fetch.sh` once), or wherever `DPF_OT_DEPS` points.

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let deps = std::env::var("DPF_OT_DEPS").map(PathBuf::from).unwrap_or_else(|_| manifest.join("../../third_party"));
    println!("cargo:rerun-if-env-changed=DPF_OT_DEPS");
    println!("cargo:rerun-if-changed=cpp/emp_shim.cpp");
    println!("cargo:rerun-if-changed=cpp/ote_shim.cpp");
    println!("cargo:rerun-if-changed=cpp/sci_shim.cpp");
    println!("cargo:rerun-if-changed=cpp/sci_override");
    let sci = deps.join("EzPC/SCI/src");
    let need = [
        deps.join("emp-ot/emp-ot/emp-ot.h"),
        deps.join("libOTe/out/build/linux/libOTe/liblibOTe.a"),
        sci.join("OT/split-kkot.h"),
    ];
    for p in &need {
        assert!(p.exists(), "{} is missing: run crates/ot-sys/fetch.sh", p.display());
    }

    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .opt_level(3)
        .flag("-march=native")
        .flag("-w")
        .include(deps.join("emp-tool"))
        .include(deps.join("emp-ot"))
        .file("cpp/emp_shim.cpp")
        .compile("dpf_emp_shim");

    let l = deps.join("libOTe");
    let b = l.join("out/build/linux");
    cc::Build::new()
        .cpp(true)
        .std("c++20")
        .opt_level(3)
        .define("NDEBUG", None)
        .define("CRYPTOTOOLS_EDWARDS25519_ASM", "1")
        .flag("-march=native")
        .flag("-w")
        .include(&l)
        .include(&b)
        .include(l.join("cryptoTools"))
        .include(b.join("cryptoTools"))
        .include(l.join("out/coproto"))
        .include(b.join("coproto"))
        .include(l.join("out/macoro"))
        .include(b.join("macoro"))
        .flag(format!("-isystem{}", l.join("out/install/linux/include").display()))
        .file("cpp/ote_shim.cpp")
        .compile("dpf_ote_shim");

    // SCI, with our NetIO/IOPack first on the include path. The sources are
    // those the shim needs: the auxiliary protocols and what they reference.
    let mut b2 = cc::Build::new();
    b2.cpp(true)
        .std("c++17")
        .opt_level(3)
        .flag("-march=native")
        .flag("-fopenmp")
        .flag("-w")
        .include(manifest.join("cpp/sci_override"))
        .include(&sci)
        .file("cpp/sci_shim.cpp");
    for f in [
        "BuildingBlocks/aux-protocols.cpp",
        "BuildingBlocks/truncation.cpp",
        "BuildingBlocks/value-extension.cpp",
        "GC/emp-tool.cpp",
        "GC/halfgate_gen.cpp",
        "GC/halfgate_eva.cpp",
    ] {
        b2.file(sci.join(f));
    }
    b2.compile("dpf_sci_shim");

    for (dir, lib) in [
        (b.join("libOTe"), "libOTe"),
        (b.join("cryptoTools/cryptoTools"), "cryptoTools"),
        (b.join("coproto/coproto"), "coproto"),
        (b.join("macoro/macoro"), "macoro"),
    ] {
        println!("cargo:rustc-link-search=native={}", dir.display());
        println!("cargo:rustc-link-lib=static={lib}");
    }
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=gomp");
    println!("cargo:rustc-link-lib=stdc++");
}
