use std::path::Path;
use yaml_serde::{Value, from_reader};
use std::fs::{File, OpenOptions};
use std::io::Write;


fn write_output_file(spec_path: &Path, prefix: &str, out_path: &Path) {
    let Value::Mapping(m) = from_reader(File::open(spec_path).expect("failed to open luckperms openapi spec")).expect("Failed to parse") else {
        panic!("invalid openapi schema");
    };

    let Some(Value::Mapping(m2)) = m.get("paths") else {
        panic!("key \"paths\" did not exist in openapi spec");
    };


    let lp_paths: String = m2.keys().map(|x| match x {
        Value::String(s) => format!("\"{prefix}{s}\""),
        _ => panic!("openapi path was not a string")
    }).collect::<Vec<String>>().join(",\n");


    let mut lp_paths_str = String::new();

    lp_paths_str.push_str("[\n");
    lp_paths_str.push_str(&lp_paths);
    lp_paths_str.push_str("\n]");

    let mut lp_f = OpenOptions::new().create(true).write(true).truncate(true).open(out_path).expect("failed to open file");
    lp_f.write_all(lp_paths_str.as_bytes()).expect("failed to write paths");
}

fn main() {
    let out = std::env::var("OUT_DIR").expect("Failed to find env var OUT_DIR");
    let lp_path = std::env::var("LUCKPERMS_OPENAPI_SPEC").expect("could not find LUCKPERMS_OPENAPI_SPEC");
    let ak_path = std::env::var("AUTHENTIK_OPENAPI_SPEC").expect("could not find AUTHENTIK_OPENAPI_SPEC");

    write_output_file(&Path::new(&lp_path), "", &Path::new(&out).join("luckperms_paths"));
    write_output_file(&Path::new(&ak_path), "/api/v3", &Path::new(&out).join("authentik_paths"));


    println!("cargo::rerun-if-env-changed={}", "LUCKPERMS_OPENAPI_SPEC");
    println!("cargo::rerun-if-env-changed={}", "AUTHENTIK_OPENAPI_SPEC");
    println!("cargo::rerun-if-changed=build.rs");
}
