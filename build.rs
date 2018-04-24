use std::process::Command;
use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    // Note: replace with your own build script
    // see https://doc.rust-lang.org/cargo/reference/build-scripts.html#overriding-build-scripts
    // for more details
    Command::new("gcc").args(&["src/external_firewall.c", "-c", "-fPIC", "-o"])
                       .arg(&format!("{}/external_firewall.o", out_dir))
                       .status().unwrap();
    Command::new("ar").args(&["crus", "libexternalfirewall.a", "external_firewall.o"])
                      .current_dir(&Path::new(&out_dir))
                      .status().unwrap();

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=externalfirewall");
}
