//! Generates constants for instructions.

use std::process::Command;

fn main() {

    Command::new("aarch64-linux-gnu-as")
        .args(["asm-test/aarch64.s", "-o", "/tmp/1.o"])
        .status()
        .expect("Failed to run gas");
    let output = Command::new("aarch64-linux-gnu-objdump")
        .args(["-D", "/tmp/1.o"])
        .output().unwrap();
    let out = String::from_utf8_lossy(&output.stdout);

    let mut lines = out.lines();
    while let Some(l) = lines.next() {
        if let (Some(start), Some(end)) = (l.find("<OP_"), l.find(">")) {
            let name = &l[start+1..end];
            if name.contains('+') { continue; }
            // eprintln!("{name}");
            let line = lines.next().unwrap();
            // eprintln!("{line}");
            if let Some(pos) = line.find(":") {
                let rhs = &line[pos+1..].trim();
                if let Some((hex, rest)) = rhs.split_at_checked(8) {
                    let rest = rest.trim();
                    if u32::from_str_radix(hex, 16).is_ok() {
                        println!("const {name} : Optype = 0x{hex}; // {rest}");
                    }
                }
            }
        }

    }
    // println!("{}", out);
}

