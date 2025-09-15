use ark_serialize::CanonicalSerialize;
use kzg::{SrsEval, WIDTH};
use std::io::{self, Write};

// Binary format spec (little endian unless noted):
// magic: 4 bytes = b"KSRS"
// version: u8 = 1
// width: u16
// g1_lagrange: width * 48 bytes (compressed G1)
// g2_gen: 96 bytes (compressed G2)
// g2_tau: 96 bytes (compressed G2)
// omega_domain: width * 32 bytes (field elements)
// inv_width: 32 bytes
fn main() {
    let srs = SrsEval::deterministic();
    let mut out = Vec::new();
    out.extend_from_slice(b"KSRS");
    out.push(1u8); // version
    out.extend_from_slice(&(srs.width as u16).to_le_bytes());
    // G1 lagrange points
    for p in &srs.g1_lagrange {
        p.serialize_compressed(&mut out).expect("g1 serialize");
    }
    // G2 gen & tau
    srs.g2_gen.serialize_compressed(&mut out).expect("g2 gen");
    srs.g2_tau.serialize_compressed(&mut out).expect("g2 tau");
    // omega domain
    for w in &srs.omega_domain[0..srs.width] {
        w.serialize_compressed(&mut out).expect("omega serialize");
    }
    srs.inv_width
        .serialize_compressed(&mut out)
        .expect("inv width");
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(&out).expect("write srs");
}
