#![no_std]

extern crate alloc; // only used in tests or optional helpers

use ark_bn254::{Fr as F, G1Affine, G1Projective, G2Affine, G2Projective, Bn254};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, Zero, One, FftField};
use core::fmt::{Debug, Formatter};
use blake3::Hasher;

pub const WIDTH: usize = 32; // fixed branching factor

pub mod static_srs;
pub use static_srs::static_srs;

pub enum KzgEvalError { WidthMismatch, InvalidIndex, PointInDomain, DivZero, PairingFailed }

impl core::fmt::Display for KzgEvalError { fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result { write!(f, "{:?}", self) } }
impl Debug for KzgEvalError { fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result { match self { KzgEvalError::WidthMismatch=>write!(f,"WidthMismatch"), KzgEvalError::InvalidIndex=>write!(f,"InvalidIndex"), KzgEvalError::PointInDomain=>write!(f,"PointInDomain"), KzgEvalError::DivZero=>write!(f,"DivZero"), KzgEvalError::PairingFailed=>write!(f,"PairingFailed"), } } }

/// Public verification SRS (no tau disclosure): commitments of monomials mapped into lagrange implicitly.
/// We store lagrange point scalars L_i(τ) * G1_gen directly as points.
pub struct SrsEval {
	pub width: usize,
	pub g1_lagrange: [G1Affine; WIDTH],
	pub g2_gen: G2Affine,
	pub g2_tau: G2Affine, // [τ]G2
	pub omega_domain: [F; WIDTH], // ω^i
	pub inv_width: F,
}

impl SrsEval {
	pub fn assert_width(&self, w: usize) -> Result<(), KzgEvalError> { if self.width!=w { Err(KzgEvalError::WidthMismatch) } else { Ok(()) } }

	/// Deterministic SRS (for tests) using hash-derived tau. Not for production ceremonies.
	pub fn deterministic() -> Self {
		let width = WIDTH;
		let omega_domain = compute_domain(width);
		let inv_width = F::from(width as u64).inverse().unwrap();
		let tau = field_from_bytes(b"VERKLE_SRS_TAU");
	let g2_gen = G2Affine::generator();
	let g2_tau = (G2Affine::generator().into_group() * tau).into_affine();
		// Compute L_i(τ) scalars then multiply generator
		let mut g1_lagrange = [G1Affine::zero(); WIDTH];
	for i in 0..width { g1_lagrange[i] = (G1Affine::generator().into_group() * lagrange_at(i, tau, &omega_domain)).into_affine(); }
		SrsEval { width, g1_lagrange, g2_gen, g2_tau, omega_domain, inv_width }
	}
}

/// Evaluation-form polynomial (fixed width)
pub struct EvalPoly { pub evals: [F; WIDTH] }
impl EvalPoly { pub fn zero() -> Self { Self { evals: [F::zero(); WIDTH] } } }

#[inline] fn field_from_bytes(tag: &[u8]) -> F { let hash = blake3::hash(tag); F::from_le_bytes_mod_order(hash.as_bytes()) }

fn compute_domain(width: usize) -> [F; WIDTH] {
	// root-of-unity for 2^k where k>=5 provided by bn254's 2-adicity; derive width root
	let mut arr = [F::zero(); WIDTH];
	// Need primitive 2^5 root (width=32). Acquire primitive 2^{TWO_ADICITY} root then square down.
	let big_root = F::get_root_of_unity(1u64 << F::TWO_ADICITY).expect("root");
	let mut omega = big_root;
	for _ in 0..(F::TWO_ADICITY as usize - 5) { omega = omega.square(); }
	let mut cur = F::one();
	for i in 0..width { arr[i] = cur; cur *= omega; }
	arr
}

/// Compute L_i(τ) by direct product formula.
fn lagrange_at(i: usize, tau: F, domain: &[F; WIDTH]) -> F {
	let xi = domain[i];
	let mut num = F::one();
	let mut den = F::one();
	for (j, &xj) in domain.iter().enumerate() { if j!=i { num *= tau - xj; den *= xi - xj; } }
	num * den.inverse().unwrap()
}

/// Commit: Σ f_i * G1_Li with G1_Li = L_i(τ)G1
pub fn commit_eval(poly: &EvalPoly, srs: &SrsEval) -> G1Affine { let mut acc = G1Projective::zero(); for i in 0..srs.width { let v = poly.evals[i]; if !v.is_zero() { acc += srs.g1_lagrange[i] * v; } } acc.into_affine() }

/// Inner quotient evaluations: q(ω^i) = (f(ω^i)-f(ω^k)) * ω^{-i} /(ω^k - ω^i)  with correction for i=k.
pub fn inner_quotient(poly: &EvalPoly, k: usize, srs: &SrsEval) -> Result<[F; WIDTH], KzgEvalError> {
	if k>=srs.width { return Err(KzgEvalError::InvalidIndex); }
	let width = srs.width; let yk = poly.evals[k]; let mut q = [F::zero(); WIDTH];
	for i in 0..width { if i==k { continue; } let fi = poly.evals[i]; let omega_i = srs.omega_domain[i]; let omega_k = srs.omega_domain[k]; let denom = omega_k - omega_i; let inv = denom.inverse().ok_or(KzgEvalError::DivZero)?; let omega_i_inv = omega_i.inverse().unwrap(); q[i] = (fi - yk) * omega_i_inv * inv; }
	// q[k] = - Σ ω^{i-k} q[i]
	let omega_k_inv = srs.omega_domain[k].inverse().unwrap(); let mut acc = F::zero(); for i in 0..width { if i!=k { let factor = srs.omega_domain[i]*omega_k_inv; acc += factor * q[i]; } } q[k] = -acc; Ok(q)
}

/// Evaluate polynomial at t outside domain via barycentric formula.
pub fn evaluate_outside(poly: &EvalPoly, t: F, srs: &SrsEval) -> Result<F, KzgEvalError> {
	for &x in srs.omega_domain.iter().take(srs.width) { if x == t { return Err(KzgEvalError::PointInDomain); } }
	let mut acc = F::zero();
	let t_pow_w = t.pow([srs.width as u64]);
	for i in 0..srs.width { let xi = srs.omega_domain[i]; let denom = t - xi; let inv = denom.inverse().ok_or(KzgEvalError::DivZero)?; acc += poly.evals[i] * xi * inv; }
	Ok( (t_pow_w - F::one()) * srs.inv_width * acc )
}

/// Outer quotient: q(ω^i) = (f(ω^i)-y)/(ω^i - t)
pub fn outer_quotient(poly: &EvalPoly, t: F, y: F, srs: &SrsEval) -> Result<[F; WIDTH], KzgEvalError> {
	let mut q = [F::zero(); WIDTH];
	for i in 0..srs.width { let xi = srs.omega_domain[i]; let denom = xi - t; let inv = denom.inverse().ok_or(KzgEvalError::DivZero)?; q[i] = (poly.evals[i] - y) * inv; }
	Ok(q)
}

/// KZG pairing check for commitment C, evaluation y at z, proof π (commitment to quotient) with public g2_tau: e(C - yG1, g2_gen) == e(π, g2_tau - z g2_gen)
fn pairing_check(c: &G1Affine, y: F, z: F, pi: &G1Affine, srs: &SrsEval) -> bool {
	let gen_g1 = G1Affine::generator().into_group();
	let lhs_g1 = (G1Projective::from(*c) + (gen_g1 * (-y))).into_affine();
	let rhs_g2 = (G2Projective::from(srs.g2_tau) + (G2Projective::from(srs.g2_gen) * (-z))).into_affine();
	Bn254::pairing(lhs_g1, srs.g2_gen) == Bn254::pairing(*pi, rhs_g2)
}

/// Path multiproof output
#[derive(Clone, Debug)]
pub struct PathMultiproof {
	pub commitments: alloc::vec::Vec<G1Affine>,
	pub indices: alloc::vec::Vec<u8>,
	pub values: alloc::vec::Vec<F>,
	pub d_commit: G1Affine,
	pub y: F,
	pub h_commit: G1Affine,
	pub w: F,
	pub sigma: G1Affine,
}

fn hash_field(acc: &mut Hasher, f: &F) { let mut bytes = [0u8;32]; f.serialize_compressed(&mut bytes[..]).ok(); acc.update(&bytes); }
fn hash_g1(acc: &mut Hasher, p: &G1Affine) { let mut bytes = [0u8;48]; p.serialize_compressed(&mut bytes[..]).ok(); acc.update(&bytes); }

use ark_serialize::CanonicalSerialize;

/// Build multiproof for a single path
pub fn build_path_multiproof(polys: &[EvalPoly], path_indices: &[usize], srs: &SrsEval) -> Result<PathMultiproof, KzgEvalError> {
	let depth = polys.len();
	// Step 0: commitments and y_i
	let mut commitments = alloc::vec::Vec::with_capacity(depth);
	let mut values = alloc::vec::Vec::with_capacity(depth);
	for p in polys { commitments.push(commit_eval(p, srs)); }
	for (p,&k) in polys.iter().zip(path_indices) { values.push(p.evals[k]); }
	// r challenge
	let mut h = Hasher::new();
	for c in &commitments { hash_g1(&mut h, c); }
	for (k,v) in path_indices.iter().zip(values.iter()) { h.update(&[*k as u8]); hash_field(&mut h, v); }
	let r = F::from_le_bytes_mod_order(h.finalize().as_bytes());
	// g accumulation
	let mut g = [F::zero(); WIDTH];
	let mut r_pow = F::one();
	for (poly,&k) in polys.iter().zip(path_indices) { let q = inner_quotient(poly, k, srs)?; for i in 0..srs.width { g[i] += r_pow * q[i]; } r_pow *= r; }
	let g_poly = EvalPoly { evals: g };
	let d_commit = commit_eval(&g_poly, srs);
	// t challenge
	let mut ht = Hasher::new(); hash_field(&mut ht, &r); hash_g1(&mut ht, &d_commit); let t = F::from_le_bytes_mod_order(ht.finalize().as_bytes());
	// h accumulation
	let mut h_eval = [F::zero(); WIDTH];
	let mut r_pow = F::one();
	for (poly,&k) in polys.iter().zip(path_indices) { let denom_inv = (t - srs.omega_domain[k]).inverse().ok_or(KzgEvalError::DivZero)?; for i in 0..srs.width { h_eval[i] += r_pow * poly.evals[i] * denom_inv; } r_pow *= r; }
	let h_poly = EvalPoly { evals: h_eval };
	// Evaluate & open h,g at t
	let y = evaluate_outside(&h_poly, t, srs)?; let w = evaluate_outside(&g_poly, t, srs)?;
	let qh_eval = outer_quotient(&h_poly, t, y, srs)?; let qg_eval = outer_quotient(&g_poly, t, w, srs)?;
	let qh_poly = EvalPoly { evals: qh_eval }; let qg_poly = EvalPoly { evals: qg_eval };
	let pi_h = commit_eval(&qh_poly, srs); let pi_g = commit_eval(&qg_poly, srs);
	let h_commit = commit_eval(&h_poly, srs);
	let mut hq = Hasher::new(); hash_g1(&mut hq, &h_commit); hash_g1(&mut hq, &d_commit); hash_field(&mut hq, &y); hash_field(&mut hq, &w); let q = F::from_le_bytes_mod_order(hq.finalize().as_bytes());
	let sigma = (G1Projective::from(pi_h) + G1Projective::from(pi_g)*q).into_affine();
	Ok(PathMultiproof { commitments, indices: path_indices.iter().map(|x| *x as u8).collect(), values, d_commit, y, h_commit, w, sigma })
}

pub fn verify_path_multiproof(proof: &PathMultiproof, srs: &SrsEval, expected_leaf: F) -> bool {
	if proof.commitments.is_empty() { return false; }
	// Recompute r
	let mut h = Hasher::new();
	for c in &proof.commitments { hash_g1(&mut h, c); }
	for (k,v) in proof.indices.iter().zip(proof.values.iter()) { h.update(&[*k]); hash_field(&mut h, v); }
	let r = F::from_le_bytes_mod_order(h.finalize().as_bytes());
	// Recompute t
	let mut ht = Hasher::new(); hash_field(&mut ht, &r); hash_g1(&mut ht, &proof.d_commit); let t = F::from_le_bytes_mod_order(ht.finalize().as_bytes());
	// Recompute q
	let mut hq = Hasher::new(); hash_g1(&mut hq, &proof.h_commit); hash_g1(&mut hq, &proof.d_commit); hash_field(&mut hq, &proof.y); hash_field(&mut hq, &proof.w); let q = F::from_le_bytes_mod_order(hq.finalize().as_bytes());
	// Basic sanity: last value equals expected leaf
	if *proof.values.last().unwrap() != expected_leaf { return false; }
	// Pairing equation: e(E - yG1, g2) * e(D - wG1, g2)^q == e(sigma, g2_tau - t g2)
	let gen_g1 = G1Affine::generator().into_group();
	let lhs1 = (G1Projective::from(proof.h_commit) + gen_g1 * (-proof.y)).into_affine();
	let lhs2 = (G1Projective::from(proof.d_commit) + gen_g1 * (-proof.w)).into_affine();
	let gamma = (G2Projective::from(srs.g2_tau) + (G2Projective::from(srs.g2_gen) * (-t))).into_affine();
	let pair1 = Bn254::pairing(lhs1, srs.g2_gen).0;
	let pair2 = Bn254::pairing(lhs2, srs.g2_gen).0;
	let q_big = q.into_bigint();
	let pair2q = pair2.pow(q_big);
	let lhs = pair1 * pair2q;
	let rhs = Bn254::pairing(proof.sigma, gamma).0;
	lhs == rhs
}

// ---------------- Simple per-level opening helpers (used during transitional integration) ----------------
/// Open evaluation-form polynomial at domain index k.
pub fn open_domain(poly: &EvalPoly, width: usize, k: usize, srs: &SrsEval) -> Result<(F, G1Affine), KzgEvalError> {
	srs.assert_width(width)?; if k>=width { return Err(KzgEvalError::InvalidIndex); }
	let q_evals = inner_quotient(poly, k, srs)?; let q_poly = EvalPoly { evals: q_evals }; let pi = commit_eval(&q_poly, srs); Ok((poly.evals[k], pi))
}

/// Verify opening at domain index k.
pub fn verify_domain_open(commitment: &G1Affine, value: F, k: usize, proof: &G1Affine, srs: &SrsEval) -> bool {
	if k>=srs.width { return false; }
	let z = srs.omega_domain[k];
	pairing_check(commitment, value, z, proof, srs)
}


