//! Wire-compatible port of [schollz/pake/v3](https://github.com/schollz/pake) —
//! the password-authenticated key exchange (SPAKE2-style, Boneh–Shoup fig. 21)
//! used both between croc peers and between clients and the relay.
//!
//! Compatibility notes:
//! * Messages are JSON with Go's field names, including the Unicode
//!   subscripts (`Uᵤ`, `Xᵥ`, …); coordinates are arbitrary-precision decimal
//!   JSON numbers, exactly as Go's `big.Int` marshals.
//! * Curves: `p256`, `p384`, `p521` and `siec` (the nonstandard 255-bit
//!   "super-isolated" curve croc uses for the relay handshake, y² = x³ + 19).
//!   Go's `ed25519` option is not yet ported.
//! * Like the Go original (which uses `math/big`), this implementation is
//!   **not constant-time**. Migrating the standard curves to RustCrypto's
//!   constant-time arithmetic is tracked in MIGRATION.md.

use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum PakeError {
    UnknownCurve(String),
    BadMessage(String),
    NotOnCurve(&'static str),
    SameRole,
    NoSessionKey,
}

impl std::fmt::Display for PakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PakeError::UnknownCurve(c) => write!(f, "no such curve: {c}"),
            PakeError::BadMessage(m) => write!(f, "bad pake message: {m}"),
            PakeError::NotOnCurve(w) => write!(f, "{w} values not on curve"),
            PakeError::SameRole => write!(f, "can't have its own role"),
            PakeError::NoSessionKey => write!(f, "session key not generated"),
        }
    }
}

impl std::error::Error for PakeError {}

/// Affine point; `None` is the point at infinity.
type Point = Option<(BigUint, BigUint)>;

/// Curve parameters retained for the on-curve check and affine negation only;
/// all scalar multiplication / point addition runs in a constant-time backend
/// ([`ct`] for the NIST curves, [`siec_ct`] for SIEC), which carries its own
/// generator, so the base point is no longer stored here.
struct Curve {
    kind: CurveKind,
    p: BigUint,
    a: BigUint, // curve coefficient a, already reduced mod p
    b: BigUint,
}

fn hexu(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).expect("bad hex constant")
}

fn decu(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).expect("bad decimal constant")
}

/// Which arithmetic backend a curve uses.
#[derive(Clone, Copy, PartialEq)]
enum CurveKind {
    /// Constant-time RustCrypto backend (see [`ct`]).
    Std(ct::StdId),
    /// Variable-time `num-bigint` backend — the only option for SIEC, whose
    /// nonstandard curve has no constant-time implementation anywhere (Go's
    /// `tscholl2/siec` is variable-time too).
    Siec,
}

/// Constant-time scalar multiplication and point addition for the standard
/// NIST curves, backed by the audited RustCrypto `p256`/`p384`/`p521` crates.
///
/// The PAKE wire format is raw affine coordinates as big integers, so each
/// operation converts `num-bigint` coordinates in, runs the constant-time
/// group operation, and converts the affine result back out. Scalars are
/// reduced mod the group order first: Go's `crypto/elliptic.ScalarMult`
/// treats the scalar as an unreduced big-endian integer, but every one of
/// these curves has prime order and cofactor 1, so `k·P == (k mod n)·P` —
/// the point is identical, and RustCrypto requires a canonical scalar.
mod ct {
    use num_bigint::BigUint;

    pub type Point = Option<(BigUint, BigUint)>;

    #[derive(Clone, Copy, PartialEq)]
    pub enum StdId {
        P256,
        P384,
        P521,
    }

    macro_rules! std_backend {
        ($modname:ident, $krate:ident, $order_hex:literal) => {
            mod $modname {
                use super::Point;
                use num_bigint::BigUint;
                use $krate::elliptic_curve::group::Group as _;
                use $krate::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
                use $krate::elliptic_curve::PrimeField;
                use $krate::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};

                fn order() -> BigUint {
                    BigUint::parse_bytes($order_hex, 16).unwrap()
                }

                /// Left-pad big-endian bytes to the curve's field width.
                fn pad(b: &[u8]) -> FieldBytes {
                    let mut out = FieldBytes::default();
                    let n = out.len();
                    let src = if b.len() > n { &b[b.len() - n..] } else { b };
                    out[n - src.len()..].copy_from_slice(src);
                    out
                }

                /// Reduce an arbitrary big-endian scalar mod n into a canonical
                /// curve scalar.
                fn scalar_from(k: &[u8]) -> Scalar {
                    let reduced = BigUint::from_bytes_be(k) % order();
                    let opt = Scalar::from_repr(pad(&reduced.to_bytes_be()));
                    Option::<Scalar>::from(opt).expect("reduced scalar is < n")
                }

                fn to_proj(pt: &Point) -> ProjectivePoint {
                    match pt {
                        None => ProjectivePoint::IDENTITY,
                        Some((x, y)) => {
                            let ep = EncodedPoint::from_affine_coordinates(
                                &pad(&x.to_bytes_be()),
                                &pad(&y.to_bytes_be()),
                                false,
                            );
                            Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))
                                .map(ProjectivePoint::from)
                                // Guarded upstream by is_on_curve; an off-curve
                                // point here would already have been rejected.
                                .unwrap_or(ProjectivePoint::IDENTITY)
                        }
                    }
                }

                fn from_proj(p: ProjectivePoint) -> Point {
                    let ep = p.to_affine().to_encoded_point(false);
                    match (ep.x(), ep.y()) {
                        (Some(x), Some(y)) => {
                            Some((BigUint::from_bytes_be(x), BigUint::from_bytes_be(y)))
                        }
                        _ => None, // identity
                    }
                }

                pub fn scalar_mult(x: &BigUint, y: &BigUint, k: &[u8]) -> Point {
                    from_proj(to_proj(&Some((x.clone(), y.clone()))) * scalar_from(k))
                }

                pub fn scalar_base_mult(k: &[u8]) -> Point {
                    from_proj(ProjectivePoint::generator() * scalar_from(k))
                }

                pub fn add(a: &Point, b: &Point) -> Point {
                    from_proj(to_proj(a) + to_proj(b))
                }
            }
        };
    }

    std_backend!(
        be256,
        p256,
        b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    );
    std_backend!(
        be384,
        p384,
        b"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
    );
    std_backend!(
        be521,
        p521,
        b"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"
    );

    pub fn scalar_mult(id: StdId, x: &BigUint, y: &BigUint, k: &[u8]) -> Point {
        match id {
            StdId::P256 => be256::scalar_mult(x, y, k),
            StdId::P384 => be384::scalar_mult(x, y, k),
            StdId::P521 => be521::scalar_mult(x, y, k),
        }
    }

    pub fn scalar_base_mult(id: StdId, k: &[u8]) -> Point {
        match id {
            StdId::P256 => be256::scalar_base_mult(k),
            StdId::P384 => be384::scalar_base_mult(k),
            StdId::P521 => be521::scalar_base_mult(k),
        }
    }

    pub fn add(id: StdId, a: &Point, b: &Point) -> Point {
        match id {
            StdId::P256 => be256::add(a, b),
            StdId::P384 => be384::add(a, b),
            StdId::P521 => be521::add(a, b),
        }
    }
}

/// Curve names supported by this port (Go additionally offers "ed25519").
pub fn available_curves() -> &'static [&'static str] {
    &["p256", "p384", "p521", "siec"]
}

impl Curve {
    fn by_name(name: &str) -> Result<Curve, PakeError> {
        // NIST parameters are the standard SEC2 values, matching Go's
        // crypto/elliptic; siec matches github.com/tscholl2/siec.
        match name {
            "p256" => {
                let p = hexu("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
                Ok(Curve {
                    kind: CurveKind::Std(ct::StdId::P256),
                    a: &p - 3u32,
                    b: hexu("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
                    p,
                })
            }
            "p384" => {
                let p = hexu(
                    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
                );
                Ok(Curve {
                    kind: CurveKind::Std(ct::StdId::P384),
                    a: &p - 3u32,
                    b: hexu("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
                    p,
                })
            }
            "p521" => {
                let p = hexu(
                    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                );
                Ok(Curve {
                    kind: CurveKind::Std(ct::StdId::P521),
                    a: &p - 3u32,
                    b: hexu("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
                    p,
                })
            }
            "siec" => Ok(Curve {
                kind: CurveKind::Siec,
                p: decu(
                    "28948022309329048855892746252183396360603931420023084536990047309120118726721",
                ),
                a: BigUint::zero(),
                b: decu("19"),
            }),
            other => Err(PakeError::UnknownCurve(other.to_string())),
        }
    }

    fn is_on_curve(&self, pt: &Point) -> bool {
        match pt {
            None => false,
            Some((x, y)) => {
                let lhs = y.modpow(&BigUint::from(2u32), &self.p);
                let rhs =
                    (x.modpow(&BigUint::from(3u32), &self.p) + (&self.a * x) % &self.p + &self.b)
                        % &self.p;
                lhs == rhs
            }
        }
    }

    /// Affine point negation: (x, y) → (x, −y mod p). Cheap and not
    /// secret-scalar-dependent, so this stays on `num-bigint`.
    fn neg_y(&self, pt: &Point) -> Point {
        pt.as_ref().map(|(x, y)| {
            let neg = if y.is_zero() {
                BigUint::zero()
            } else {
                &self.p - y
            };
            (x.clone(), neg)
        })
    }

    /// Point addition, dispatched to the constant-time backend for the curve.
    fn add(&self, p1: &Point, p2: &Point) -> Point {
        match self.kind {
            CurveKind::Std(id) => ct::add(id, p1, p2),
            CurveKind::Siec => siec_ct::add(p1, p2),
        }
    }

    /// Scalar multiplication, constant-time in the scalar for every curve:
    /// the standard NIST curves use the RustCrypto backend, SIEC the
    /// `crypto-bigint` Montgomery backend in [`siec_ct`].
    fn scalar_mult(&self, pt: &Point, k: &[u8]) -> Point {
        let Some((x, y)) = pt else {
            return None; // k · O = O
        };
        match self.kind {
            CurveKind::Std(id) => ct::scalar_mult(id, x, y, k),
            CurveKind::Siec => siec_ct::scalar_mult(x, y, k),
        }
    }

    fn scalar_base_mult(&self, k: &[u8]) -> Point {
        match self.kind {
            CurveKind::Std(id) => ct::scalar_base_mult(id, k),
            CurveKind::Siec => siec_ct::scalar_base_mult(k),
        }
    }
}

/// Constant-time SIEC arithmetic.
///
/// SIEC (`y² = x³ + 19` over a 255-bit prime, generator (5, 12)) is croc's
/// nonstandard relay-handshake curve; no crate implements it, and Go's
/// `tscholl2/siec` is variable-time. This backend is constant-time in the
/// scalar: field arithmetic is `crypto-bigint`'s Montgomery form (constant
/// time), point addition uses the Renes–Costello–Batina *complete* formula
/// (uniform — no input-dependent branches), and scalar multiplication is a
/// double-and-add-*always* ladder with `subtle` conditional selection, so the
/// same operations run regardless of the scalar bits.
///
/// The scalar is processed over exactly `8·k.len()` bits; the length is public
/// (protocol-fixed: the 3-byte weak key for the handshake, or a 32-byte
/// ephemeral), so no reduction is needed — every curve here has prime order,
/// making `k·P` well defined for an unreduced `k`, matching Go.
mod siec_ct {
    use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
    use crypto_bigint::{Odd, U256};
    use num_bigint::BigUint;
    use std::sync::OnceLock;
    use subtle::{Choice, ConditionallySelectable};

    type Fp = FixedMontyForm<{ U256::LIMBS }>;
    type Point = Option<(BigUint, BigUint)>;

    // SIEC field prime p (255-bit).
    const P_HEX: &str = "4000000000000000000000000200104080000000000000000004004103082041";

    fn params() -> &'static FixedMontyParams<{ U256::LIMBS }> {
        static P: OnceLock<FixedMontyParams<{ U256::LIMBS }>> = OnceLock::new();
        P.get_or_init(|| FixedMontyParams::new(Odd::new(U256::from_be_hex(P_HEX)).unwrap()))
    }

    fn fp(v: u64) -> Fp {
        Fp::new(&U256::from_u64(v), params())
    }

    fn fp_from_biguint(v: &BigUint) -> Fp {
        let be = v.to_bytes_be();
        let mut bytes = [0u8; 32]; // coords are < p < 2^255, so ≤ 32 bytes
        bytes[32 - be.len()..].copy_from_slice(&be);
        Fp::new(&U256::from_be_slice(&bytes), params())
    }

    fn fp_to_biguint(f: &Fp) -> BigUint {
        BigUint::from_bytes_be(&f.retrieve().to_be_bytes())
    }

    /// Homogeneous projective point (X:Y:Z); the identity is (0:1:0).
    #[derive(Clone, Copy)]
    struct Pt {
        x: Fp,
        y: Fp,
        z: Fp,
    }

    impl ConditionallySelectable for Pt {
        fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
            Pt {
                x: Fp::conditional_select(&a.x, &b.x, c),
                y: Fp::conditional_select(&a.y, &b.y, c),
                z: Fp::conditional_select(&a.z, &b.z, c),
            }
        }
    }

    fn identity() -> Pt {
        Pt {
            x: Fp::zero(params()),
            y: Fp::one(params()),
            z: Fp::zero(params()),
        }
    }

    fn projective(p: &Point) -> Pt {
        match p {
            None => identity(),
            Some((x, y)) => Pt {
                x: fp_from_biguint(x),
                y: fp_from_biguint(y),
                z: Fp::one(params()),
            },
        }
    }

    fn to_affine(p: &Pt) -> Point {
        if p.z.retrieve() == U256::ZERO {
            return None; // point at infinity
        }
        let zinv: Fp = Option::from(p.z.invert()).expect("z ≠ 0 is invertible mod prime p");
        Some((fp_to_biguint(&(p.x * zinv)), fp_to_biguint(&(p.y * zinv))))
    }

    /// Renes–Costello–Batina complete addition, Algorithm 7 (`a = 0`), with
    /// `b3 = 3·b = 57`. Uniform: correct for all inputs incl. P = Q and the
    /// identity, with no data-dependent branches.
    // Statements are kept in the paper's exact `tN ← tI op tJ` order (not
    // compound-assign) so they line up 1:1 with Algorithm 7 for review.
    #[allow(clippy::assign_op_pattern)]
    fn add_pt(p: &Pt, q: &Pt) -> Pt {
        let b3 = fp(57);
        let (x1, y1, z1) = (p.x, p.y, p.z);
        let (x2, y2, z2) = (q.x, q.y, q.z);
        let mut t0 = x1 * x2;
        let mut t1 = y1 * y2;
        let mut t2 = z1 * z2;
        let mut t3 = x1 + y1;
        let mut t4 = x2 + y2;
        t3 = t3 * t4;
        t4 = t0 + t1;
        t3 = t3 - t4;
        t4 = y1 + z1;
        let mut t5 = y2 + z2;
        t4 = t4 * t5;
        t5 = t1 + t2;
        t4 = t4 - t5;
        let mut x3 = x1 + z1;
        let mut y3 = x2 + z2;
        x3 = x3 * y3;
        y3 = t0 + t2;
        y3 = x3 - y3;
        x3 = t0 + t0;
        t0 = x3 + t0;
        t2 = b3 * t2;
        let mut z3 = t1 + t2;
        t1 = t1 - t2;
        y3 = b3 * y3;
        x3 = t4 * y3;
        t2 = t3 * t1;
        x3 = t2 - x3;
        y3 = y3 * t0;
        t1 = t1 * z3;
        y3 = t1 + y3;
        t0 = t0 * t3;
        z3 = z3 * t4;
        z3 = z3 + t0;
        Pt {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Double-and-add-*always* over the big-endian bits of `k`. Constant-time
    /// in the bit values: each step doubles, computes R+base, then selects.
    fn scalar_mult_pt(base: &Pt, k: &[u8]) -> Pt {
        let mut r = identity();
        for &byte in k {
            for i in (0..8).rev() {
                let bit = (byte >> i) & 1;
                r = add_pt(&r, &r); // double
                let r_add = add_pt(&r, base);
                r = Pt::conditional_select(&r, &r_add, Choice::from(bit));
            }
        }
        r
    }

    pub fn scalar_mult(x: &BigUint, y: &BigUint, k: &[u8]) -> Point {
        let base = Pt {
            x: fp_from_biguint(x),
            y: fp_from_biguint(y),
            z: Fp::one(params()),
        };
        to_affine(&scalar_mult_pt(&base, k))
    }

    pub fn scalar_base_mult(k: &[u8]) -> Point {
        let base = Pt {
            x: fp(5),
            y: fp(12),
            z: Fp::one(params()),
        };
        to_affine(&scalar_mult_pt(&base, k))
    }

    pub fn add(p1: &Point, p2: &Point) -> Point {
        to_affine(&add_pt(&projective(p1), &projective(p2)))
    }
}

/// The fixed "nothing-up-my-sleeve" U/V points from schollz/pake's
/// `initCurve`, which serve as the password-blinding generators.
fn uv_points(curve: &str) -> (BigUint, BigUint, BigUint, BigUint) {
    let (ux, uy, vx, vy) = match curve {
        "p256" => (
            "793136080485469241208656611513609866400481671852",
            "59748757929350367369315811184980635230185250460108398961713395032485227207304",
            "1086685267857089638167386722555472967068468061489",
            "9157340230202296554417312816309453883742349874205386245733062928888341584123",
        ),
        "p384" => (
            "793136080485469241208656611513609866400481671852",
            "7854890799382392388170852325516804266858248936799429260403044177981810983054351714387874260245230531084533936948596",
            "1086685267857089638167386722555472967068468061489",
            "21898206562669911998235297167979083576432197282633635629145270958059347586763418294901448537278960988843108277491616",
        ),
        "p521" => (
            "793136080485469241208656611513609866400481671852",
            "4032821203812196944795502391345776760852202059010382256134592838722123385325802540879231526503456158741518531456199762365161310489884151533417829496019094620",
            "1086685267857089638167386722555472967068468061489",
            "5010916268086655347194655708160715195931018676225831839835602465999566066450501167246678404591906342753230577187831311039273858772817427392089150297708931207",
        ),
        "siec" => (
            "793136080485469241208656611513609866400481671853",
            "18458907634222644275952014841865282643645472623913459400556233196838128612339",
            "1086685267857089638167386722555472967068468061489",
            "19593504966619549205903364028255899745298716108914514072669075231742699650911",
        ),
        _ => unreachable!("curve validated in by_name"),
    };
    (decu(ux), decu(uy), decu(vx), decu(vy))
}

/// Mirrors `pake.Pake`. Role 0 initiates (croc sender / relay client),
/// role 1 responds (croc recipient / relay server).
pub struct Pake {
    pub role: u8,
    curve: Curve,
    pw: Vec<u8>,
    u: Point,
    v: Point,
    x: Point,
    y: Point,
    vpw: Point,
    upw: Point,
    alpha: [u8; 32],
    k: Option<Vec<u8>>,
    /// Set by [`Pake::init_curve_with_identities`]: the curve name and the
    /// ordered participant identities mixed into the session-key transcript.
    /// `None` keeps the legacy (identity-free) transcript.
    ids: Option<Identities>,
}

/// Participant binding for `pake.InitCurveWithIdentities`.
struct Identities {
    curve_name: String,
    id_a: Vec<u8>,
    id_b: Vec<u8>,
}

impl Drop for Pake {
    fn drop(&mut self) {
        // Wipe secret material: the weak password, the random blinding scalar,
        // and the derived session key. (Public curve points aren't secret.)
        use zeroize::Zeroize;
        self.pw.zeroize();
        self.alpha.zeroize();
        if let Some(k) = self.k.as_mut() {
            k.zeroize();
        }
    }
}

/// Domain separator for the identity-bound session key (Go:
/// `identityTranscriptDomain`).
const IDENTITY_TRANSCRIPT_DOMAIN: &[u8] =
    b"github.com/schollz/pake/v3/identity-bound-session-key/v1";

/// Minimal big-endian bytes, matching Go's `big.Int.Bytes()` (empty for 0).
fn go_bytes(n: &BigUint) -> Vec<u8> {
    if n.is_zero() {
        Vec::new()
    } else {
        n.to_bytes_be()
    }
}

fn coord_json(pt: &Point, idx: usize) -> String {
    match pt {
        Some(p) => {
            let v = if idx == 0 { &p.0 } else { &p.1 };
            v.to_str_radix(10)
        }
        None => "null".to_string(),
    }
}

impl Pake {
    /// Mirrors `pake.InitCurve(pw, role, curve)`.
    pub fn init_curve(pw: &[u8], role: u8, curve_name: &str) -> Result<Pake, PakeError> {
        Self::init(pw, role, curve_name, None)
    }

    /// Mirrors `pake.InitCurveWithIdentities(pw, role, curve, idA, idB)`: the
    /// wire values are unchanged, but the session key additionally commits to
    /// the ordered participant identities and the curve name.
    pub fn init_curve_with_identities(
        pw: &[u8],
        role: u8,
        curve_name: &str,
        id_a: &[u8],
        id_b: &[u8],
    ) -> Result<Pake, PakeError> {
        if role != 0 && role != 1 {
            return Err(PakeError::BadMessage("role must be 0 (A) or 1 (B)".into()));
        }
        if id_a.is_empty() || id_b.is_empty() {
            return Err(PakeError::BadMessage(
                "both participant identities are required".into(),
            ));
        }
        Self::init(
            pw,
            role,
            curve_name,
            Some(Identities {
                curve_name: curve_name.to_string(),
                id_a: id_a.to_vec(),
                id_b: id_b.to_vec(),
            }),
        )
    }

    fn init(
        pw: &[u8],
        role: u8,
        curve_name: &str,
        ids: Option<Identities>,
    ) -> Result<Pake, PakeError> {
        let curve = Curve::by_name(curve_name)?;
        let (ux, uy, vx, vy) = uv_points(curve_name);
        let u: Point = Some((ux, uy));
        let v: Point = Some((vx, vy));
        if !curve.is_on_curve(&u) || !curve.is_on_curve(&v) {
            return Err(PakeError::NotOnCurve("U/V"));
        }
        let mut p = Pake {
            role: if role == 1 { 1 } else { 0 },
            curve,
            pw: pw.to_vec(),
            u,
            v,
            x: None,
            y: None,
            vpw: None,
            upw: None,
            alpha: [0u8; 32],
            k: None,
            ids,
        };
        if p.role == 0 {
            // STEP: A computes X = U·pw + G·α
            p.vpw = p.curve.scalar_mult(&p.v, &p.pw);
            p.upw = p.curve.scalar_mult(&p.u, &p.pw);
            rand::thread_rng().fill_bytes(&mut p.alpha);
            let alpha_g = p.curve.scalar_base_mult(&p.alpha);
            p.x = p.curve.add(&p.upw, &alpha_g);
        }
        Ok(p)
    }

    /// JSON of the public variables, byte-format-compatible with Go's
    /// `Pake.Bytes()` (which marshals `Public()`).
    ///
    /// `Public()` zeroes the private fields but still marshals them, so the
    /// trailing `"P"…"K"` nulls are part of the wire format. They are not
    /// decoration: croc peers unmarshal a `pake2` reply on top of the struct
    /// that still holds their own `pake1` value, and Go's decoder reuses that
    /// backing array when the reply is shorter — a peer given a compact reply
    /// would silently corrupt its own copy of the transcript and derive a
    /// different channel key.
    pub fn bytes(&self) -> Vec<u8> {
        format!(
            "{{\"Role\":{},\"Uᵤ\":{},\"Uᵥ\":{},\"Vᵤ\":{},\"Vᵥ\":{},\"Xᵤ\":{},\"Xᵥ\":{},\"Yᵤ\":{},\"Yᵥ\":{},\
             \"P\":null,\"Pw\":null,\"Vpwᵤ\":null,\"Vpwᵥ\":null,\"Upwᵤ\":null,\"Upwᵥ\":null,\
             \"Aα\":null,\"Aαᵤ\":null,\"Aαᵥ\":null,\"Zᵤ\":null,\"Zᵥ\":null,\"K\":null}}",
            self.role,
            coord_json(&self.u, 0),
            coord_json(&self.u, 1),
            coord_json(&self.v, 0),
            coord_json(&self.v, 1),
            coord_json(&self.x, 0),
            coord_json(&self.x, 1),
            coord_json(&self.y, 0),
            coord_json(&self.y, 1),
        )
        .into_bytes()
    }

    /// Process the other party's `bytes()`. Mirrors `Pake.Update`.
    pub fn update(&mut self, q_bytes: &[u8]) -> Result<(), PakeError> {
        let v: serde_json::Value =
            serde_json::from_slice(q_bytes).map_err(|e| PakeError::BadMessage(e.to_string()))?;
        let q_role = v
            .get("Role")
            .and_then(|r| r.as_u64())
            .ok_or_else(|| PakeError::BadMessage("missing Role".into()))?;
        if q_role == u64::from(self.role) {
            return Err(PakeError::SameRole);
        }

        let get_pt = |a: &str, b: &str| -> Result<Point, PakeError> {
            let read = |k: &str| -> Result<Option<BigUint>, PakeError> {
                match v.get(k) {
                    None | Some(serde_json::Value::Null) => Ok(None),
                    Some(serde_json::Value::Number(n)) => {
                        BigUint::parse_bytes(n.to_string().as_bytes(), 10)
                            .map(Some)
                            .ok_or_else(|| PakeError::BadMessage(format!("bad number in {k}")))
                    }
                    Some(_) => Err(PakeError::BadMessage(format!("bad type for {k}"))),
                }
            };
            match (read(a)?, read(b)?) {
                (Some(x), Some(y)) => Ok(Some((x, y))),
                _ => Ok(None),
            }
        };

        if self.role == 1 {
            // Received X from role 0; compute Y and the session key.
            let x = get_pt("Xᵤ", "Xᵥ")?;
            if !self.curve.is_on_curve(&x) {
                return Err(PakeError::NotOnCurve("X"));
            }
            self.x = x;
            self.vpw = self.curve.scalar_mult(&self.v, &self.pw);
            self.upw = self.curve.scalar_mult(&self.u, &self.pw);
            rand::thread_rng().fill_bytes(&mut self.alpha);
            let alpha_g = self.curve.scalar_base_mult(&self.alpha);
            self.y = self.curve.add(&self.vpw, &alpha_g);
            // Z = (X − U·pw)·α
            let z = self.curve.scalar_mult(
                &self.curve.add(&self.x, &self.curve.neg_y(&self.upw)),
                &self.alpha,
            );
            self.k = Some(self.session_hash(&z));
        } else {
            // Received Y from role 1; compute the session key.
            let y = get_pt("Yᵤ", "Yᵥ")?;
            if !self.curve.is_on_curve(&y) {
                return Err(PakeError::NotOnCurve("Y"));
            }
            self.y = y;
            // Z = (Y − V·pw)·α
            let z = self.curve.scalar_mult(
                &self.curve.add(&self.y, &self.curve.neg_y(&self.vpw)),
                &self.alpha,
            );
            self.k = Some(self.session_hash(&z));
        }
        Ok(())
    }

    /// K = SHA-256(pw ‖ X ‖ Y ‖ Z), coordinates as minimal big-endian bytes —
    /// identical to the Go hash transcript.
    ///
    /// With identities (`InitCurveWithIdentities`) the transcript instead is a
    /// length-prefixed encoding of the domain string, password, both identities,
    /// the curve name and the same coordinates.
    fn session_hash(&self, z: &Point) -> Vec<u8> {
        let mut h = Sha256::new();
        let Some(ids) = self.ids.as_ref() else {
            h.update(&self.pw);
            for (x, y) in [&self.x, &self.y, z].into_iter().flatten() {
                h.update(go_bytes(x));
                h.update(go_bytes(y));
            }
            return h.finalize().to_vec();
        };
        let mut field = |b: &[u8]| {
            h.update((b.len() as u64).to_le_bytes());
            h.update(b);
        };
        field(IDENTITY_TRANSCRIPT_DOMAIN);
        field(&self.pw);
        field(&ids.id_a);
        field(&ids.id_b);
        field(ids.curve_name.as_bytes());
        for pt in [&self.x, &self.y, z] {
            let (x, y) = match pt {
                Some((x, y)) => (go_bytes(x), go_bytes(y)),
                None => (Vec::new(), Vec::new()),
            };
            field(&x);
            field(&y);
        }
        h.finalize().to_vec()
    }

    /// Mirrors `Pake.SessionKey()`.
    pub fn session_key(&self) -> Result<Vec<u8>, PakeError> {
        self.k.clone().ok_or(PakeError::NoSessionKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(x: &str, y: &str) -> Point {
        Some((decu(x), decu(y)))
    }

    // Vectors generated from Go: crypto/elliptic and tscholl2/siec.
    // k = [1,2,3], pw = "some weak password".
    #[test]
    fn curve_math_matches_go() {
        let cases = [
            (
                "p256",
                "102177944418445466389220905852915392516949163071651313602197983576123586934735",
                "12754519112898262912616834608795559432138427757113692694370306044119752522562",
                "53954790233206707704377774197001360701189579251421636694579065471580808416597",
                "41929415471034965769699623633456831331823762153021418032864295447392317574423",
                "85261230923817659378034781912389283490647924559679374044289549934359765692098",
                "90372841657351955323498452116869639283295929300168252311841047427800105458529",
                "56580451076035890794735812961332685999617134615540236958551681516392327273195",
                "75288104128370351045713828736793861432249051783569416604062630277772205897021",
            ),
            (
                "siec",
                "20229788123255377252117609246816679794288126641783108573469038758141726144217",
                "24954944596292334650496455898477874666706713116404087873386411796931353338967",
                "7821604000828645370021527849864151781367895404633092807658104706533585607615",
                "12321748203907507311416299713967757533295516333623235765596715248801536832937",
                "12890957542364314192977455365464309255040581227397603771913365039752644473691",
                "1966715140277028004077810007564794649573112867679091036145080828506010855244",
                "18547106034652231084511426306268961189874505941601908436538648901407802923025",
                "8402302362712934719936415865028500915225426216290299538851902885977033418305",
            ),
        ];
        for (name, bx, by, px, py, ax, ay, dx, dy) in cases {
            let c = Curve::by_name(name).unwrap();
            let base = c.scalar_base_mult(&[1, 2, 3]);
            assert_eq!(base, pt(bx, by), "{name} scalar_base_mult");
            let scaled = c.scalar_mult(&base, b"some weak password");
            assert_eq!(scaled, pt(px, py), "{name} scalar_mult");
            assert_eq!(c.add(&base, &scaled), pt(ax, ay), "{name} add");
            assert_eq!(c.add(&base, &base), pt(dx, dy), "{name} double");
            assert!(c.is_on_curve(&base), "{name} on-curve");
        }
    }

    #[test]
    fn p384_p521_math_matches_go() {
        let cases = [
            (
                "p384",
                "24130927011173430378231057715197952681212665601905718919812090427010627717617469793155471216181827994232970479175536",
                "22037717132134218994409514148592082898077814907006468766203048987388822776133667992787817158513600959851507961684462",
                "37938645104099558529039088645282427725214109020491924994898352048444881929089432281343305530002613387212720251233369",
                "20411337777528479339208809955846131057199373993776380976847402659571748725478491323644617084795723963038548737212830",
            ),
            (
                "p521",
                "3661484409096487934920985446688295603408788383505517370011714675946370519279057366380235341438780144678641434360488908890221422137292668771035770549856068144",
                "5878886331948791724308241370702049630564158522048871648675704033410798172537062624939691818027757737380067027799817402093791327928224298943333530214666999536",
                "3479096684240030949358318169654864542756086130414806873765920570342335262632437335260474255738567934069355392222537586631894323327038117389362721239740982185",
                "2850673940125373004196833367292998411493512986424629351274559082111462554595354362522690709984291995078991396962260758567978184395564360311638298205431254799",
            ),
        ];
        for (name, bx, by, px, py) in cases {
            let c = Curve::by_name(name).unwrap();
            let base = c.scalar_base_mult(&[1, 2, 3]);
            assert_eq!(base, pt(bx, by), "{name} scalar_base_mult");
            let scaled = c.scalar_mult(&base, b"some weak password");
            assert_eq!(scaled, pt(px, py), "{name} scalar_mult");
        }
    }

    // The standard curves must use the constant-time RustCrypto backend and
    // SIEC the bignum backend; guards against a future refactor silently
    // routing a NIST curve back through variable-time code.
    #[test]
    fn backend_selection() {
        for name in ["p256", "p384", "p521"] {
            assert!(
                matches!(Curve::by_name(name).unwrap().kind, CurveKind::Std(_)),
                "{name} should use the constant-time backend"
            );
        }
        assert!(matches!(
            Curve::by_name("siec").unwrap().kind,
            CurveKind::Siec
        ));
    }

    // A large scalar (top bit set, so ≥ n for p256) must still agree between
    // the constant-time backend and a direct reduction — exercising the
    // reduce-mod-n path the RustCrypto scalar requires.
    #[test]
    fn large_scalar_reduces_like_go() {
        let c = Curve::by_name("p256").unwrap();
        let k = [0xffu8; 32]; // 2^256 - 1 > n
                              // k·G computed via the backend must be a valid on-curve point equal to
                              // (k mod n)·G. Recompute (k mod n)·G by feeding the reduced bytes.
        let n =
            decu("115792089210356248762697446949407573529996955224135760342422259061068512044369");
        let reduced = (BigUint::from_bytes_be(&k) % &n).to_bytes_be();
        assert_eq!(
            c.scalar_base_mult(&k),
            c.scalar_base_mult(&reduced),
            "k·G must equal (k mod n)·G"
        );
        assert!(c.is_on_curve(&c.scalar_base_mult(&k)));
    }

    #[test]
    fn full_exchange_all_curves() {
        for curve in available_curves() {
            let mut a = Pake::init_curve(b"shared-secret", 0, curve).unwrap();
            let mut b = Pake::init_curve(b"shared-secret", 1, curve).unwrap();
            b.update(&a.bytes()).unwrap();
            a.update(&b.bytes()).unwrap();
            assert_eq!(
                a.session_key().unwrap(),
                b.session_key().unwrap(),
                "curve {curve}"
            );
            assert_eq!(a.session_key().unwrap().len(), 32);
        }
    }

    #[test]
    fn wrong_password_differs() {
        let mut a = Pake::init_curve(b"secret-one", 0, "siec").unwrap();
        let mut b = Pake::init_curve(b"secret-two", 1, "siec").unwrap();
        b.update(&a.bytes()).unwrap();
        a.update(&b.bytes()).unwrap();
        assert_ne!(a.session_key().unwrap(), b.session_key().unwrap());
    }

    #[test]
    fn rejects_same_role_and_bad_points() {
        let mut a = Pake::init_curve(b"x", 0, "p256").unwrap();
        let a2 = Pake::init_curve(b"x", 0, "p256").unwrap();
        assert!(matches!(a.update(&a2.bytes()), Err(PakeError::SameRole)));

        let mut b = Pake::init_curve(b"x", 1, "p256").unwrap();
        let forged = br#"{"Role":0,"Xu":1,"Xv":2}"#;
        // missing real X coordinates → not on curve
        assert!(b.update(forged).is_err());
    }

    #[test]
    fn json_shape_matches_go() {
        let a = Pake::init_curve(b"x", 1, "siec").unwrap();
        let s = String::from_utf8(a.bytes()).unwrap();
        // Role-1 before update: U/V set, X/Y null — exactly as Go's Public().
        assert!(s.contains("\"Role\":1"));
        assert!(s.contains("\"Uᵤ\":793136080485469241208656611513609866400481671853"));
        assert!(s.contains("\"Xᵤ\":null"));
    }

    /// Go marshals the whole (zeroed) `Public()` struct, so every field of
    /// `pake.Pake` appears — including the private ones as `null`. Peers rely
    /// on a role-1 reply being no shorter than the role-0 value it answers.
    #[test]
    fn json_has_every_go_field_and_role1_is_longer() {
        let mut a = Pake::init_curve(b"x", 0, "p256").unwrap();
        let mut b = Pake::init_curve(b"x", 1, "p256").unwrap();
        b.update(&a.bytes()).unwrap();
        a.update(&b.bytes()).unwrap();
        let role0 = String::from_utf8(a.bytes()).unwrap();
        let role1 = String::from_utf8(b.bytes()).unwrap();
        for field in [
            "Role", "Uᵤ", "Uᵥ", "Vᵤ", "Vᵥ", "Xᵤ", "Xᵥ", "Yᵤ", "Yᵥ", "P", "Pw", "Vpwᵤ", "Vpwᵥ",
            "Upwᵤ", "Upwᵥ", "Aα", "Aαᵤ", "Aαᵥ", "Zᵤ", "Zᵥ", "K",
        ] {
            assert!(role1.contains(&format!("\"{field}\":")), "missing {field}");
        }
        assert!(role1.ends_with(",\"Zᵤ\":null,\"Zᵥ\":null,\"K\":null}"));
        // A role-0 value never carries Y, so its reply is always the longer of
        // the two — the property croc peers depend on when they decode a reply
        // over their own stored value.
        let fresh0 = Pake::init_curve(b"x", 0, "p256").unwrap();
        assert!(role1.len() > fresh0.bytes().len());
        assert!(role0.contains("\"Yᵤ\":"));
    }
}
