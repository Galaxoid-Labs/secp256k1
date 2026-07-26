/*
Internal symbols exported under the C ABI, for linking C test code against this
implementation.

**Test-only. Never ship this.** `capi/` is the public C ABI; this is a second, much wider
surface that reaches past the public API into the field, scalar and group internals, because
that is what upstream's test suite exercises. `DEVELOPMENT.md` §0.5 keeps the two separate
precisely so that nothing here can end up in a released artifact.

# Struct layout compatibility

Every type crossing this boundary has the same size and field offsets as upstream's, which
is what makes it possible to hand a `secp256k1_ge` between C and Odin without conversion:

	                 upstream    here
	secp256k1_fe        40        40
	secp256k1_ge        88        88   (infinity at offset 80 in both)
	secp256k1_gej      128       128   (infinity at offset 120 in both)
	secp256k1_scalar    32        32
	fe_storage          32        32
	ge_storage          64        64

Those are asserted at compile time below and re-checked from the C side by
`csuite/test_csuite.c`, because a silent layout drift would not fail — it would make C read
plausible garbage, which is far worse than a link error.

One subtlety is deliberate. Upstream's `infinity` is a 4-byte `int`; ours is a 1-byte
`bool` at the same offset. That is safe only because Odin zero-initializes structs, so the
three bytes above the flag are zero and C reads the int as exactly 0 or 1. Any code here
that hands out a partially written `Ge` would break that, so points are always assigned
whole rather than field by field.

# Build

	odin build csuite/ -build-mode:static -o:speed -out:libsecp256k1_csuite.a
	cc csuite/test_csuite.c libsecp256k1_csuite.a -o csuite_test && ./csuite_test
*/
package csuite

import "base:intrinsics"
import "../ecdsa"
import "../ecmult"
import "../field"
import "../group"
import "../scalar"

// Layout compatibility with upstream's C structs. These are the sizes and offsets a C
// caller compiles against; if any changes, the C side must be re-checked rather than these
// numbers updated to match.
#assert(size_of(field.Field_Elem) == 40)
#assert(size_of(field.Field_Storage) == 32)
#assert(size_of(scalar.Scalar) == 32)
#assert(size_of(group.Ge) == 88)
#assert(size_of(group.Gej) == 128)
#assert(size_of(group.Ge_Storage) == 64)
#assert(offset_of(group.Ge, infinity) == 80)
#assert(offset_of(group.Gej, infinity) == 120)

// The internal invariant layer changes `Field_Elem`'s layout by adding magnitude and
// normalized fields, which would break every offset above. Building this package with it on
// is a configuration error, not something to paper over at runtime.
#assert(!field.VERIFY, "csuite requires -define:SECP256K1_VERIFY=false; VERIFY changes Field_Elem's layout")

// ---------------------------------------------------------------------------------------
// field
// ---------------------------------------------------------------------------------------

@(export, link_name = "secp256k1_fe_normalize")
csuite_fe_normalize :: proc "c" (r: ^field.Field_Elem) {
	field.fe_normalize(r)
}

@(export, link_name = "secp256k1_fe_normalize_weak")
csuite_fe_normalize_weak :: proc "c" (r: ^field.Field_Elem) {
	field.fe_normalize_weak(r)
}

@(export, link_name = "secp256k1_fe_normalize_var")
csuite_fe_normalize_var :: proc "c" (r: ^field.Field_Elem) {
	field.fe_normalize_var(r)
}

@(export, link_name = "secp256k1_fe_normalizes_to_zero")
csuite_fe_normalizes_to_zero :: proc "c" (r: ^field.Field_Elem) -> i32 {
	return i32(field.fe_normalizes_to_zero(r))
}

@(export, link_name = "secp256k1_fe_normalizes_to_zero_var")
csuite_fe_normalizes_to_zero_var :: proc "c" (r: ^field.Field_Elem) -> i32 {
	return i32(field.fe_normalizes_to_zero_var(r))
}

@(export, link_name = "secp256k1_fe_set_int")
csuite_fe_set_int :: proc "c" (r: ^field.Field_Elem, a: u32) {
	field.fe_set_int(r, a)
}

@(export, link_name = "secp256k1_fe_is_zero")
csuite_fe_is_zero :: proc "c" (a: ^field.Field_Elem) -> i32 {
	return i32(field.fe_is_zero(a))
}

@(export, link_name = "secp256k1_fe_is_odd")
csuite_fe_is_odd :: proc "c" (a: ^field.Field_Elem) -> i32 {
	return i32(field.fe_is_odd(a))
}

@(export, link_name = "secp256k1_fe_equal")
csuite_fe_equal :: proc "c" (a: ^field.Field_Elem, b: ^field.Field_Elem) -> i32 {
	return i32(field.fe_equal(a, b))
}

@(export, link_name = "secp256k1_fe_cmp_var")
csuite_fe_cmp_var :: proc "c" (a: ^field.Field_Elem, b: ^field.Field_Elem) -> i32 {
	return i32(field.fe_cmp_var(a, b))
}

@(export, link_name = "secp256k1_fe_set_b32_mod")
csuite_fe_set_b32_mod :: proc "c" (r: ^field.Field_Elem, a: ^[32]u8) {
	field.fe_set_b32_mod(r, a)
}

@(export, link_name = "secp256k1_fe_set_b32_limit")
csuite_fe_set_b32_limit :: proc "c" (r: ^field.Field_Elem, a: ^[32]u8) -> i32 {
	return i32(field.fe_set_b32_limit(r, a))
}

@(export, link_name = "secp256k1_fe_get_b32")
csuite_fe_get_b32 :: proc "c" (r: ^[32]u8, a: ^field.Field_Elem) {
	field.fe_get_b32(r, a)
}

@(export, link_name = "secp256k1_fe_negate_unchecked")
csuite_fe_negate :: proc "c" (r: ^field.Field_Elem, a: ^field.Field_Elem, m: i32) {
	field.fe_negate(r, a, int(m))
}

@(export, link_name = "secp256k1_fe_mul_int_unchecked")
csuite_fe_mul_int :: proc "c" (r: ^field.Field_Elem, a: i32) {
	field.fe_mul_int(r, u32(a))
}

@(export, link_name = "secp256k1_fe_add")
csuite_fe_add :: proc "c" (r: ^field.Field_Elem, a: ^field.Field_Elem) {
	field.fe_add(r, a)
}

@(export, link_name = "secp256k1_fe_add_int")
csuite_fe_add_int :: proc "c" (r: ^field.Field_Elem, a: i32) {
	field.fe_add_int(r, u32(a))
}

@(export, link_name = "secp256k1_fe_mul")
csuite_fe_mul :: proc "c" (r: ^field.Field_Elem, a: ^field.Field_Elem, b: ^field.Field_Elem) {
	field.fe_mul(r, a, b)
}

@(export, link_name = "secp256k1_fe_sqr")
csuite_fe_sqr :: proc "c" (r: ^field.Field_Elem, a: ^field.Field_Elem) {
	field.fe_sqr(r, a)
}

@(export, link_name = "secp256k1_fe_inv")
csuite_fe_inv :: proc "c" (r: ^field.Field_Elem, a: ^field.Field_Elem) {
	field.fe_inv(r, a)
}

@(export, link_name = "secp256k1_fe_inv_var")
csuite_fe_inv_var :: proc "c" (r: ^field.Field_Elem, a: ^field.Field_Elem) {
	field.fe_inv_var(r, a)
}

@(export, link_name = "secp256k1_fe_sqrt")
csuite_fe_sqrt :: proc "c" (r: ^field.Field_Elem, a: ^field.Field_Elem) -> i32 {
	return i32(field.fe_sqrt(r, a))
}

@(export, link_name = "secp256k1_fe_is_square_var")
csuite_fe_is_square_var :: proc "c" (a: ^field.Field_Elem) -> i32 {
	return i32(field.fe_is_square_var(a))
}

@(export, link_name = "secp256k1_fe_cmov")
csuite_fe_cmov :: proc "c" (r: ^field.Field_Elem, a: ^field.Field_Elem, flag: i32) {
	field.fe_cmov(r, a, flag != 0)
}

@(export, link_name = "secp256k1_fe_half")
csuite_fe_half :: proc "c" (r: ^field.Field_Elem) {
	field.fe_half(r)
}

@(export, link_name = "secp256k1_fe_to_storage")
csuite_fe_to_storage :: proc "c" (r: ^field.Field_Storage, a: ^field.Field_Elem) {
	field.fe_to_storage(r, a)
}

@(export, link_name = "secp256k1_fe_from_storage")
csuite_fe_from_storage :: proc "c" (r: ^field.Field_Elem, a: ^field.Field_Storage) {
	field.fe_from_storage(r, a)
}

@(export, link_name = "secp256k1_fe_storage_cmov")
csuite_fe_storage_cmov :: proc "c" (
	r: ^field.Field_Storage,
	a: ^field.Field_Storage,
	flag: i32,
) {
	field.fe_storage_cmov(r, a, flag != 0)
}

// ---------------------------------------------------------------------------------------
// scalar
// ---------------------------------------------------------------------------------------

@(export, link_name = "secp256k1_scalar_set_int")
csuite_scalar_set_int :: proc "c" (r: ^scalar.Scalar, v: u32) {
	scalar.scalar_set_int(r, v)
}

@(export, link_name = "secp256k1_scalar_is_zero")
csuite_scalar_is_zero :: proc "c" (a: ^scalar.Scalar) -> i32 {
	return i32(scalar.scalar_is_zero(a))
}

@(export, link_name = "secp256k1_scalar_is_one")
csuite_scalar_is_one :: proc "c" (a: ^scalar.Scalar) -> i32 {
	return i32(scalar.scalar_is_one(a))
}

@(export, link_name = "secp256k1_scalar_is_even")
csuite_scalar_is_even :: proc "c" (a: ^scalar.Scalar) -> i32 {
	return i32(scalar.scalar_is_even(a))
}

@(export, link_name = "secp256k1_scalar_is_high")
csuite_scalar_is_high :: proc "c" (a: ^scalar.Scalar) -> i32 {
	return i32(scalar.scalar_is_high(a))
}

@(export, link_name = "secp256k1_scalar_add")
csuite_scalar_add :: proc "c" (r: ^scalar.Scalar, a: ^scalar.Scalar, b: ^scalar.Scalar) -> i32 {
	return i32(scalar.scalar_add(r, a, b))
}

@(export, link_name = "secp256k1_scalar_mul")
csuite_scalar_mul :: proc "c" (r: ^scalar.Scalar, a: ^scalar.Scalar, b: ^scalar.Scalar) {
	scalar.scalar_mul(r, a, b)
}

@(export, link_name = "secp256k1_scalar_negate")
csuite_scalar_negate :: proc "c" (r: ^scalar.Scalar, a: ^scalar.Scalar) {
	scalar.scalar_negate(r, a)
}

@(export, link_name = "secp256k1_scalar_cond_negate")
csuite_scalar_cond_negate :: proc "c" (r: ^scalar.Scalar, flag: i32) -> i32 {
	return i32(scalar.scalar_cond_negate(r, flag != 0))
}

@(export, link_name = "secp256k1_scalar_inverse")
csuite_scalar_inverse :: proc "c" (r: ^scalar.Scalar, a: ^scalar.Scalar) {
	scalar.scalar_inverse(r, a)
}

@(export, link_name = "secp256k1_scalar_inverse_var")
csuite_scalar_inverse_var :: proc "c" (r: ^scalar.Scalar, a: ^scalar.Scalar) {
	scalar.scalar_inverse_var(r, a)
}

@(export, link_name = "secp256k1_scalar_half")
csuite_scalar_half :: proc "c" (r: ^scalar.Scalar, a: ^scalar.Scalar) {
	scalar.scalar_half(r, a)
}

@(export, link_name = "secp256k1_scalar_set_b32")
csuite_scalar_set_b32 :: proc "c" (r: ^scalar.Scalar, b32: ^[32]u8, overflow: ^i32) {
	over := scalar.scalar_set_b32(r, b32)
	if overflow != nil {
		overflow^ = i32(over)
	}
}

@(export, link_name = "secp256k1_scalar_set_b32_seckey")
csuite_scalar_set_b32_seckey :: proc "c" (r: ^scalar.Scalar, b32: ^[32]u8) -> i32 {
	return i32(scalar.scalar_set_b32_seckey(r, b32))
}

@(export, link_name = "secp256k1_scalar_get_b32")
csuite_scalar_get_b32 :: proc "c" (bin: ^[32]u8, a: ^scalar.Scalar) {
	scalar.scalar_get_b32(bin, a)
}

@(export, link_name = "secp256k1_scalar_eq")
csuite_scalar_eq :: proc "c" (a: ^scalar.Scalar, b: ^scalar.Scalar) -> i32 {
	return i32(scalar.scalar_eq(a, b))
}

@(export, link_name = "secp256k1_scalar_cmov")
csuite_scalar_cmov :: proc "c" (r: ^scalar.Scalar, a: ^scalar.Scalar, flag: i32) {
	scalar.scalar_cmov(r, a, flag != 0)
}

// ---------------------------------------------------------------------------------------
// group
// ---------------------------------------------------------------------------------------

@(export, link_name = "secp256k1_ge_set_xy")
csuite_ge_set_xy :: proc "c" (r: ^group.Ge, x: ^field.Field_Elem, y: ^field.Field_Elem) {
	group.ge_set_xy(r, x, y)
}

@(export, link_name = "secp256k1_ge_set_gej")
csuite_ge_set_gej :: proc "c" (r: ^group.Ge, a: ^group.Gej) {
	group.ge_set_gej(r, a)
}

@(export, link_name = "secp256k1_ge_is_infinity")
csuite_ge_is_infinity :: proc "c" (a: ^group.Ge) -> i32 {
	return i32(group.ge_is_infinity(a))
}

@(export, link_name = "secp256k1_ge_is_valid_var")
csuite_ge_is_valid_var :: proc "c" (a: ^group.Ge) -> i32 {
	return i32(group.ge_is_valid_var(a))
}

@(export, link_name = "secp256k1_ge_neg")
csuite_ge_neg :: proc "c" (r: ^group.Ge, a: ^group.Ge) {
	group.ge_neg(r, a)
}

@(export, link_name = "secp256k1_gej_set_ge")
csuite_gej_set_ge :: proc "c" (r: ^group.Gej, a: ^group.Ge) {
	group.gej_set_ge(r, a)
}

@(export, link_name = "secp256k1_gej_set_infinity")
csuite_gej_set_infinity :: proc "c" (r: ^group.Gej) {
	group.gej_set_infinity(r)
}

@(export, link_name = "secp256k1_gej_is_infinity")
csuite_gej_is_infinity :: proc "c" (a: ^group.Gej) -> i32 {
	return i32(group.gej_is_infinity(a))
}

@(export, link_name = "secp256k1_gej_neg")
csuite_gej_neg :: proc "c" (r: ^group.Gej, a: ^group.Gej) {
	group.gej_neg(r, a)
}

@(export, link_name = "secp256k1_gej_double_var")
csuite_gej_double_var :: proc "c" (r: ^group.Gej, a: ^group.Gej, rzr: ^field.Field_Elem) {
	group.gej_double_var(r, a, rzr)
}

@(export, link_name = "secp256k1_gej_add_var")
csuite_gej_add_var :: proc "c" (
	r: ^group.Gej,
	a: ^group.Gej,
	b: ^group.Gej,
	rzr: ^field.Field_Elem,
) {
	group.gej_add_var(r, a, b, rzr)
}

@(export, link_name = "secp256k1_gej_add_ge")
csuite_gej_add_ge :: proc "c" (r: ^group.Gej, a: ^group.Gej, b: ^group.Ge) {
	group.gej_add_ge(r, a, b)
}

@(export, link_name = "secp256k1_gej_add_ge_var")
csuite_gej_add_ge_var :: proc "c" (
	r: ^group.Gej,
	a: ^group.Gej,
	b: ^group.Ge,
	rzr: ^field.Field_Elem,
) {
	group.gej_add_ge_var(r, a, b, rzr)
}

@(export, link_name = "secp256k1_ge_to_storage")
csuite_ge_to_storage :: proc "c" (r: ^group.Ge_Storage, a: ^group.Ge) {
	group.ge_to_storage(r, a)
}

@(export, link_name = "secp256k1_ge_from_storage")
csuite_ge_from_storage :: proc "c" (r: ^group.Ge, a: ^group.Ge_Storage) {
	group.ge_from_storage(r, a)
}

@(export, link_name = "secp256k1_ge_storage_cmov")
csuite_ge_storage_cmov :: proc "c" (
	r: ^group.Ge_Storage,
	a: ^group.Ge_Storage,
	flag: i32,
) {
	group.ge_storage_cmov(r, a, flag != 0)
}

@(export, link_name = "secp256k1_ge_set_xo_var")
csuite_ge_set_xo_var :: proc "c" (r: ^group.Ge, x: ^field.Field_Elem, odd: i32) -> i32 {
	return i32(group.ge_set_xo_var(r, x, odd != 0))
}

@(export, link_name = "secp256k1_gej_rescale")
csuite_gej_rescale :: proc "c" (r: ^group.Gej, s: ^field.Field_Elem) {
	group.gej_rescale(r, s)
}

@(export, link_name = "secp256k1_fe_get_bounds")
csuite_fe_get_bounds :: proc "c" (r: ^field.Field_Elem, m: i32) {
	field.fe_get_bounds(r, int(m))
}


// Upstream exposes these as globals, and its test bodies reference them by name.
@(export, link_name = "secp256k1_scalar_zero")
csuite_scalar_zero := scalar.Scalar{}

@(export, link_name = "secp256k1_scalar_one")
csuite_scalar_one := scalar.Scalar{d = {1, 0, 0, 0}}

@(export, link_name = "secp256k1_ge_set_infinity")
csuite_ge_set_infinity :: proc "c" (r: ^group.Ge) {
	group.ge_set_infinity(r)
}

@(export, link_name = "secp256k1_ge_set_gej_var")
csuite_ge_set_gej_var :: proc "c" (r: ^group.Ge, a: ^group.Gej) {
	group.ge_set_gej_var(r, a)
}

@(export, link_name = "secp256k1_ge_eq_var")
csuite_ge_eq_var :: proc "c" (a: ^group.Ge, b: ^group.Ge) -> i32 {
	return i32(group.ge_eq_var(a, b))
}

@(export, link_name = "secp256k1_gej_eq_var")
csuite_gej_eq_var :: proc "c" (a: ^group.Gej, b: ^group.Gej) -> i32 {
	return i32(group.gej_eq_var(a, b))
}

@(export, link_name = "secp256k1_gej_eq_ge_var")
csuite_gej_eq_ge_var :: proc "c" (a: ^group.Gej, b: ^group.Ge) -> i32 {
	return i32(group.gej_eq_ge_var(a, b))
}

@(export, link_name = "secp256k1_gej_double")
csuite_gej_double :: proc "c" (r: ^group.Gej, a: ^group.Gej) {
	group.gej_double(r, a)
}

@(export, link_name = "secp256k1_gej_add_zinv_var")
csuite_gej_add_zinv_var :: proc "c" (
	r: ^group.Gej,
	a: ^group.Gej,
	b: ^group.Ge,
	bzinv: ^field.Field_Elem,
) {
	group.gej_add_zinv_var(r, a, b, bzinv)
}

@(export, link_name = "secp256k1_ge_mul_lambda")
csuite_ge_mul_lambda :: proc "c" (r: ^group.Ge, a: ^group.Ge) {
	group.ge_mul_lambda(r, a)
}

@(export, link_name = "secp256k1_ge_set_all_gej_var")
csuite_ge_set_all_gej_var :: proc "c" (r: [^]group.Ge, a: [^]group.Gej, len: u64) {
	group.ge_set_all_gej_var(r[:len], a[:len])
}

@(export, link_name = "secp256k1_ge_set_all_gej")
csuite_ge_set_all_gej :: proc "c" (r: [^]group.Ge, a: [^]group.Gej, len: u64) {
	group.ge_set_all_gej(r[:len], a[:len])
}

@(export, link_name = "secp256k1_ge_x_on_curve_var")
csuite_ge_x_on_curve_var :: proc "c" (x: ^field.Field_Elem) -> i32 {
	return i32(group.ge_x_on_curve_var(x))
}

@(export, link_name = "secp256k1_ge_x_frac_on_curve_var")
csuite_ge_x_frac_on_curve_var :: proc "c" (
	xn: ^field.Field_Elem,
	xd: ^field.Field_Elem,
) -> i32 {
	return i32(group.ge_x_frac_on_curve_var(xn, xd))
}

@(export, link_name = "secp256k1_scalar_cadd_bit")
csuite_scalar_cadd_bit :: proc "c" (r: ^scalar.Scalar, bit: u32, flag: i32) {
	scalar.scalar_cadd_bit(r, uint(bit), flag != 0)
}

@(export, link_name = "secp256k1_scalar_check_overflow")
csuite_scalar_check_overflow :: proc "c" (a: ^scalar.Scalar) -> i32 {
	return i32(scalar.scalar_check_overflow(a))
}

@(export, link_name = "secp256k1_scalar_get_bits_limb32")
csuite_scalar_get_bits_limb32 :: proc "c" (a: ^scalar.Scalar, offset: u32, count: u32) -> u32 {
	return scalar.scalar_get_bits_limb32(a, uint(offset), uint(count))
}

@(export, link_name = "secp256k1_scalar_get_bits_var")
csuite_scalar_get_bits_var :: proc "c" (a: ^scalar.Scalar, offset: u32, count: u32) -> u32 {
	return scalar.scalar_get_bits_var(a, uint(offset), uint(count))
}

// ---------------------------------------------------------------------------------------
// ecmult
//
// The generator context is handed across as an opaque blob of matching size; C never looks
// inside it, it only takes its address and passes it back. `secp256k1_csuite_layout`
// reports the size so the C side can size its storage from the library rather than from a
// number written twice.
// ---------------------------------------------------------------------------------------

// Globals upstream's test bodies reference by name.
//
// These are *not* initialized here. `group.GENERATOR` and friends are filled by `@(init)`
// procedures, which the Odin runtime runs at program start — and a C program linking this
// static library never starts that runtime, so they would never run. Worse, a package-level
// initializer here would copy the value before the `@(init)` had a chance either way.
//
// `capi/` already solves this by calling the `ensure_init` chain from its entry points; the
// same applies here, through `secp256k1_csuite_init`, which C must call first. The upstream
// test bodies caught this: `run_point_times_order` compared against a zeroed generator.
@(export, link_name = "secp256k1_fe_one")
csuite_fe_one: field.Field_Elem

@(export, link_name = "secp256k1_ge_const_g")
csuite_ge_const_g: group.Ge

@(export, link_name = "secp256k1_const_lambda")
csuite_const_lambda: scalar.Scalar

@(export, link_name = "secp256k1_ecmult_const_K")
csuite_ecmult_const_K: scalar.Scalar

/*
Initializes the library and the exported globals. A C caller must call this before anything
else; calling it repeatedly is harmless.
*/
@(export, link_name = "secp256k1_csuite_init")
csuite_init :: proc "c" () {
	group.ensure_init()
	ecmult.ensure_init()
	ecdsa.ensure_init()

	csuite_fe_one = field.ONE
	csuite_ge_const_g = group.GENERATOR
	csuite_const_lambda = scalar.LAMBDA
	csuite_ecmult_const_K = ecmult.CONST_K
}

@(export, link_name = "secp256k1_ecmult")
csuite_ecmult :: proc "c" (
	r: ^group.Gej,
	a: ^group.Gej,
	na: ^scalar.Scalar,
	ng: ^scalar.Scalar,
) {
	ecmult.ecmult(r, a, na, ng)
}

@(export, link_name = "secp256k1_ecmult_const")
csuite_ecmult_const :: proc "c" (r: ^group.Gej, a: ^group.Ge, q: ^scalar.Scalar) {
	ecmult.ecmult_const(r, a, q)
}

@(export, link_name = "secp256k1_ecmult_gen")
csuite_ecmult_gen :: proc "c" (
	ctx: ^ecmult.Ecmult_Gen_Context,
	r: ^group.Gej,
	gn: ^scalar.Scalar,
) {
	ecmult.ecmult_gen(ctx, r, gn)
}

@(export, link_name = "secp256k1_ecmult_gen_context_build")
csuite_ecmult_gen_context_build :: proc "c" (ctx: ^ecmult.Ecmult_Gen_Context) {
	ecmult.ecmult_gen_context_build(ctx)
}

@(export, link_name = "secp256k1_ecmult_gen_blind")
csuite_ecmult_gen_blind :: proc "c" (ctx: ^ecmult.Ecmult_Gen_Context, seed32: ^[32]u8) {
	ecmult.ecmult_gen_blind(ctx, seed32)
}

@(export, link_name = "secp256k1_ecmult_wnaf")
csuite_ecmult_wnaf :: proc "c" (wnaf: [^]i32, len: i32, a: ^scalar.Scalar, w: i32) -> i32 {
	// Upstream's wNAF digits are `int`; ours are `int` too, but the widths differ on LP64,
	// so the digits are converted rather than aliased.
	buf: [256]int
	n := ecmult.wnaf(buf[:len], a, uint(w))
	for i in 0 ..< int(len) {
		wnaf[i] = i32(buf[i])
	}
	return i32(n)
}

@(export, link_name = "secp256k1_scalar_split_lambda")
csuite_scalar_split_lambda :: proc "c" (r1: ^scalar.Scalar, r2: ^scalar.Scalar, k: ^scalar.Scalar) {
	scalar.scalar_split_lambda(r1, r2, k)
}

@(export, link_name = "secp256k1_scalar_split_128")
csuite_scalar_split_128 :: proc "c" (r1: ^scalar.Scalar, r2: ^scalar.Scalar, k: ^scalar.Scalar) {
	scalar.scalar_split_128(r1, r2, k)
}

// ---------------------------------------------------------------------------------------
// ecdsa
//
// Upstream passes r and s as separate scalars where this implementation groups them in a
// `Signature`. The two are layout-identical — a `Signature` is exactly two adjacent scalars
// — but they are copied rather than aliased, so the ABI does not depend on that holding.
// ---------------------------------------------------------------------------------------

@(export, link_name = "secp256k1_ecdsa_sig_sign")
csuite_ecdsa_sig_sign :: proc "c" (
	ctx: ^ecmult.Ecmult_Gen_Context,
	sigr: ^scalar.Scalar,
	sigs: ^scalar.Scalar,
	seckey: ^scalar.Scalar,
	message: ^scalar.Scalar,
	nonce: ^scalar.Scalar,
	recid: ^i32,
) -> i32 {
	sig: ecdsa.Signature
	rec: int
	ok := ecdsa.sig_sign(ctx, &sig, seckey, message, nonce, recid != nil ? &rec : nil)
	sigr^ = sig.r
	sigs^ = sig.s
	if recid != nil {
		recid^ = i32(rec)
	}
	return i32(ok)
}

@(export, link_name = "secp256k1_ecdsa_sig_verify")
csuite_ecdsa_sig_verify :: proc "c" (
	sigr: ^scalar.Scalar,
	sigs: ^scalar.Scalar,
	pubkey: ^group.Ge,
	message: ^scalar.Scalar,
) -> i32 {
	sig := ecdsa.Signature{r = sigr^, s = sigs^}
	return i32(ecdsa.sig_verify(&sig, pubkey, message))
}

/*
Reports the sizes and offsets this build actually produced, so the C side can verify them
against its own rather than trusting a comment.
*/
@(export, link_name = "secp256k1_csuite_layout")
csuite_layout :: proc "c" (out: ^[9]u64) {
	out[0] = u64(size_of(field.Field_Elem))
	out[1] = u64(size_of(group.Ge))
	out[2] = u64(offset_of(group.Ge, infinity))
	out[3] = u64(size_of(group.Gej))
	out[4] = u64(offset_of(group.Gej, infinity))
	out[5] = u64(size_of(scalar.Scalar))
	out[6] = u64(size_of(field.Field_Storage))
	out[7] = u64(size_of(group.Ge_Storage))
	out[8] = u64(size_of(ecmult.Ecmult_Gen_Context))
}

// Keeps `intrinsics` referenced when no other use remains, so the import does not warn.
_ :: intrinsics
