/*
The internal invariant layer for field elements.

Compiled away entirely unless `VERIFY` is set, so release builds pay nothing. Under
`-debug` these checks are what catch magnitude and normalization bugs that black-box
vectors cannot see — a firing check has found a real bug, so never weaken one to make a
test pass.

Mirrors upstream's `secp256k1_fe_verify` and `secp256k1_fe_verify_magnitude`.
*/
package field

/*
Asserts that a satisfies the representation bounds implied by its recorded magnitude and
normalized flag.

A normalized element is held to the tighter bound: limbs below 2^52, top limb below 2^48,
and the represented integer strictly below p.
*/
fe_verify :: #force_inline proc "contextless" (a: ^Field_Elem, loc := #caller_location) {
	when VERIFY {
		m := 1 if a.normalized else 2 * a.magnitude

		CHECK(a.magnitude >= 0, "fe_verify: negative magnitude", loc)
		CHECK(a.magnitude <= 32, "fe_verify: magnitude exceeds 32", loc)

		CHECK(a.n[0] <= u64(M52) * u64(m), "fe_verify: limb 0 out of range", loc)
		CHECK(a.n[1] <= u64(M52) * u64(m), "fe_verify: limb 1 out of range", loc)
		CHECK(a.n[2] <= u64(M52) * u64(m), "fe_verify: limb 2 out of range", loc)
		CHECK(a.n[3] <= u64(M52) * u64(m), "fe_verify: limb 3 out of range", loc)
		CHECK(a.n[4] <= u64(M48) * u64(m), "fe_verify: limb 4 out of range", loc)

		if a.normalized {
			// The only way a normalized element can reach p is for every limb above
			// limb 0 to be saturated; in that case limb 0 must stay below p's limb 0.
			if a.n[4] == M48 && (a.n[3] & a.n[2] & a.n[1]) == M52 {
				CHECK(a.n[0] < P0, "fe_verify: normalized value is not below p", loc)
			}
		}
	}
}

/*
Asserts that a's magnitude does not exceed m.

Callers state the bound their arithmetic requires; this is where an unnormalized input
sneaking into a magnitude-sensitive routine gets caught.

Mirrors upstream's `SECP256K1_FE_VERIFY_MAGNITUDE`.
*/
fe_verify_magnitude :: #force_inline proc "contextless" (
	a: ^Field_Elem,
	m: int,
	loc := #caller_location,
) {
	when VERIFY {
		CHECK((m >= 0) & (m <= 32), "fe_verify_magnitude: bound out of range", loc)
		CHECK(a.magnitude <= m, "fe_verify_magnitude: magnitude exceeds bound", loc)
	}
}
