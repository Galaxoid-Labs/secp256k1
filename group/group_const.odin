/*
The curve generator.

Built at package initialization from the words in `params`, so that swapping
`EXHAUSTIVE_ORDER` swaps the generator with no code change here. `params` stores it as
plain 32-bit words precisely so that it can depend on nothing.

The generator is checked against the curve equation by
`tests/group/test_group.test_generator_is_on_curve`. That check is not decorative: an
earlier draft of `params` carried a fabricated x coordinate for the order-7 curve, and
nothing else in the build would have caught it.
*/
package group

import "../field"
import "../params"

/*
The generator point G of the configured curve.
*/
GENERATOR: Ge

/*
The generator in Jacobian coordinates.
*/
GENERATOR_J: Gej

@(init, private)
init_generator :: proc "contextless" () {
	w := params.GENERATOR

	x := field.fe_const(w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7])
	y := field.fe_const(w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15])

	ge_set_xy(&GENERATOR, &x, &y)
	gej_set_ge(&GENERATOR_J, &GENERATOR)
}
