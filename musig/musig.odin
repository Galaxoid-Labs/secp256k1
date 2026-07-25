/*
MuSig2 multi-signatures, per BIP327.

Mirrors upstream's `modules/musig/`.

# Status and risk

`CLAUDE.md` singles this module out: it is the largest piece here and its nonce handling is
the highest-risk code in the project. A MuSig2 implementation that produces valid signatures
but permits nonce reuse silently leaks every participant's secret key — the failure is
invisible in testing and total in consequence.

The single-use discipline is therefore built into the API shape rather than left to
documentation: `Secnonce` is invalidated by `partial_sign`, and signing with an already-used
nonce fails rather than producing a second signature under the same nonce.
*/
package musig

import "../ecmult"
import "../group"
import "../scalar"

/*
Multiplies a point by a scalar using the variable-time engine.

Used only on public data — participant keys during aggregation — where variable-time is
appropriate. Wrapped so the choice is stated once rather than at each call site.
*/
@(private)
ecmult_point :: proc "contextless" (r: ^group.Gej, p: ^group.Gej, k: ^scalar.Scalar) {
	ecmult.ecmult(r, p, k, nil)
}
