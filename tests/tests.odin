/*
Aggregator for the test tree.

`odin test tests/ -all-packages` needs a root package that pulls every test sub-package
into the build; `@require` forces the import to be kept even though nothing here
references it.

Add a line here whenever a new test package appears.
*/
package tests

@(require) import _ "./field"
@(require) import _ "./modinv"
@(require) import _ "./scalar"
@(require) import _ "./group"
@(require) import _ "./ecmult"
@(require) import _ "./hash"
@(require) import _ "./ctx"
@(require) import _ "./ecdsa"
@(require) import _ "./schnorr"
@(require) import _ "./ecdh_recovery"
@(require) import _ "./ellswift"
