/*
The version constants are the single source of truth for the library's version, and three
places copy them: the C header's `SECP256K1_VER_*` macros, the README, and the string
`VERSION` itself. Odin has no compile-time integer-to-string, so the string cannot be derived
from the numeric components; this asserts they were edited together instead.
*/
package test_ecmult_misc

import "core:fmt"
import "core:strings"
import "core:testing"
import secp "../.."

@(test)
test_version_string_matches_components :: proc(t: ^testing.T) {
	expected := fmt.tprintf("%d.%d.%d", secp.VERSION_MAJOR, secp.VERSION_MINOR, secp.VERSION_PATCH)
	testing.expectf(
		t,
		secp.VERSION == expected,
		"VERSION is %q but the components say %q",
		secp.VERSION,
		expected,
	)
}

/*
The C header carries the same version as preprocessor macros, because a C consumer cannot
read an Odin constant. A header that drifts from the library is worse than one with no
version at all, so the numbers are compared rather than assumed.
*/
@(test)
test_c_header_version_matches :: proc(t: ^testing.T) {
	// `#load` resolves relative to this source file and at compile time, so the test does
	// not depend on the working directory and a missing header is a build failure rather
	// than a test that quietly reports it cannot find anything to check.
	text :: string(#load("../../capi/include/secp256k1.h"))

	macros := [3]struct {
		name: string,
		want: int,
	} {
		{"SECP256K1_VER_MAJOR", secp.VERSION_MAJOR},
		{"SECP256K1_VER_MINOR", secp.VERSION_MINOR},
		{"SECP256K1_VER_PATCH", secp.VERSION_PATCH},
	}
	for m in macros {
		needle := fmt.tprintf("#define %s %d", m.name, m.want)
		testing.expectf(t, strings.contains(text, needle), "%s missing from the header", needle)
	}

	needle := fmt.tprintf("#define SECP256K1_VER_STRING \"%s\"", secp.VERSION)
	testing.expectf(t, strings.contains(text, needle), "%s missing from the header", needle)
}
