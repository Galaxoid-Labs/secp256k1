/*
BIP340 Schnorr signing and verification.

Mirrors upstream's `examples/schnorr.c`.

	odin run examples/schnorr
*/
package example_schnorr

import "core:crypto"
import "core:fmt"
import secp256k1 "../.."

/*
Prints a label and a byte slice as hex.

Written out rather than using `%x`, which formats an array element-wise as a list.
*/
show :: proc(label: string, b: []u8) {
	fmt.printf("%s", label)
	for v in b {
		fmt.printf("%02x", v)
	}
	fmt.println()
}

main :: proc() {
	ctx: secp256k1.Context
	secp256k1.init(&ctx)
	defer secp256k1.destroy(&ctx)

	seed: [32]u8
	crypto.rand_bytes(seed[:])
	secp256k1.randomize(&ctx, &seed)

	seckey: [32]u8
	for {
		crypto.rand_bytes(seckey[:])
		if secp256k1.seckey_verify(&seckey) {
			break
		}
	}

	kp, err := secp256k1.keypair_create(&ctx, &seckey)
	if err != .None {
		fmt.eprintfln("keypair creation failed: %v", err)
		return
	}
	defer secp256k1.keypair_destroy(&kp)

	// BIP340 keys are x-only: 32 bytes, with the y coordinate implicitly even.
	xonly, parity, xerr := secp256k1.keypair_xonly_pubkey(&kp)
	if xerr != .None {
		fmt.eprintfln("x-only extraction failed: %v", xerr)
		return
	}
	{ tmp := secp256k1.xonly_pubkey_serialize(xonly); show("x-only key:  ", tmp[:]) }
	fmt.printfln("parity:      %v", parity)

	// Unlike ECDSA, BIP340 signs a message of any length directly.
	msg := transmute([]u8)string("Hello, secp256k1!")

	// Auxiliary randomness is optional. It need not be secret; it makes the signature
	// non-deterministic and adds fault-attack resistance.
	aux: [32]u8
	crypto.rand_bytes(aux[:])

	sig, serr := secp256k1.schnorr_sign(&ctx, msg, &kp, &aux)
	if serr != .None {
		fmt.eprintfln("signing failed: %v", serr)
		return
	}
	{ tmp := transmute([64]u8)sig; show("signature:   ", tmp[:]) }

	fmt.printfln("verified:    %v", secp256k1.schnorr_verify(sig, msg, xonly))

	// A different message must not verify.
	other := transmute([]u8)string("Hello, secp256k1?")
	fmt.printfln("wrong msg:   %v", secp256k1.schnorr_verify(sig, other, xonly))

	crypto.rand_bytes(seckey[:])
}
