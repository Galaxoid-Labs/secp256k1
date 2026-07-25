/*
ECDSA signing and verification.

Mirrors upstream's `examples/ecdsa.c`.

	odin run examples/ecdsa
*/
package example_ecdsa

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

	// Randomize the context before any secret-key operation. This is not optional in real
	// use: without it, every signature runs through identical intermediate values.
	seed: [32]u8
	crypto.rand_bytes(seed[:])
	secp256k1.randomize(&ctx, &seed)

	// Generate a secret key, retrying in the vanishingly rare case that the random bytes
	// are not a valid key.
	seckey: [32]u8
	for {
		crypto.rand_bytes(seckey[:])
		if secp256k1.seckey_verify(&seckey) {
			break
		}
	}

	pubkey, err := secp256k1.pubkey_from_seckey(&ctx, &seckey)
	if err != .None {
		fmt.eprintfln("failed to derive the public key: %v", err)
		return
	}

	compressed := secp256k1.pubkey_serialize(pubkey)
	show("public key:  ", compressed[:])

	// A real application signs the hash of a message, never the message itself.
	msg_hash := [32]u8 {
		0x31, 0x5f, 0x5b, 0xdb, 0x76, 0xd0, 0x78, 0xc4,
		0x3b, 0x8a, 0xc0, 0x06, 0x4e, 0x4a, 0x01, 0x64,
		0x61, 0x2b, 0x1f, 0xce, 0x77, 0xc8, 0x69, 0x34,
		0x5b, 0xfc, 0x94, 0xc7, 0x58, 0x94, 0xed, 0xd3,
	}

	sig, serr := secp256k1.ecdsa_sign(&ctx, &msg_hash, &seckey)
	if serr != .None {
		fmt.eprintfln("signing failed: %v", serr)
		return
	}

	compact := secp256k1.ecdsa_serialize_compact(sig)
	show("signature:   ", compact[:])

	der_buf: [72]u8
	der, derr := secp256k1.ecdsa_serialize_der(der_buf[:], sig)
	if derr == .None {
		show("DER:         ", der)
	}

	ok := secp256k1.ecdsa_verify(sig, &msg_hash, pubkey)
	fmt.printfln("verified:    %v", ok)

	// Signing is deterministic: the same key and message always give the same signature.
	again, _ := secp256k1.ecdsa_sign(&ctx, &msg_hash, &seckey)
	fmt.printfln("determinism: %v", secp256k1.ecdsa_serialize_compact(again) == compact)

	// Wipe the secret key when finished with it.
	crypto.rand_bytes(seckey[:])
}
