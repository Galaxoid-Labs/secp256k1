/*
ECDH key exchange.

Mirrors upstream's `examples/ecdh.c`.

	odin run examples/ecdh
*/
package example_ecdh

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

	make_key :: proc(ctx: ^secp256k1.Context) -> ([32]u8, secp256k1.Pubkey) {
		sk: [32]u8
		for {
			crypto.rand_bytes(sk[:])
			if secp256k1.seckey_verify(&sk) {
				break
			}
		}
		pk, _ := secp256k1.pubkey_from_seckey(ctx, &sk)
		return sk, pk
	}

	alice_sec, alice_pub := make_key(&ctx)
	bob_sec, bob_pub := make_key(&ctx)

	{ tmp := secp256k1.pubkey_serialize(alice_pub); show("alice pub:   ", tmp[:]) }
	{ tmp := secp256k1.pubkey_serialize(bob_pub); show("bob pub:     ", tmp[:]) }

	// Each party combines its own secret with the other's public key.
	alice_shared, aerr := secp256k1.ecdh_shared_secret(bob_pub, &alice_sec)
	bob_shared, berr := secp256k1.ecdh_shared_secret(alice_pub, &bob_sec)

	if aerr != .None || berr != .None {
		fmt.eprintfln("ECDH failed: %v %v", aerr, berr)
		return
	}

	show("alice sees:  ", alice_shared[:])
	show("bob sees:    ", bob_shared[:])
	fmt.printfln("agree:       %v", alice_shared == bob_shared)

	crypto.rand_bytes(alice_sec[:])
	crypto.rand_bytes(bob_sec[:])
}
