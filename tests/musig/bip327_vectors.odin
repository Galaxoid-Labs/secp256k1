/*
BIP327 MuSig2 test vectors, transcribed from upstream's `src/modules/musig/vectors.h`
(bitcoin-core/secp256k1 v0.7.1), which is itself generated from the BIP327 reference
`test_vectors_musig2_generate.py`.

Generated, not hand-written. Regenerating from the header must reproduce this file byte for
byte. Do not edit — `CLAUDE.md`: vectors come from upstream, unmodified.

MuSig2 is the highest-risk module in this project and had the least external validation, so
the *error* cases matter at least as much as the valid ones: they pin what must be
**rejected**. An implementation that aggregates an invalid public key, or accepts a
malformed nonce, is not lenient — it is exploitable.
*/
package test_musig

Key_Agg_Valid :: struct {
	key_indices: []int,
	expected:    string, // x-only aggregate key
}

Key_Agg_Error :: struct {
	key_indices:   []int,
	tweak_indices: []int,
	is_xonly:      []bool,
	error:         string, // upstream's MUSIG_* discriminant
}

Nonce_Agg_Valid :: struct {
	pnonce_indices: []int,
	expected:       string, // 66-byte aggregate nonce
}

Nonce_Agg_Error :: struct {
	pnonce_indices:    []int,
	invalid_nonce_idx: int,
}

// The 7 candidate public keys, compressed. Indices 3..6 are deliberately malformed.
KEY_AGG_PUBKEYS := [7]string{
	"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
	"03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
	"023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66",
	"020000000000000000000000000000000000000000000000000000000000000005",
	"02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
	"04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
	"03935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9",
}

KEY_AGG_TWEAKS := [2]string{
	"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
	"252e4bd67410a76cdf933d30eaa1608214037f1b105a013eccd3c5c184a6110b",
}

KEY_AGG_VALID := [4]Key_Agg_Valid{
	{{0, 1, 2}, "90539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c"},
	{{2, 1, 0}, "6204de8b083426dc6eaf9502d27024d53fc826bf7d2012148a0575435df54b2b"},
	{{0, 0, 0}, "b436e3bad62b8cd409969a224731c193d051162d8c5ae8b109306127da3aa935"},
	{{0, 0, 1, 1}, "69bc22bfa5d106306e48a20679de1d7389386124d07571d0d872686028c26a3e"},
}

KEY_AGG_ERROR := [5]Key_Agg_Error{
	{{0, 3}, {}, {}, "MUSIG_PUBKEY"},
	{{0, 4}, {}, {}, "MUSIG_PUBKEY"},
	{{5, 0}, {}, {}, "MUSIG_PUBKEY"},
	{{0, 1}, {0}, {true}, "MUSIG_TWEAK"},
	{{6}, {1}, {false}, "MUSIG_TWEAK"},
}

// The 7 candidate public nonces. Indices 4..6 are deliberately malformed.
NONCE_AGG_PNONCES := [7]string{
	"020151c80f435648df67a22b749cd798ce54e0321d034b92b709b567d60a42e66603ba47fbc1834437b3212e89a84d8425e7bf12e0245d98262268ebdcb385d50641",
	"03ff406ffd8adb9cd29877e4985014f66a59f6cd01c0e88caa8e5f3166b1f676a60248c264cdd57d3c24d79990b0f865674eb62a0f9018277a95011b41bfc193b833",
	"020151c80f435648df67a22b749cd798ce54e0321d034b92b709b567d60a42e6660279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	"03ff406ffd8adb9cd29877e4985014f66a59f6cd01c0e88caa8e5f3166b1f676a60379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	"04ff406ffd8adb9cd29877e4985014f66a59f6cd01c0e88caa8e5f3166b1f676a60248c264cdd57d3c24d79990b0f865674eb62a0f9018277a95011b41bfc193b833",
	"03ff406ffd8adb9cd29877e4985014f66a59f6cd01c0e88caa8e5f3166b1f676a60248c264cdd57d3c24d79990b0f865674eb62a0f9018277a95011b41bfc193b831",
	"03ff406ffd8adb9cd29877e4985014f66a59f6cd01c0e88caa8e5f3166b1f676a602fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
}

NONCE_AGG_VALID := [2]Nonce_Agg_Valid{
	{{0, 1}, "035fe1873b4f2967f52fea4a06ad5a8eccbe9d0fd73068012c894e2e87ccb5804b024725377345bde0e9c33af3c43c0a29a9249f2f2956fa8cfeb55c8573d0262dc8"},
	{{2, 3}, "035fe1873b4f2967f52fea4a06ad5a8eccbe9d0fd73068012c894e2e87ccb5804b000000000000000000000000000000000000000000000000000000000000000000"},
}

NONCE_AGG_ERROR := [3]Nonce_Agg_Error{
	{{0, 4}, 1},
	{{5, 1}, 0},
	{{6, 1}, 0},
}

// Nonce generation vectors: the full derivation input set, including the optional
// fields, with the exact secnonce and pubnonce BIP327 requires.
Nonce_Gen_Case :: struct {
	rand, sk, pk, aggpk, msg, extra_in: string, // empty means absent
	expected_secnonce, expected_pubnonce: string,
}

NONCE_GEN := [2]Nonce_Gen_Case{
	{"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", "0202020202020202020202020202020202020202020202020202020202020202", "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766", "0707070707070707070707070707070707070707070707070707070707070707", "0101010101010101010101010101010101010101010101010101010101010101", "0808080808080808080808080808080808080808080808080808080808080808", "b114e502beaa4e301dd08a50264172c84e41650e6cb726b410c0694d59effb6495b5caf28d045b973d63e3c99a44b807bde375fd6cb39e46dc4a511708d0e9d2024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766", "02f7be7089e8376eb355272368766b17e88e7db72047d05e56aa881ea52b3b35df02c29c8046fdd0ded4c7e55869137200fbdbfe2eb654267b6d7013602caed3115a"},
	{"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", "", "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "", "", "", "89bdd787d0284e5e4d5fc572e49e316bab7e21e3b1830de37dfe80156fa41a6d0b17ae8d024c53679699a6fd7944d9c4a366b514baf43088e0708b1023dd289702f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "02c96e7cb1e8aa5dac64d872947914198f607d90ecde5200de52978ad5ded63c000299ec5117c2d29edee8a2092587c3909be694d5cff0667d6c02ea4059f7cd9786"},
}

// Signature aggregation: partial signatures combined into one BIP340 signature.
Sig_Agg_Case :: struct {
	key_indices, tweak_indices: []int,
	is_xonly:                   []bool,
	aggnonce:                   string,
	psig_indices:               []int,
	expected:                   string, // 64-byte signature; empty for error cases
	invalid_sig_idx:            int,
}

SIG_AGG_PUBKEYS := [4]string{
	"03935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9",
	"02d2dc6f5df7c56acf38c7fa0ae7a759ae30e19b37359dfde015872324c7ef6e05",
	"03c7fb101d97ff930acd0c6760852ef64e69083de0b06ac6335724754bb4b0522c",
	"02352433b21e7e05d3b452b81cae566e06d2e003ece16d1074aaba4289e0e3d581",
}

SIG_AGG_TWEAKS := [3]string{
	"b511da492182a91b0ffb9a98020d55f260ae86d7ecbd0399c7383d59a5f2af7c",
	"a815fe049ee3c5aab66310477fbc8bcccac2f3395f59f921c364acd78a2f48dc",
	"75448a87274b056468b977be06eb1e9f657577b7320b0a3376ea51fd420d18a8",
}

SIG_AGG_PSIGS := [9]string{
	"b15d2cd3c3d22b04dae438ce653f6b4ecf042f42cfded7c41b64aaf9b4af53fb",
	"6193d6ac61b354e9105bbdc8937a3454a6d705b6d57322a5a472a02ce99fcb64",
	"9a87d3b79ec67228cb97878b76049b15dbd05b8158d17b5b9114d3c226887505",
	"66f82ea90923689b855d36c6b7e032fb9970301481b99e01cdb4d6ac7c347a15",
	"4f5aee41510848a6447dcd1bbc78457ef69024944c87f40250d3ef2c25d33efe",
	"ddef427bbb847cc027beff4edb01038148917832253ebc355fc33f4a8e2fcce4",
	"97b890a26c981da8102d3bc294159d171d72810fdf7c6a691def02f0f7af3fdc",
	"53fa9e08ba5243cbcb0d797c5ee83bc6728e539eb76c2d0bf0f971ee4e909971",
	"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
}

SIG_AGG_MSG :: "599c67ea410d005b9da90817cf03ed3b1c868e4da4edf00a5880b0082c237869"

SIG_AGG_VALID := [4]Sig_Agg_Case{
	{{0, 1}, {}, {}, "0341432722c5cd0268d829c702cf0d1cbce57033eed201fd335191385227c3210c03d377f2d258b64aadc0e16f26462323d701d286046a2ea93365656afd9875982b", {0, 1}, "041da22223ce65c92c9a0d6c2cac828aaf1eee56304fec371ddf91ebb2b9ef0912f1038025857fedeb3ff696f8b99fa4bb2c5812f6095a2e0004ec99ce18de1e", 0},
	{{0, 2}, {}, {}, "0224afd36c902084058b51b5d36676bba4dc97c775873768e58822f87fe437d792028cb15929099eee2f5dae404cd39357591ba32e9af4e162b8d3e7cb5efe31cb20", {2, 3}, "1069b67ec3d2f3c7c08291accb17a9c9b8f2819a52eb5df8726e17e7d6b52e9f01800260a7e9dac450f4be522de4ce12ba91aeaf2b4279219ef74be1d286add9", 0},
	{{0, 2}, {0}, {false}, "0208c5c438c710f4f96a61e9ff3c37758814b8c3ae12bfea0ed2c87ff6954ff186020b1816ea104b4fca2d304d733e0e19cead51303ff6420bfd222335caa402916d", {4, 5}, "5c558e1dcade86da0b2f02626a512e30a22cf5255caea7ee32c38e9a71a0e9148ba6c0e6ec7683b64220f0298696f1b878cd47b107b81f7188812d593971e0cc", 0},
	{{0, 3}, {0, 1, 2}, {true, false, true}, "02b5ad07afcd99b6d92cb433fbd2a28fdeb98eae2eb09b6014ef0f8197cd58403302e8616910f9293cf692c49f351db86b25e352901f0e237bafda11f1c1cef29ffd", {6, 7}, "839b08820b681dba8daf4cc7b104e8f2638f9388f8d7a555dc17b6e6971d7426ce07bf6ab01f1db50e4e33719295f4094572b79868e440fb3defd3fac1db589e", 0},
}

SIG_AGG_ERROR := [1]Sig_Agg_Case{
	{{0, 3}, {0, 1, 2}, {true, false, true}, "02b5ad07afcd99b6d92cb433fbd2a28fdeb98eae2eb09b6014ef0f8197cd58403302e8616910f9293cf692c49f351db86b25e352901f0e237bafda11f1c1cef29ffd", {7, 8}, "", 1},
}

// Signing and verification: one signer's partial signature within a session.
Sign_Verify_Valid :: struct {
	key_indices:   []int,
	aggnonce_index, msg_index, signer_index: int,
	expected:      string, // 32-byte partial signature
}

Sign_Verify_Error :: struct {
	key_indices:   []int,
	aggnonce_index, msg_index, secnonce_index: int,
	error:         string,
}

SV_SK :: "7fb9e0e687ada1eebf7ecfe2f21e73ebdb51a7d450948dfe8d76d7f2d1007671"

SV_PUBKEYS := [4]string{
	"03935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9",
	"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
	"02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba661",
	"020000000000000000000000000000000000000000000000000000000000000007",
}

SV_SECNONCES := [2]string{
	"508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f703935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9",
	"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9",
}

SV_PUBNONCES := [5]string{
	"0337c87821afd50a8644d820a8f3e02e499c931865c2360fb43d0a0d20dafe07ea0287bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480",
	"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	"032de2662628c90b03f5e720284eb52ff7d71f4284f627b68a853d78c78e1ffe9303e4c5524e83ffe1493b9077cf1ca6beb2090c93d930321071ad40b2f44e599046",
	"0237c87821afd50a8644d820a8f3e02e499c931865c2360fb43d0a0d20dafe07ea0387bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480",
	"0200000000000000000000000000000000000000000000000000000000000000090287bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480",
}

SV_AGGNONCES := [5]string{
	"028465fcf0bbdbcf443aabcce533d42b4b5a10966ac09a49655e8c42daab8fcd61037496a3cc86926d452cafcfd55d25972ca1675d549310de296bff42f72eeea8c9",
	"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	"048465fcf0bbdbcf443aabcce533d42b4b5a10966ac09a49655e8c42daab8fcd61037496a3cc86926d452cafcfd55d25972ca1675d549310de296bff42f72eeea8c9",
	"028465fcf0bbdbcf443aabcce533d42b4b5a10966ac09a49655e8c42daab8fcd61020000000000000000000000000000000000000000000000000000000000000009",
	"028465fcf0bbdbcf443aabcce533d42b4b5a10966ac09a49655e8c42daab8fcd6102fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
}

SV_MSGS := [1]string{
	"f95466d086770e689964664219266fe5ed215c92ae20bab5c9d79addddf3c0cf",
}

SV_VALID := [4]Sign_Verify_Valid{
	{{0, 1, 2}, 0, 0, 0, "012abbcb52b3016ac03ad82395a1a415c48b93def78718e62a7a90052fe224fb"},
	{{1, 0, 2}, 0, 0, 1, "9ff2f7aaa856150cc8819254218d3adeeb0535269051897724f9db3789513a52"},
	{{1, 2, 0}, 0, 0, 2, "fa23c359f6fac4e7796bb93bc9f0532a95468c539ba20ff86d7c76ed92227900"},
	{{0, 1}, 1, 0, 0, "ae386064b26105404798f75de2eb9af5eda5387b064b83d049cb7c5e08879531"},
}

SV_SIGN_ERROR := [6]Sign_Verify_Error{
	{{1, 2}, 0, 0, 0, "MUSIG_PUBKEY"},
	{{1, 0, 3}, 0, 0, 0, "MUSIG_PUBKEY"},
	{{1, 2, 0}, 2, 0, 0, "MUSIG_AGGNONCE"},
	{{1, 2, 0}, 3, 0, 0, "MUSIG_AGGNONCE"},
	{{1, 2, 0}, 4, 0, 0, "MUSIG_AGGNONCE"},
	{{0, 1, 2}, 0, 0, 1, "MUSIG_SECNONCE"},
}

// Tweak vectors: chains of x-only and plain EC tweaks applied before signing.
Tweak_Case :: struct {
	key_indices, nonce_indices, tweak_indices: []int,
	is_xonly:     []bool,
	signer_index: int,
	expected:     string,
}

TW_SK :: "7fb9e0e687ada1eebf7ecfe2f21e73ebdb51a7d450948dfe8d76d7f2d1007671"
TW_SECNONCE :: "508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f703935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9"
TW_AGGNONCE :: "028465fcf0bbdbcf443aabcce533d42b4b5a10966ac09a49655e8c42daab8fcd61037496a3cc86926d452cafcfd55d25972ca1675d549310de296bff42f72eeea8c9"
TW_MSG :: "f95466d086770e689964664219266fe5ed215c92ae20bab5c9d79addddf3c0cf"

TW_PUBKEYS := [3]string{
	"03935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9",
	"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
	"02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
}

TW_PUBNONCES := [3]string{
	"0337c87821afd50a8644d820a8f3e02e499c931865c2360fb43d0a0d20dafe07ea0287bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480",
	"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	"032de2662628c90b03f5e720284eb52ff7d71f4284f627b68a853d78c78e1ffe9303e4c5524e83ffe1493b9077cf1ca6beb2090c93d930321071ad40b2f44e599046",
}

TW_TWEAKS := [5]string{
	"e8f791ff9225a2af0102afff4a9a723d9612a682a25ebe79802b263cdfcd83bb",
	"ae2ea797cc0fe72ac5b97b97f3c6957d7e4199a167a58eb08bcaffda70ac0455",
	"f52ecbc565b3d8bea2dfd5b75a4f457e54369809322e4120831626f290fa87e0",
	"1969ad73cc177fa0b4fced6df1f7bf9907e665fde9ba196a74fed0a3cf5aef9d",
	"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
}

TW_VALID := [5]Tweak_Case{
	{{1, 2, 0}, {1, 2, 0}, {0}, {true}, 2, "e28a5c66e61e178c2ba19db77b6cf9f7e2f0f56c17918cd13135e60cc848fe91"},
	{{1, 2, 0}, {1, 2, 0}, {0}, {false}, 2, "38b0767798252f21bf5702c48028b095428320f73a4b14db1e25de58543d2d2d"},
	{{1, 2, 0}, {1, 2, 0}, {0, 1}, {false, true}, 2, "408a0a21c4a0f5dacaf9646ad6eb6fecd7f7a11f03ed1f48dfff2185bc2c2408"},
	{{1, 2, 0}, {1, 2, 0}, {0, 1, 2, 3}, {false, false, true, true}, 2, "45abd206e61e3df2ec9e264a6fec8292141a633c28586388235541f9ade75435"},
	{{1, 2, 0}, {1, 2, 0}, {0, 1, 2, 3}, {true, false, true, false}, 2, "b255fdcac27b40c7ce7848e2d3b7bf5ea0ed756da81565ac804ccca3e1d5d239"},
}

TW_ERROR := [1]Tweak_Case{
	{{1, 2, 0}, {1, 2, 0}, {4}, {false}, 2, "00"},
}
