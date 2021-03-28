{
  "targets": [
    {
      "target_name": "module",
      "sources": [
        "src/dazoe_ed25519/sha512.c",
        "src/dazoe_ed25519/ed25519/keypair.c",
        "src/dazoe_ed25519/ed25519/sign.c",
        "src/dazoe_ed25519/ed25519/open.c",
        "src/dazoe_ed25519/ed25519/crypto_verify_32.c",
        "src/dazoe_ed25519/ed25519/ge_double_scalarmult.c",
        "src/dazoe_ed25519/ed25519/ge_frombytes.c",
        "src/dazoe_ed25519/ed25519/ge_scalarmult_base.c",
        "src/dazoe_ed25519/ed25519/ge_precomp_0.c",
        "src/dazoe_ed25519/ed25519/ge_p2_0.c",
        "src/dazoe_ed25519/ed25519/ge_p2_dbl.c",
        "src/dazoe_ed25519/ed25519/ge_p3_0.c",
        "src/dazoe_ed25519/ed25519/ge_p3_dbl.c",
        "src/dazoe_ed25519/ed25519/ge_p3_to_p2.c",
        "src/dazoe_ed25519/ed25519/ge_p3_to_cached.c",
        "src/dazoe_ed25519/ed25519/ge_p3_tobytes.c",
        "src/dazoe_ed25519/ed25519/ge_madd.c",
        "src/dazoe_ed25519/ed25519/ge_add.c",
        "src/dazoe_ed25519/ed25519/ge_msub.c",
        "src/dazoe_ed25519/ed25519/ge_sub.c",
        "src/dazoe_ed25519/ed25519/ge_p1p1_to_p3.c",
        "src/dazoe_ed25519/ed25519/ge_p1p1_to_p2.c",
        "src/dazoe_ed25519/ed25519/ge_tobytes.c",
        "src/dazoe_ed25519/ed25519/fe_0.c",
        "src/dazoe_ed25519/ed25519/fe_1.c",
        "src/dazoe_ed25519/ed25519/fe_cmov.c",
        "src/dazoe_ed25519/ed25519/fe_copy.c",
        "src/dazoe_ed25519/ed25519/fe_neg.c",
        "src/dazoe_ed25519/ed25519/fe_add.c",
        "src/dazoe_ed25519/ed25519/fe_sub.c",
        "src/dazoe_ed25519/ed25519/fe_mul.c",
        "src/dazoe_ed25519/ed25519/fe_sq.c",
        "src/dazoe_ed25519/ed25519/fe_sq2.c",
        "src/dazoe_ed25519/ed25519/fe_invert.c",
        "src/dazoe_ed25519/ed25519/fe_tobytes.c",
        "src/dazoe_ed25519/ed25519/fe_isnegative.c",
        "src/dazoe_ed25519/ed25519/fe_isnonzero.c",
        "src/dazoe_ed25519/ed25519/fe_frombytes.c",
        "src/dazoe_ed25519/ed25519/fe_pow22523.c",
        "src/dazoe_ed25519/ed25519/sc_reduce.c",
        "src/dazoe_ed25519/ed25519/sc_muladd.c",
        "./src/module.c"
      ],
      "cflags": [
        "-std=c99"
      ],
      "link_settings": {
        "libraries": [
          ""
        ]
      }
    }
  ]
}