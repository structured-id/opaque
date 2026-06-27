# Changelog

## [1.1.0](https://github.com/structured-id/opaque/compare/v1.0.4...v1.1.0) (2026-06-27)


### Features

* **policy:** Rust-parity password policy validation for the TS fallback ([c6e9dd7](https://github.com/structured-id/opaque/commit/c6e9dd77dea8fbc1b745970fee57f5e0d708605b))
* **zkpp:** Blake2b Fiat-Shamir transcript, interop-verified vs halo2 ([8d06186](https://github.com/structured-id/opaque/commit/8d061861cfd42bb99a57178a59ad94105bb91bb7))
* **zkpp:** domain primitives for vanishing quotient (lagrange_to_coeff, extended_to_coeff, divide_by_vanishing) ([f68dd9a](https://github.com/structured-id/opaque/commit/f68dd9a20265bb46ccb2fc1894f52a29aa278a7f))
* **zkpp:** dynamic lazy loader (wasm-simd&gt;wasm&gt;pure-ts) — pure-TS code-split, loaded only on no-WASM fallback ([6fc07ac](https://github.com/structured-id/opaque/commit/6fc07acb78812dda590cf6876518931b3deb878b))
* **zkpp:** ECC complete-addition tail witness byte-exact ([6b4dba1](https://github.com/structured-id/opaque/commit/6b4dba1953b7d38fb598f404933df13d5162ab80))
* **zkpp:** ECC variable-base mul incomplete double-and-add witness byte-exact ([7aee2db](https://github.com/structured-id/opaque/commit/7aee2dbe58655c7a181d2d74363ff435d6658551))
* **zkpp:** ECC variable-base mul scalar decomposition (k=scalar+t_q bits) byte-exact ([55b7f5f](https://github.com/structured-id/opaque/commit/55b7f5f267f532be81a6653e1a642314a602e747))
* **zkpp:** EvaluationDomain coset-FFT (coeff_to_extended), interop-verified vs halo2 ([f3a4223](https://github.com/structured-id/opaque/commit/f3a42234bd8b941368d3bbb604973628fd02efb0))
* **zkpp:** full ECC variable-base mul assembly — variableBaseMul(k,P)==[k]P end-to-end ([7a35556](https://github.com/structured-id/opaque/commit/7a3555622ced4ce75f05a3cb33de48344c3c3d1e))
* **zkpp:** gadget A (policy engine) witness byte-exact vs halo2 circuit ([815980f](https://github.com/structured-id/opaque/commit/815980fa8b746f93156af27353a9e37cea8a3c9d))
* **zkpp:** gadget B diff-accumulator witness byte-exact vs halo2 ([531e34e](https://github.com/structured-id/opaque/commit/531e34e3cf0cabdf4802c0cdebda1f3c4fb525b3))
* **zkpp:** gadget C opaque-binder application witness (H_p + M=blind·H_p) byte-exact ([be78532](https://github.com/structured-id/opaque/commit/be78532eb1bc6313f07bbd62ad98930ea5db5b41))
* **zkpp:** gadget D breach-bloom witness (hash+bits+indices) byte-exact vs halo2 ([4bebd10](https://github.com/structured-id/opaque/commit/4bebd100a4676815a86c91f088d3e74c6869b207))
* **zkpp:** IPA polynomial commitment (MSM+blind), interop-verified vs halo2 ([ae53d32](https://github.com/structured-id/opaque/commit/ae53d323845b7c765a378984deb5251401add02f))
* **zkpp:** lookup commit_product (Z_lookup) byte-exact + lookup expressions ([0aa2e0f](https://github.com/structured-id/opaque/commit/0aa2e0fab04c2a93478ac82ce7c3411d875f8514))
* **zkpp:** lookup evals byte-exact — full lookup argument ported (permute/product/expressions/evals) ([9cdd0e8](https://github.com/structured-id/opaque/commit/9cdd0e819474136ffa738d854e90d9fce1a14633))
* **zkpp:** lookup folded-H expressions byte-exact (permute+product+expressions complete) ([76698c1](https://github.com/structured-id/opaque/commit/76698c1d75970617dfc0fc3a545fda09a7a29f34))
* **zkpp:** lookup h_poly (quotient) byte-exact — lookup argument fully verified ([fde7511](https://github.com/structured-id/opaque/commit/fde75118c10754ccd55ed0b89f293dca6313bfb8))
* **zkpp:** lookup permute_expression_pair (A'/S' + commits) byte-exact vs halo2 ([a2cd8ee](https://github.com/structured-id/opaque/commit/a2cd8ee6443fd1fa2c82d8cf4db413ed789e17fa))
* **zkpp:** native HashToCurve (gadget C H_p), interop-verified vs Rust ([391ae77](https://github.com/structured-id/opaque/commit/391ae77776d06961b2c876bac60755a2c3290efe))
* **zkpp:** Okamoto commit-prove binding, interop-verified vs Rust ([38ae1ee](https://github.com/structured-id/opaque/commit/38ae1ee600bff302e8161c2f7332fa498c0799ca))
* **zkpp:** orchestration — all Poseidon hash-chains (gadget_b/c/d, 12 perms) reproduce real circuit ([43a87c8](https://github.com/structured-id/opaque/commit/43a87c8a8ac19aff5d77905a966b6b8c32dfabd9))
* **zkpp:** orchestration — Poseidon input cells (gadget_b zeros, gadget_c/d password fes) ([d171e95](https://github.com/structured-id/opaque/commit/d171e95345950a24a062333f6e6c6731ae90a01c))
* **zkpp:** orchestration gadget_c binding — H_p + r·G2 fixed-base mul + Pedersen com reproduce real circuit ([505c88c](https://github.com/structured-id/opaque/commit/505c88c35e987c7019821e02b4078de51c64771d))
* **zkpp:** orchestration R0 — gadget_a witness reproduces real circuit advice cols 0-9 byte-exact ([d739a39](https://github.com/structured-id/opaque/commit/d739a3949b7c664131a6f46f1a26bdacd2909d17))
* **zkpp:** orchestration R26 — gadget_b diff-acc reproduces real circuit advice cols 11-16 ([1d896f5](https://github.com/structured-id/opaque/commit/1d896f56a1a59527b432c12e4162917318e66cca))
* **zkpp:** orchestration R34 — gadget_c HashToCurve Poseidon (password input) reproduces real circuit ([9749a7d](https://github.com/structured-id/opaque/commit/9749a7d795f9c8db8b342a74151412ae42fd824d))
* **zkpp:** orchestration R46 — fixed-base mul window decomposition reproduces real circuit col26 ([dfe72c0](https://github.com/structured-id/opaque/commit/dfe72c0e7d4c15dc9448bf58fb0b0f4cadcd54ae))
* **zkpp:** orchestration R5 — Pow5 Poseidon permutation reproduces real circuit cols 18-21 byte-exact ([3299332](https://github.com/structured-id/opaque/commit/32993320f00a5c03ea4389fcc5d4910cd594bc54))
* **zkpp:** orchestration R67 — gadget_d hash bit-decomposition reproduces real circuit cols 39-40 ([41ffe38](https://github.com/structured-id/opaque/commit/41ffe38c95122c1bdd27d7c754fac2073730bad4))
* **zkpp:** Pallas+Vesta via makeCurve factory + MSM (Vesta interop-verified) ([4eeb563](https://github.com/structured-id/opaque/commit/4eeb563402b529d5142c61f166c4492c5c33b573))
* **zkpp:** Pasta field + Pallas curve foundation (verified vs pasta_curves) ([e12ac76](https://github.com/structured-id/opaque/commit/e12ac762d47b60f3f61d507e36ee45e21f24b6f8))
* **zkpp:** platform capability detection + kernel auto-selection ([7335711](https://github.com/structured-id/opaque/commit/7335711796ccbb4402df8fa00a1f1aad15d41bd0))
* **zkpp:** Poseidon P128Pow5T3 over Pasta, interop-verified vs halo2_gadgets ([4c8fb77](https://github.com/structured-id/opaque/commit/4c8fb777914ab16c29fcfac7871a774a4c252859))
* **zkpp:** Pow5 Poseidon-chip witness layout (checkpoint states + partial sboxes) ([e5dab3c](https://github.com/structured-id/opaque/commit/e5dab3c5aff52edda12d6d05dcde99eb6602c17a))
* **zkpp:** radix-2 NTT over Pasta, interop-verified vs halo2 best_fft ([580de8e](https://github.com/structured-id/opaque/commit/580de8e491b155e3f68c86f1e3dd268c1537845f))
* **zkpp:** SimpleFloorPlanner region packing — reproduces all 71 ZkppCircuit region starts ([117afe7](https://github.com/structured-id/opaque/commit/117afe7de83c0bd55faa3f4ae906862dea0d7251))
* **zkpp:** step 6a advice extended coset verified vs halo2 (folded-H inputs) ([277c4ea](https://github.com/structured-id/opaque/commit/277c4ea27115a5f519d1bf3d9fce63c540061faa))
* **zkpp:** TS halo2 prover step 1 (advice commit), byte-exact vs create_proof ([889da41](https://github.com/structured-id/opaque/commit/889da418a5f59165ec4d57dbbd08d1b1a2873773))
* **zkpp:** TS prover step 2 (transcript hash_into+instance+advice -&gt; theta), byte-exact ([4794208](https://github.com/structured-id/opaque/commit/47942083b8ff3cafc678baf6071613b99b021f48))
* **zkpp:** TS prover step 3 (beta/gamma challenges), byte-exact vs halo2 ([5773211](https://github.com/structured-id/opaque/commit/5773211293cec3192c9cb9c2260c0956cbdfd291))
* **zkpp:** TS prover step 4 (permutation grand-product Z), byte-exact vs halo2 ([82bf00d](https://github.com/structured-id/opaque/commit/82bf00dbf2a952ab7482e4e6f708724443098431))
* **zkpp:** TS prover step 6 folded H (gate + permutation constraints) byte-exact vs halo2 ([02d53ba](https://github.com/structured-id/opaque/commit/02d53ba13554c556afa426e2a4ae0a74d4af7fdd))
* **zkpp:** TS prover step 8 (evaluations at x, 17 scalars) byte-exact vs halo2 ([b034a89](https://github.com/structured-id/opaque/commit/b034a8910eb9c33cbdd41e47cae31e631ac5e544))
* **zkpp:** TS prover step 9a IPA opening (s_commit, L/R, c, f) byte-exact vs halo2 ([e836541](https://github.com/structured-id/opaque/commit/e8365418a2d700752bb4adefcac3b15ea4604c95))
* **zkpp:** TS prover step 9b multiopen — FULL toy create_proof byte-exact vs halo2 ([317085e](https://github.com/structured-id/opaque/commit/317085e3e8e6bbbef928be1221f80a86da051a26))
* **zkpp:** TS prover steps 4b-5 (Z commit, vanishing random commit, y), byte-exact ([8804695](https://github.com/structured-id/opaque/commit/8804695fdbd55312abd2b1f9d63835763ff8514f))
* **zkpp:** TS prover steps 6c-7 (h-pieces commit, x challenge) byte-exact vs halo2 ([af4bbd3](https://github.com/structured-id/opaque/commit/af4bbd34785a59435f6954b64744cd4ef225481d))
* **zkpp:** verify divide_by_vanishing + extended_to_coeff (folded H -&gt; h) vs halo2 ([7b9e11a](https://github.com/structured-id/opaque/commit/7b9e11a77a42c7448b263c9131cc6781d471bae0))


### Bug Fixes

* **backend:** delegate OPAQUE protocol to TS backend when WASM OPAQUE unavailable ([046007d](https://github.com/structured-id/opaque/commit/046007db163f335401b5c02c771a41d300775e1f))
* **deps:** align packageManager to yarn 4.14.1 to match lockfile v9 ([dac6e16](https://github.com/structured-id/opaque/commit/dac6e1630f4deaec892ae2258ed748e369dd7fee))


### Performance Improvements

* **zkpp:** back Pallas curve with [@noble](https://github.com/noble) weierstrass (~11x faster, native-capable) ([339176c](https://github.com/structured-id/opaque/commit/339176c77261bc1c5446e4e7f02de05527c26e27))
* **zkpp:** pippenger MSM (16x faster, 251ms for n=2048) + suite benchmark ([5c84464](https://github.com/structured-id/opaque/commit/5c844645df1d96092b20350249bdef0bde15e15c))

## [1.0.4](https://github.com/structured-id/opaque/compare/v1.0.3...v1.0.4) (2026-04-03)


### Bug Fixes

* resolve DTS build failure and prettier formatting ([#34](https://github.com/structured-id/opaque/issues/34)) ([4de0dfa](https://github.com/structured-id/opaque/commit/4de0dfa9bac435a0325eb7fc88eb446236d42d14))

## [1.0.3](https://github.com/structured-id/opaque/compare/v1.0.2...v1.0.3) (2026-04-03)


### Bug Fixes

* include wasm/ directory in npm package files ([a6ec698](https://github.com/structured-id/opaque/commit/a6ec698bc42f8154ad777833629eef8bc8f5d0f4))

## [1.0.2](https://github.com/structured-id/opaque/compare/v1.0.1...v1.0.2) (2026-04-03)


### Bug Fixes

* add type declarations for wasm-bindgen module (fixes CI typecheck) ([20c3135](https://github.com/structured-id/opaque/commit/20c3135250108f1659577ab7db2c977789b36697))
* import wasm-bindgen from wasm/ (in git) not dist/ (build artifact) ([1929f28](https://github.com/structured-id/opaque/commit/1929f289275cb9252e81cc22d2f55669ed478f25))
* resolve all lint errors (unused imports, any types, dead expressions) ([191447d](https://github.com/structured-id/opaque/commit/191447d2b2cdda2a9aeb4372c98c630676b1cb0c))

## 1.0.0 (2026-02-10)

### Features

* scaffold OPAQUE client library ([3aaee5a](https://github.com/structured-id/opaque/commit/3aaee5a13ea35fcd26d1786e89582be311045479)), closes [#1](https://github.com/structured-id/opaque/issues/1)

### Bug Fixes

* **ci:** enable corepack before yarn install ([444a564](https://github.com/structured-id/opaque/commit/444a564b4243ba1b671a61d5e6fd07128baadb71))
* **ci:** match packageManager to local yarn 4.12.0 ([4232d20](https://github.com/structured-id/opaque/commit/4232d20d42998649d79cbbdda8d018e54926a828))
* **ci:** remove registry-url to enable npm OIDC publishing ([99e37e2](https://github.com/structured-id/opaque/commit/99e37e26908b6c390cecc447d056a7ccab50e3d1)), closes [#3](https://github.com/structured-id/opaque/issues/3)
* correct CJS/ESM exports, rename hkdfDerive, add finish tests ([4caa190](https://github.com/structured-id/opaque/commit/4caa1905d15cfacf13bc30cbf8423fcea943a8d0))

### Refactoring

* **crypto:** rename prk to ikm, use concat helper, security disclaimer ([eb3d71b](https://github.com/structured-id/opaque/commit/eb3d71b3afed658c6f58f1f6e136f698a4753a8c))
* **crypto:** return Uint8Array from hash, use shared encode helper ([3ecf62b](https://github.com/structured-id/opaque/commit/3ecf62b059f9c2c1d002e5cb694aed697dfe7bfb)), closes [#1](https://github.com/structured-id/opaque/issues/1)
* **crypto:** use concat() and slice() instead of spread operators ([e6fa7cc](https://github.com/structured-id/opaque/commit/e6fa7ccba0319636ed2d09e20bc366605be11b78)), closes [#1](https://github.com/structured-id/opaque/issues/1)
