# Changelog

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
