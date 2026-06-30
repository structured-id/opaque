# Changelog

## [0.2.0](https://github.com/structured-id/opaque/compare/opaque-zkpp-v0.1.0...opaque-zkpp-v0.2.0) (2026-06-30)


### Features

* **opaque-zkpp:** wire determinate WASM prove progress to onProgress ([b6d9719](https://github.com/structured-id/opaque/commit/b6d971936649e8e0a7ef18fb12bea08db42427e7))


### Bug Fixes

* **opaque-zkpp:** deploy threaded wasm variants + wire backend-wasm to generate_zkpp_proof ([b43a8c9](https://github.com/structured-id/opaque/commit/b43a8c90bddb4e997405f8e1a29636d041fa495a))
* **opaque-zkpp:** load wasm glue at runtime via ../wasm (external in tsup) so the package builds ([fe85214](https://github.com/structured-id/opaque/commit/fe85214cff22ac9f1dee24eb76c67402879ae1a6))


### Performance Improvements

* **opaque-zkpp:** persistent worker pool reused across stages + commit-MSM worker ([41b46a4](https://github.com/structured-id/opaque/commit/41b46a487691315c6833c33fc95a6c5d21b7a989))
