# @structured-id/opaque (monorepo)

Yarn workspace with two independently-licensed packages:

| Package | License | Description |
|---------|---------|-------------|
| [`packages/opaque`](packages/opaque) | Apache-2.0 | `@structured-id/opaque` — RFC 9807 OPAQUE PAKE client with password-policy validation |
| [`packages/opaque-zkpp`](packages/opaque-zkpp) | AGPL-3.0-only | `@structured-id/opaque-zkpp` — Zero-Knowledge Password Policy prover (Halo2/Pasta), patent-protected |

Licensing is **per package** — see [`NOTICE`](NOTICE) and each package's `LICENSE`.
The Apache package never depends on the AGPL package at build time; the ZKPP
prover is an optional, separately-installed add-on.

```sh
yarn install          # install workspace
yarn build            # build all packages
yarn test             # test all packages
```
