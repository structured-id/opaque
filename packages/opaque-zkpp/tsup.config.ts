import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  target: 'es2022',
  // The compiled wasm glue (shipped in ../wasm/) is loaded at runtime via dynamic
  // import — keep it external so esbuild neither bundles it nor follows its
  // wasm-bindgen-rayon worker (which imports '../../..').
  external: ['../wasm/opaque.js', '../wasm/opaque-simd.js'],
});
