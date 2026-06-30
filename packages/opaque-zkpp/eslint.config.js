import js from '@eslint/js';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';

export default [
  js.configs.recommended,
  {
    files: ['src/**/*.ts', 'tests/**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
      globals: {
        // Browser + worker + node test globals (no-undef is off; listed for clarity).
        crypto: 'readonly',
        console: 'readonly',
        process: 'readonly',
        performance: 'readonly',
        navigator: 'readonly',
        self: 'readonly',
        globalThis: 'readonly',
        Worker: 'readonly',
        MessageEvent: 'readonly',
        TextEncoder: 'readonly',
        TextDecoder: 'readonly',
        atob: 'readonly',
        btoa: 'readonly',
        fetch: 'readonly',
        structuredClone: 'readonly',
        setTimeout: 'readonly',
        WebAssembly: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      // Disable no-undef for TypeScript — TS compiler handles this with type checking.
      'no-undef': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      'no-unused-vars': 'off',
    },
  },
  {
    // Test scaffolding parses Rust reference dumps with loose shapes; `any` is
    // pragmatic there and does not affect the behavioural assertions. src stays strict.
    files: ['tests/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
  {
    ignores: ['dist/', 'node_modules/', 'coverage/', 'wasm/'],
  },
];
