import js from '@eslint/js';

/**
 * Flat config. Deliberately close to the recommended baseline: this project has
 * no house style worth enforcing beyond "catch real mistakes", and a long list
 * of stylistic rules would just add noise to every diff.
 */
export default [
  {
    ignores: ['node_modules/**', 'web/**', 'coverage/**', 'prisma/migrations/**'],
  },
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: {
        process: 'readonly',
        Buffer: 'readonly',
        console: 'readonly',
        fetch: 'readonly',
        AbortSignal: 'readonly',
        URL: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
      },
    },
    rules: {
      // Unused args are load-bearing in Express: error middleware is identified
      // by arity, so `next` must stay even when unused.
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-console': 'error', // everything goes through pino
      eqeqeq: ['error', 'always', { null: 'ignore' }],
      'no-return-await': 'error',
      'prefer-const': 'error',
    },
  },
  {
    // Test helpers and the mock receiver legitimately write to stdout.
    files: ['test/**', 'mock-receiver/**', 'scripts/**'],
    rules: { 'no-console': 'off' },
  },
];
