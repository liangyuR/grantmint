// Dashboard lint gate: typescript-eslint recommended + React hooks rules, wired into CI so
// type-safety regressions (stray `any`, unused escapes, broken hook deps) fail the build.
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/', 'node_modules/'] },
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.{ts,tsx}'],
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // v7's React-Compiler-era opinion; this app deliberately uses the classic fetch-on-mount →
      // setState pattern (no data-fetching library), which the rule flags wholesale. The load-bearing
      // hooks rules (rules-of-hooks, exhaustive-deps) stay on.
      'react-hooks/set-state-in-effect': 'off',
      // The crypto demo path must stay honestly typed — never silence the compiler.
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/ban-ts-comment': 'error',
    },
  },
);
