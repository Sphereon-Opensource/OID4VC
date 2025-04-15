// tsup.config.ts
// import * as path from 'node:path'
import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['lib/index.ts'],
  format: ['esm', 'cjs'],
  tsconfig: '../../tsconfig.tsup.json',
  dts: true,
  target: ['es2022'],

  experimentalDts: false,
  // onSuccess: "tsc --emitDeclarationOnly",
  shims: true,
  sourcemap: true,
  splitting: false,
  outDir: 'dist',
  clean: true,
  skipNodeModulesBundle: false,
})
