import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: false,
    workspace: ['packages/*'],
    coverage: {
      provider: 'v8',
    },
  },
})
