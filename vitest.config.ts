import { defineConfig } from 'vitest/config'

export default defineConfig({

  test: {
    globals: true,
    workspace: ['packages/*'],
    coverage: {
      provider: 'v8'
    }
  }
})

