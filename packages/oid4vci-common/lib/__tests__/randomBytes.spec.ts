import { describe, expect, it } from 'vitest'

import randomBytes from '../functions/randomBytes.cjs'

import { UNIT_TEST_TIMEOUT } from './CredentialOfferUtil.spec'

describe('randomBytes should', () => {
  it(
    'generate random bytes of length 32',
    () => {
      const bytes = randomBytes(32)
      expect(bytes).toBeDefined()
      expect(bytes.length).toEqual(32)
    },
    UNIT_TEST_TIMEOUT,
  )
})
