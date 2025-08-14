import { PEX } from '@sphereon/pex'
import { describe, expect, it } from 'vitest'
import { anyDef, VCs } from './fixtures'

// TODO figure out what to do with this test as we do not use any pd's anymore, should i guess be dcql
describe.skip('auth0 presentation tool', () => {
  it('any match definition should return all credentials', async () => {
    const pex = new PEX()
    expect(VCs).toHaveLength(5)
    const selectResult = pex.selectFrom(anyDef, VCs)
    expect(selectResult.matches).toHaveLength(5)
  })
})
