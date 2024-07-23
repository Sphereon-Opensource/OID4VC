import { CNonceState, IStateManager, STATE_MISSING_ERROR } from '@sphereon/oid4vci-common'
import { uuidv4 } from '@sphereon/oid4vci-common'

import { MemoryStates } from '../state-manager'

describe('MemoryIssuerStateManager', () => {
  let memoryCNonceStateManager: IStateManager<CNonceState>

  beforeAll(() => {
    memoryCNonceStateManager = new MemoryStates<CNonceState>({ expiresInSec: 0 })
  })

  beforeEach(async () => {
    const day = 86400000
    for (const i of Array.from(Array(3).keys())) {
      const timestamp = +new Date(+new Date() + day * (i - 1))
      const cNonce: CNonceState = { cNonce: uuidv4(), createdAt: timestamp }
      await memoryCNonceStateManager.set(String(i), cNonce)
    }
  })

  it('should retrieve a state', async () => {
    await expect(memoryCNonceStateManager.get(String(0))).resolves.toBeDefined()
    await expect(memoryCNonceStateManager.getAsserted(String(0))).resolves.toBeDefined()
  })
  it('should check whether a state exists', async () => {
    await expect(memoryCNonceStateManager.has(String(1))).resolves.toBeTruthy()
  })
  it('should delete a state', async () => {
    await expect(memoryCNonceStateManager.delete(String(1))).resolves.toBeTruthy()
    await expect(memoryCNonceStateManager.get(String(0))).resolves.toBeDefined()
    await expect(memoryCNonceStateManager.get(String(1))).resolves.toBeUndefined()
    await expect(memoryCNonceStateManager.get(String(2))).resolves.toBeDefined()
  })
  it('should delete all expired states', async () => {
    await memoryCNonceStateManager.clearExpired(+new Date() + 10000)
    // yesterday should be expired
    await expect(memoryCNonceStateManager.get(String(0))).resolves.toBeUndefined()
    // today should be expired because the method parameter is a few milliseconds ahead
    await expect(memoryCNonceStateManager.get(String(1))).resolves.toBeUndefined()
    await expect(memoryCNonceStateManager.get(String(2))).resolves.toBeDefined()
  })
  it('should delete all states', async () => {
    await memoryCNonceStateManager.clearAll()
    await expect(memoryCNonceStateManager.get(String(0))).resolves.toBeUndefined()
    await expect(memoryCNonceStateManager.get(String(1))).resolves.toBeUndefined()
    await expect(memoryCNonceStateManager.get(String(2))).resolves.toBeUndefined()
  })
  it('should throw exception when state does not exist', async () => {
    await expect(memoryCNonceStateManager.getAsserted(String(3))).rejects.toThrowError(Error(STATE_MISSING_ERROR + ' (3)'))
  })
})
