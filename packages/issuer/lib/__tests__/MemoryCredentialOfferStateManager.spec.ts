import { CredentialOfferSession, IStateManager, STATE_MISSING_ERROR } from '@sphereon/oid4vci-common'

import { CredentialOfferStateBuilder } from '../state-manager'
import { MemoryStates } from '../state-manager'

describe('MemoryIssuerStateManager', () => {
  let memoryIssuerStateManager: IStateManager<CredentialOfferSession>

  beforeAll(() => {
    memoryIssuerStateManager = new MemoryStates<CredentialOfferSession>()
  })

  beforeEach(async () => {
    const day = 86400000
    for (const i of Array.from(Array(3).keys())) {
      const timestamp = +new Date(+new Date() + day * (i - 1))
      const issuerState = new CredentialOfferStateBuilder()
        .credentialOffer({ credential_offer: { credential_issuer: 'test', credentials: ['test'] } })
        .createdOn(timestamp)
        .build()
      await memoryIssuerStateManager.set(String(i), issuerState)
    }
  })

  it('should retrieve a state', async () => {
    await expect(memoryIssuerStateManager.get(String(0))).resolves.toBeDefined()
    await expect(memoryIssuerStateManager.getAsserted(String(0))).resolves.toBeDefined()
  })
  it('should check whether a state exists', async () => {
    await expect(memoryIssuerStateManager.has(String(1))).resolves.toBeTruthy()
  })
  it('should delete a state', async () => {
    await expect(memoryIssuerStateManager.delete(String(1))).resolves.toBeTruthy()
    await expect(memoryIssuerStateManager.get(String(0))).resolves.toBeDefined()
    await expect(memoryIssuerStateManager.get(String(1))).resolves.toBeUndefined()
    await expect(memoryIssuerStateManager.get(String(2))).resolves.toBeDefined()
  })
  it('should delete all expired states', async () => {
    await memoryIssuerStateManager.clearExpired(+new Date() + 10000)
    // yesterday should be expired
    await expect(memoryIssuerStateManager.get(String(0))).resolves.toBeUndefined()
    // today should be expired because the method parameter is a few milliseconds ahead
    await expect(memoryIssuerStateManager.get(String(1))).resolves.toBeUndefined()
    await expect(memoryIssuerStateManager.get(String(2))).resolves.toBeDefined()
  })
  it('should delete all states', async () => {
    await memoryIssuerStateManager.clearAll()
    await expect(memoryIssuerStateManager.get(String(0))).resolves.toBeUndefined()
    await expect(memoryIssuerStateManager.get(String(1))).resolves.toBeUndefined()
    await expect(memoryIssuerStateManager.get(String(2))).resolves.toBeUndefined()
  })
  it('should throw exception when state does not exist', async () => {
    await expect(memoryIssuerStateManager.getAsserted(String(3))).rejects.toThrowError(Error(STATE_MISSING_ERROR))
  })
})
