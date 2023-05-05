import { UNKNOWN_CLIENT_ERROR } from '@sphereon/openid4vci-common'

import { CredentialOfferStateBuilder } from '../state-manager'
import { MemoryCredentialOfferStateManager } from '../state-manager'

describe('MemoryIssuerStateManager', () => {
  let memoryIssuerStateManager: MemoryCredentialOfferStateManager

  beforeAll(() => {
    memoryIssuerStateManager = new MemoryCredentialOfferStateManager()
  })

  beforeEach(async () => {
    const day = 86400000
    for (const i of Array.from(Array(3).keys())) {
      const timestamp = +new Date(+new Date() + day * (i - 1))
      const issuerState = new CredentialOfferStateBuilder()
        .credentialOffer({ credential_offer: { credential_issuer: 'test', credentials: ['test'] } })
        .createdOn(timestamp)
        .build()
      await memoryIssuerStateManager.setState(String(i), issuerState)
    }
  })

  it('should retrieve a state', async () => {
    await expect(memoryIssuerStateManager.getState(String(0))).resolves.toBeDefined()
    await expect(memoryIssuerStateManager.getAssertedState(String(0))).resolves.toBeDefined()
  })
  it('should check whether a state exists', async () => {
    await expect(memoryIssuerStateManager.hasState(String(1))).resolves.toBeTruthy()
  })
  it('should delete a state', async () => {
    await expect(memoryIssuerStateManager.deleteState(String(1))).resolves.toBeTruthy()
    await expect(memoryIssuerStateManager.getState(String(0))).resolves.toBeDefined()
    await expect(memoryIssuerStateManager.getState(String(1))).resolves.toBeUndefined()
    await expect(memoryIssuerStateManager.getState(String(2))).resolves.toBeDefined()
  })
  it('should delete all expired states', async () => {
    await memoryIssuerStateManager.clearExpiredStates(+new Date() + 10000)
    // yesterday should be expired
    await expect(memoryIssuerStateManager.getState(String(0))).resolves.toBeUndefined()
    // today should be expired because the method parameter is a few milliseconds ahead
    await expect(memoryIssuerStateManager.getState(String(1))).resolves.toBeUndefined()
    await expect(memoryIssuerStateManager.getState(String(2))).resolves.toBeDefined()
  })
  it('should delete all states', async () => {
    await memoryIssuerStateManager.clearAllStates()
    await expect(memoryIssuerStateManager.getState(String(0))).resolves.toBeUndefined()
    await expect(memoryIssuerStateManager.getState(String(1))).resolves.toBeUndefined()
    await expect(memoryIssuerStateManager.getState(String(2))).resolves.toBeUndefined()
  })
  it('should throw exception when state does not exist', async () => {
    await expect(memoryIssuerStateManager.getAssertedState(String(3))).rejects.toThrowError(Error(UNKNOWN_CLIENT_ERROR))
  })
})
