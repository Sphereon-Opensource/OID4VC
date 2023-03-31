import { IssuerStateBuilder } from '../state-manager/IssuerStateBuilder'
import { MemoryIssuerStateManager } from '../state-manager/MemoryIssuerStateManager'

describe('MemoryIssuerStateManager', () => {
  let memoryIssuerStateManager: MemoryIssuerStateManager

  beforeAll(() => {
    memoryIssuerStateManager = new MemoryIssuerStateManager()
  })

  beforeEach(() => {
    const day = 86400000
    for (const i of Array.from(Array(3).keys())) {
      const timestamp = +new Date(+new Date() + day * (i - 1))
      const issuerState = new IssuerStateBuilder()
        .credentialOffer({ credential_offer: { credential_issuer: 'test', credentials: ['test'] } })
        .createdOn(timestamp)
        .build()
      memoryIssuerStateManager.setState(String(i), issuerState)
    }
  })

  it('should retrieve a state', () => {
    expect(memoryIssuerStateManager.getState(String(0))).toBeDefined()
  })
  it('should check whether a state exists', () => {
    expect(memoryIssuerStateManager.hasState(String(1))).toBeTruthy()
  })
  it('should delete a state', () => {
    expect(memoryIssuerStateManager.deleteState(String(1))).toBeTruthy()
    expect(memoryIssuerStateManager.getState(String(0))).toBeDefined()
    expect(memoryIssuerStateManager.getState(String(1))).toBeUndefined()
    expect(memoryIssuerStateManager.getState(String(2))).toBeDefined()
  })
  it('should delete all expired states', () => {
    memoryIssuerStateManager.clearExpiredStates(+new Date() + 10000)
    // yesterday should be expired
    expect(memoryIssuerStateManager.getState(String(0))).toBeUndefined()
    // today should be expired because the method parameter is a few milliseconds ahead
    expect(memoryIssuerStateManager.getState(String(1))).toBeUndefined()
    expect(memoryIssuerStateManager.getState(String(2))).toBeDefined()
  })
  it('should delete all states', () => {
    memoryIssuerStateManager.clearAllStates()
    expect(memoryIssuerStateManager.getState(String(0))).toBeUndefined()
    expect(memoryIssuerStateManager.getState(String(1))).toBeUndefined()
    expect(memoryIssuerStateManager.getState(String(2))).toBeUndefined()
  })
})
