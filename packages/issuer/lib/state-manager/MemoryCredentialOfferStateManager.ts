import { CredentialOfferState, IStateManager, UNKNOWN_CLIENT_ERROR } from '@sphereon/oid4vci-common'

export class MemoryCredentialOfferStateManager implements IStateManager<CredentialOfferState> {
  private readonly credentialOfferStateManager: Map<string, CredentialOfferState>
  constructor() {
    this.credentialOfferStateManager = new Map()
  }

  async clearAllStates(): Promise<void> {
    this.credentialOfferStateManager.clear()
  }

  async clearExpiredStates(timestamp?: number): Promise<void> {
    const states = Array.from(this.credentialOfferStateManager.entries())
    timestamp = timestamp ?? +new Date()
    for (const [issuerState, state] of states) {
      if (state.createdOn < timestamp) {
        this.credentialOfferStateManager.delete(issuerState)
      }
    }
  }

  async deleteState(state: string): Promise<boolean> {
    return this.credentialOfferStateManager.delete(state)
  }

  async getState(state: string): Promise<CredentialOfferState | undefined> {
    return this.credentialOfferStateManager.get(state)
  }

  async hasState(state: string): Promise<boolean> {
    return this.credentialOfferStateManager.has(state)
  }

  async setState(state: string, payload: CredentialOfferState): Promise<void> {
    this.credentialOfferStateManager.set(state, payload)
  }

  async getAssertedState(issuerState: string): Promise<CredentialOfferState> {
    if (await this.hasState(issuerState)) {
      return (await this.getState(issuerState)) as CredentialOfferState
    } else {
      throw new Error(UNKNOWN_CLIENT_ERROR)
    }
  }
}
