import { C_NONCE_MISSING_ERROR, CNonceState, IStateManager } from '@sphereon/openid4vci-common'

export class MemoryCNonceStateManager implements IStateManager<CNonceState> {
  private readonly cNonceStateManager: Map<string, CNonceState>

  constructor() {
    this.cNonceStateManager = new Map()
  }
  async clearAllStates(): Promise<void> {
    this.cNonceStateManager.clear()
  }

  async clearExpiredStates(timestamp?: number): Promise<void> {
    const states = Array.from(this.cNonceStateManager.entries())
    timestamp = timestamp ?? +new Date()
    for (const [issuerState, state] of states) {
      if (state.createdOn < timestamp) {
        this.cNonceStateManager.delete(issuerState)
      }
    }
  }

  async deleteState(state: string): Promise<boolean> {
    return this.cNonceStateManager.delete(state)
  }

  async getAssertedState(issuerState: string): Promise<CNonceState | undefined> {
    if (await this.hasState(issuerState)) {
      return await this.getState(issuerState)
    } else {
      throw new Error(C_NONCE_MISSING_ERROR)
    }
  }

  async getState(state: string): Promise<CNonceState | undefined> {
    return this.cNonceStateManager.get(state)
  }

  async hasState(state: string): Promise<boolean> {
    return this.cNonceStateManager.has(state)
  }

  async setState(state: string, payload: CNonceState): Promise<void> {
    this.cNonceStateManager.set(state, payload)
  }
}
