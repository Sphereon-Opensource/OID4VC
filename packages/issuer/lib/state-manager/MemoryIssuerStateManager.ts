import { IIssuerStateManager, IssuerState } from '@sphereon/openid4vci-common'

export class MemoryIssuerStateManager implements IIssuerStateManager {
  private readonly issuerStateManager: Map<string, IssuerState>
  constructor() {
    this.issuerStateManager = new Map()
  }

  clearAllStates(): void {
    this.issuerStateManager.clear()
  }

  clearExpiredStates(timestamp?: number): void {
    const states = Array.from(this.issuerStateManager.entries())
    timestamp = timestamp ?? +new Date()
    for (const [issuerState, state] of states) {
      if (state.createdOn < timestamp) {
        this.issuerStateManager.delete(issuerState)
      }
    }
  }

  deleteState(issuerState: string): boolean {
    return this.issuerStateManager.delete(issuerState)
  }

  getState(issuerState: string): IssuerState | undefined {
    return this.issuerStateManager.get(issuerState)
  }

  hasState(issuerState: string): boolean {
    return this.issuerStateManager.has(issuerState)
  }

  setState(issuerState: string, payload: IssuerState): Map<string, IssuerState> {
    return this.issuerStateManager.set(issuerState, payload)
  }
}
