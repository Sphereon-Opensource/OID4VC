import { C_NONCE_MISSING_ERROR, CNonceState, IStateManager } from '@sphereon/oid4vci-common'

export class MemoryCNonceStateManager implements IStateManager<CNonceState> {
  private readonly cNonceStateManager: Map<string, CNonceState>
  private intervalRoutineId?: NodeJS.Timer

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

  async getAssertedState(issuerState: string): Promise<CNonceState> {
    if (await this.hasState(issuerState)) {
      return (await this.getState(issuerState)) as CNonceState
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

  startCleanupRoutine(timestamp?: number, timeout?: number): void {
    if (!this.intervalRoutineId) {
      this.intervalRoutineId = setInterval(() => this.clearExpiredStates(timestamp), timeout ?? 5000)
    }
  }

  stopCleanupRouting(): void {
    if (this.intervalRoutineId) {
      clearInterval(this.intervalRoutineId)
    }
  }
}
