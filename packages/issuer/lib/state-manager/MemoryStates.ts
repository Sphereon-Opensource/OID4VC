import { IStateManager, STATE_MISSING_ERROR } from '@sphereon/oid4vci-common'
import { StateType } from '@sphereon/oid4vci-common/dist/types/StateManager.types'

export class MemoryStates<T extends StateType> implements IStateManager<T> {
  private readonly states: Map<string, T>
  private intervalRoutineId?: NodeJS.Timer

  constructor() {
    this.states = new Map()
  }
  async clearAll(): Promise<void> {
    this.states.clear()
  }

  async clearExpired(timestamp?: number): Promise<void> {
    const states = Array.from(this.states.entries())
    timestamp = timestamp ?? +new Date()
    for (const [id, state] of states) {
      if (state.createdOn < timestamp) {
        this.states.delete(id)
      }
    }
  }

  async delete(id: string): Promise<boolean> {
    return this.states.delete(id)
  }

  async getAsserted(id: string): Promise<T> {
    if (await this.has(id)) {
      return (await this.get(id)) as T
    } else {
      throw new Error(STATE_MISSING_ERROR)
    }
  }

  async get(id: string): Promise<T | undefined> {
    return this.states.get(id)
  }

  async has(id: string): Promise<boolean> {
    return this.states.has(id)
  }

  async set(id: string, stateValue: T): Promise<void> {
    this.states.set(id, stateValue)
  }

  startCleanupRoutine(timestamp?: number, timeout?: number): void {
    if (!this.intervalRoutineId) {
      this.intervalRoutineId = setInterval(() => this.clearExpired(timestamp), timeout ?? 5000)
    }
  }

  stopCleanupRouting(): void {
    if (this.intervalRoutineId) {
      clearInterval(this.intervalRoutineId)
    }
  }
}
