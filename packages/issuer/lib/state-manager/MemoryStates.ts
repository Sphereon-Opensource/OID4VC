import { IStateManager, STATE_MISSING_ERROR } from '@sphereon/oid4vci-common'
import { StateType } from '@sphereon/oid4vci-common/dist/types/StateManager.types'

export class MemoryStates<T extends StateType> implements IStateManager<T> {
  private readonly expiresInMS: number
  private readonly states: Map<string, T>
  private cleanupIntervalId?: NodeJS.Timer

  constructor(opts?: { expiresInSec?: number }) {
    this.expiresInMS = opts?.expiresInSec !== undefined ? opts?.expiresInSec * 1000 : 180000
    this.states = new Map()
  }
  async clearAll(): Promise<void> {
    this.states.clear()
  }

  async clearExpired(timestamp?: number): Promise<void> {
    const states = Array.from(this.states.entries())
    const ts = timestamp ?? +new Date()
    for (const [id, state] of states) {
      if (state.createdAt + this.expiresInMS < ts) {
        this.states.delete(id)
      }
    }
  }

  async delete(id: string): Promise<boolean> {
    if (!id) {
      throw Error('No id supplied')
    }
    return this.states.delete(id)
  }

  async getAsserted(id: string): Promise<T> {
    if (!id) {
      throw Error('No id supplied')
    }
    let result: T | undefined
    if (await this.has(id)) {
      result = (await this.get(id)) as T
    }
    if (!result) {
      throw new Error(STATE_MISSING_ERROR + ` (${id})`)
    }
    return result
  }

  async get(id: string): Promise<T | undefined> {
    return this.states.get(id)
  }

  async has(id: string): Promise<boolean> {
    if (!id) {
      throw Error('No id supplied')
    }
    return this.states.has(id)
  }

  async set(id: string, stateValue: T): Promise<void> {
    if (!id) {
      throw Error('No id supplied')
    }
    this.states.set(id, stateValue)
  }

  async startCleanupRoutine(timeout?: number): Promise<void> {
    if (!this.cleanupIntervalId) {
      this.cleanupIntervalId = setInterval(() => this.clearExpired(), timeout ?? 30000)
    }
  }

  async stopCleanupRoutine(): Promise<void> {
    if (this.cleanupIntervalId) {
      clearInterval(this.cleanupIntervalId)
    }
  }
}
