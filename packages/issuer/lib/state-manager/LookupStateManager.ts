// noinspection ES6MissingAwait

import { IStateManager, StateType } from '@sphereon/oid4vci-common'

export class LookupStateManager<K extends StateType, V extends StateType> implements IStateManager<V> {
  constructor(
    private keyValueMapper: IStateManager<K>,
    private valueStateManager: IStateManager<V>,
    private lookup: string,
  ) {}

  startCleanupRoutine(timeout?: number | undefined): Promise<void> {
    this.keyValueMapper.startCleanupRoutine(timeout)
    return this.valueStateManager.startCleanupRoutine(timeout)
  }

  stopCleanupRoutine(): Promise<void> {
    this.keyValueMapper.stopCleanupRoutine()
    return this.valueStateManager.stopCleanupRoutine()
  }

  async clearAll(): Promise<void> {
    this.keyValueMapper.clearAll()
    this.valueStateManager.clearAll()
  }

  async clearExpired(timestamp?: number): Promise<void> {
    this.keyValueMapper.clearExpired(timestamp)
    this.valueStateManager.clearExpired(timestamp)
  }

  private async assertedValueId(key: string): Promise<string> {
    const prop = this.lookup
    const valueId = await this.keyValueMapper
      .getAsserted(key)
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      .then((keyState) => (keyState && prop in keyState ? keyState[prop] : undefined))
    if (typeof valueId !== 'string') {
      throw Error('no value id could be derived for key' + key)
    }
    return valueId
  }

  private async valueId(key: string): Promise<string | undefined> {
    const prop = this.lookup
    return (
      (await this.keyValueMapper
        .get(key)
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        .then((keyState) => (keyState && prop in keyState ? keyState[prop] : undefined))) as string
    )
  }

  async delete(id: string): Promise<boolean> {
    return await this.assertedValueId(id).then(async (value) => {
      await this.keyValueMapper.delete(id)
      return await this.valueStateManager.delete(value)
    })
  }

  async get(id: string): Promise<V | undefined> {
    return this.valueId(id).then((value) => (value ? this.valueStateManager.get(value) : undefined))
  }

  async has(id: string): Promise<boolean> {
    return this.valueId(id).then((value) => (value ? this.valueStateManager.has(value) : false))
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async set(_id: string, _stateValue: V): Promise<void> {
    throw Error(`Please use the setMappedMethod that accepts both and id, value and object`)
  }

  async setMapped(valueKey: string, keyObject: K, stateValue: V): Promise<void> {
    const keys = keyObject as any
    if (!(this.lookup in keys) || !keys[this.lookup]) {
      return Promise.reject(new Error(`keyValue ${keyObject} does not contain the lookup property ${this.lookup}`))
    }
    const key = keys[this.lookup]
    await this.keyValueMapper.set(key, keyObject)
    await this.valueStateManager.set(valueKey, stateValue)
  }

  async getAsserted(id: string): Promise<V> {
    return this.assertedValueId(id).then((value) => this.valueStateManager.getAsserted(value))
  }
}
