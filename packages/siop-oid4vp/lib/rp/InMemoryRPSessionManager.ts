import { EventEmitter } from 'events'

import { AuthorizationRequest } from '../authorization-request'
import { AuthorizationResponse } from '../authorization-response'
import {
  AuthorizationEvent,
  AuthorizationEvents,
  AuthorizationRequestState,
  AuthorizationRequestStateStatus,
  AuthorizationResponseState,
  AuthorizationResponseStateStatus,
} from '../types'

import { IRPSessionManager } from './types'

/**
 * Please note that this session manager is not really meant to be used in large production settings, as it stores everything in memory!
 * It also doesn't do scheduled cleanups. It runs a cleanup whenever a request or response is received. In a high-volume production setting you will want scheduled cleanups running in the background
 * Since this is a low level library we have not created a full-fledged implementation.
 * We suggest to create your own implementation using the event system of the library
 */
export class InMemoryRPSessionManager implements IRPSessionManager {
  private readonly authorizationRequests: Record<string, AuthorizationRequestState> = {}
  private readonly authorizationResponses: Record<string, AuthorizationResponseState> = {}

  // stored by hashcode
  private readonly nonceMapping: Record<number, string> = {}
  // stored by hashcode
  private readonly stateMapping: Record<number, string> = {}
  private readonly maxAgeInSeconds: number

  private static getKeysForCorrelationId(mapping: Record<number, string>, correlationId: string): number[] {
    return Object.entries(mapping)
      .filter((entry) => entry[1] === correlationId)
      .map((filtered) => Number.parseInt(filtered[0]))
  }

  public constructor(eventEmitter: EventEmitter, opts?: { maxAgeInSeconds?: number }) {
    if (!eventEmitter) {
      throw Error('RP Session manager depends on an event emitter in the application')
    }
    this.maxAgeInSeconds = opts?.maxAgeInSeconds ?? 5 * 60
    eventEmitter.on(AuthorizationEvents.ON_AUTH_REQUEST_CREATED_SUCCESS, this.onAuthorizationRequestCreatedSuccess.bind(this))
    eventEmitter.on(AuthorizationEvents.ON_AUTH_REQUEST_CREATED_FAILED, this.onAuthorizationRequestCreatedFailed.bind(this))
    eventEmitter.on(AuthorizationEvents.ON_AUTH_REQUEST_SENT_SUCCESS, this.onAuthorizationRequestSentSuccess.bind(this))
    eventEmitter.on(AuthorizationEvents.ON_AUTH_REQUEST_SENT_FAILED, this.onAuthorizationRequestSentFailed.bind(this))
    eventEmitter.on(AuthorizationEvents.ON_AUTH_RESPONSE_RECEIVED_SUCCESS, this.onAuthorizationResponseReceivedSuccess.bind(this))
    eventEmitter.on(AuthorizationEvents.ON_AUTH_RESPONSE_RECEIVED_FAILED, this.onAuthorizationResponseReceivedFailed.bind(this))
    eventEmitter.on(AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_SUCCESS, this.onAuthorizationResponseVerifiedSuccess.bind(this))
    eventEmitter.on(AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_FAILED, this.onAuthorizationResponseVerifiedFailed.bind(this))
  }

  async getRequestStateByCorrelationId(correlationId: string, errorOnNotFound?: boolean): Promise<AuthorizationRequestState | undefined> {
    return await this.getFromMapping('correlationId', correlationId, this.authorizationRequests, errorOnNotFound)
  }

  async getRequestStateByNonce(nonce: string, errorOnNotFound?: boolean): Promise<AuthorizationRequestState | undefined> {
    return await this.getFromMapping('nonce', nonce, this.authorizationRequests, errorOnNotFound)
  }

  async getRequestStateByState(state: string, errorOnNotFound?: boolean): Promise<AuthorizationRequestState | undefined> {
    return await this.getFromMapping('state', state, this.authorizationRequests, errorOnNotFound)
  }

  async getResponseStateByCorrelationId(correlationId: string, errorOnNotFound?: boolean): Promise<AuthorizationResponseState | undefined> {
    return await this.getFromMapping('correlationId', correlationId, this.authorizationResponses, errorOnNotFound)
  }

  async getResponseStateByNonce(nonce: string, errorOnNotFound?: boolean): Promise<AuthorizationResponseState | undefined> {
    return await this.getFromMapping('nonce', nonce, this.authorizationResponses, errorOnNotFound)
  }

  async getResponseStateByState(state: string, errorOnNotFound?: boolean): Promise<AuthorizationResponseState | undefined> {
    return await this.getFromMapping('state', state, this.authorizationResponses, errorOnNotFound)
  }

  private async getFromMapping<T>(
    type: 'nonce' | 'state' | 'correlationId',
    value: string,
    mapping: Record<string, T>,
    errorOnNotFound?: boolean,
  ): Promise<T> {
    const correlationId = await this.getCorrelationIdImpl(type, value, errorOnNotFound)
    const result = mapping[correlationId] as T
    if (!result && errorOnNotFound) {
      throw Error(`Could not find ${type} from correlation id ${correlationId}`)
    }
    return result
  }

  private async onAuthorizationRequestCreatedSuccess(event: AuthorizationEvent<AuthorizationRequest>): Promise<void> {
    this.cleanup().catch((error) => console.log(JSON.stringify(error)))
    this.updateState('request', event, AuthorizationRequestStateStatus.CREATED).catch((error) => console.log(JSON.stringify(error)))
  }

  private async onAuthorizationRequestCreatedFailed(event: AuthorizationEvent<AuthorizationRequest>): Promise<void> {
    this.cleanup().catch((error) => console.log(JSON.stringify(error)))
    this.updateState('request', event, AuthorizationRequestStateStatus.ERROR).catch((error) => console.log(JSON.stringify(error)))
  }

  private async onAuthorizationRequestSentSuccess(event: AuthorizationEvent<AuthorizationRequest>): Promise<void> {
    this.cleanup().catch((error) => console.log(JSON.stringify(error)))
    this.updateState('request', event, AuthorizationRequestStateStatus.SENT).catch((error) => console.log(JSON.stringify(error)))
  }

  private async onAuthorizationRequestSentFailed(event: AuthorizationEvent<AuthorizationRequest>): Promise<void> {
    this.cleanup().catch((error) => console.log(JSON.stringify(error)))
    this.updateState('request', event, AuthorizationRequestStateStatus.ERROR).catch((error) => console.log(JSON.stringify(error)))
  }

  private async onAuthorizationResponseReceivedSuccess(event: AuthorizationEvent<AuthorizationResponse>): Promise<void> {
    this.cleanup().catch((error) => console.log(JSON.stringify(error)))
    await this.updateState('response', event, AuthorizationResponseStateStatus.RECEIVED)
  }

  private async onAuthorizationResponseReceivedFailed(event: AuthorizationEvent<AuthorizationResponse>): Promise<void> {
    this.cleanup().catch((error) => console.log(JSON.stringify(error)))
    await this.updateState('response', event, AuthorizationResponseStateStatus.ERROR)
  }

  private async onAuthorizationResponseVerifiedFailed(event: AuthorizationEvent<AuthorizationResponse>): Promise<void> {
    await this.updateState('response', event, AuthorizationResponseStateStatus.ERROR)
  }

  private async onAuthorizationResponseVerifiedSuccess(event: AuthorizationEvent<AuthorizationResponse>): Promise<void> {
    await this.updateState('response', event, AuthorizationResponseStateStatus.VERIFIED)
  }

  public async getCorrelationIdByNonce(nonce: string, errorOnNotFound?: boolean): Promise<string | undefined> {
    return await this.getCorrelationIdImpl('nonce', nonce, errorOnNotFound)
  }

  public async getCorrelationIdByState(state: string, errorOnNotFound?: boolean): Promise<string | undefined> {
    return await this.getCorrelationIdImpl('state', state, errorOnNotFound)
  }

  private async getCorrelationIdImpl(
    type: 'nonce' | 'state' | 'correlationId',
    value: string,
    errorOnNotFound?: boolean,
  ): Promise<string | undefined> {
    if (!value || !type) {
      throw Error('No type or value provided')
    }
    if (type === 'correlationId') {
      return value
    }
    const hash = await hashCode(value)
    const correlationId = type === 'nonce' ? this.nonceMapping[hash] : this.stateMapping[hash]
    if (!correlationId && errorOnNotFound) {
      throw Error(`Could not find ${type} value for ${value}`)
    }
    return correlationId
  }

  private async updateMapping(
    mapping: Record<number, string>,
    event: AuthorizationEvent<AuthorizationRequest | AuthorizationResponse>,
    key: string,
    value: string | undefined,
    allowExisting: boolean,
  ) {
    const hash = await hashcodeForValue(event, key)
    const existing = mapping[hash]
    if (existing) {
      if (!allowExisting) {
        throw Error(`Mapping exists for key ${key} and we do not allow overwriting values`)
      } else if (value && existing !== value) {
        throw Error('Value changed for key')
      }
    }
    if (!value) {
      delete mapping[hash]
    } else {
      mapping[hash] = value
    }
  }

  private async updateState(
    type: 'request' | 'response',
    event: AuthorizationEvent<AuthorizationRequest | AuthorizationResponse>,
    status: AuthorizationRequestStateStatus | AuthorizationResponseStateStatus,
  ): Promise<void> {
    if (!event) {
      throw new Error('event not present')
    } else if (!event.correlationId) {
      throw new Error(`'${type} ${status}' event without correlation id received`)
    }
    try {
      const eventState = {
        correlationId: event.correlationId,
        ...(type === 'request' ? { request: event.subject } : {}),
        ...(type === 'response' ? { response: event.subject } : {}),
        ...(event.error ? { error: event.error } : {}),
        status,
        timestamp: event.timestamp,
        lastUpdated: event.timestamp,
      }
      if (type === 'request') {
        this.authorizationRequests[event.correlationId] = eventState as AuthorizationRequestState
        // We do not await these
        this.updateMapping(this.nonceMapping, event, 'nonce', event.correlationId, true).catch((error) => console.log(JSON.stringify(error)))
        this.updateMapping(this.stateMapping, event, 'state', event.correlationId, true).catch((error) => console.log(JSON.stringify(error)))
      } else {
        this.authorizationResponses[event.correlationId] = eventState as AuthorizationResponseState
      }
    } catch (error: unknown) {
      console.log(`Error in update state happened: ${error}`)
      // TODO VDX-166 handle error
    }
  }

  async deleteStateForCorrelationId(correlationId: string) {
    InMemoryRPSessionManager.cleanMappingForCorrelationId(this.nonceMapping, correlationId).catch((error) => console.log(JSON.stringify(error)))
    InMemoryRPSessionManager.cleanMappingForCorrelationId(this.stateMapping, correlationId).catch((error) => console.log(JSON.stringify(error)))
    delete this.authorizationRequests[correlationId]
    delete this.authorizationResponses[correlationId]
  }
  private static async cleanMappingForCorrelationId(mapping: Record<number, string>, correlationId: string): Promise<void> {
    const keys = InMemoryRPSessionManager.getKeysForCorrelationId(mapping, correlationId)
    if (keys && keys.length > 0) {
      keys.forEach((key) => delete mapping[key])
    }
  }

  private async cleanup() {
    const now = Date.now()
    const maxAgeInMS = this.maxAgeInSeconds * 1000

    const cleanupCorrelations = (reqByCorrelationId: [string, AuthorizationRequestState | AuthorizationResponseState]) => {
      const correlationId = reqByCorrelationId[0]
      const authRequest = reqByCorrelationId[1]
      if (authRequest) {
        const ts = authRequest.lastUpdated || authRequest.timestamp
        if (maxAgeInMS !== 0 && now > ts + maxAgeInMS) {
          this.deleteStateForCorrelationId(correlationId)
        }
      }
    }

    Object.entries(this.authorizationRequests).forEach((reqByCorrelationId) => {
      cleanupCorrelations.call(this, reqByCorrelationId)
    })
    Object.entries(this.authorizationResponses).forEach((resByCorrelationId) => {
      cleanupCorrelations.call(this, resByCorrelationId)
    })
  }
}

async function hashcodeForValue(event: AuthorizationEvent<AuthorizationRequest | AuthorizationResponse>, key: string): Promise<number> {
  const value = (await event.subject.getMergedProperty(key)) as string
  if (!value) {
    throw Error(`No value found for key ${key} in Authorization Request`)
  }
  return hashCode(value)
}

function hashCode(s: string): number {
  let h = 1
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0

  return h
}
