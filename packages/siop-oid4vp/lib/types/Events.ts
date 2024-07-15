export enum AuthorizationEvents {
  ON_AUTH_REQUEST_CREATED_SUCCESS = 'onAuthRequestCreatedSuccess',
  ON_AUTH_REQUEST_CREATED_FAILED = 'onAuthRequestCreatedFailed',

  ON_AUTH_REQUEST_SENT_SUCCESS = 'onAuthRequestSentSuccess',
  ON_AUTH_REQUEST_SENT_FAILED = 'onAuthRequestSentFailed',

  ON_AUTH_REQUEST_RECEIVED_SUCCESS = 'onAuthRequestReceivedSuccess',
  ON_AUTH_REQUEST_RECEIVED_FAILED = 'onAuthRequestReceivedFailed',

  ON_AUTH_REQUEST_VERIFIED_SUCCESS = 'onAuthRequestVerifiedSuccess',
  ON_AUTH_REQUEST_VERIFIED_FAILED = 'onAuthRequestVerifiedFailed',

  ON_AUTH_RESPONSE_CREATE_SUCCESS = 'onAuthResponseCreateSuccess',
  ON_AUTH_RESPONSE_CREATE_FAILED = 'onAuthResponseCreateFailed',

  ON_AUTH_RESPONSE_SENT_SUCCESS = 'onAuthResponseSentSuccess',
  ON_AUTH_RESPONSE_SENT_FAILED = 'onAuthResponseSentFailed',

  ON_AUTH_RESPONSE_RECEIVED_SUCCESS = 'onAuthResponseReceivedSuccess',
  ON_AUTH_RESPONSE_RECEIVED_FAILED = 'onAuthResponseReceivedFailed',

  ON_AUTH_RESPONSE_VERIFIED_SUCCESS = 'onAuthResponseVerifiedSuccess',
  ON_AUTH_RESPONSE_VERIFIED_FAILED = 'onAuthResponseVerifiedFailed',
}

export class AuthorizationEvent<T> {
  private readonly _subject: T | undefined
  private readonly _error?: Error
  private readonly _timestamp: number
  private readonly _correlationId: string

  public constructor(args: { correlationId: string; subject?: T; error?: Error }) {
    //fixme: Create correlationId if not provided. Might need to be deferred to registry though
    this._correlationId = args.correlationId
    this._timestamp = Date.now()
    this._subject = args.subject
    this._error = args.error
  }

  get subject(): T {
    return this._subject
  }

  get timestamp(): number {
    return this._timestamp
  }

  get error(): Error {
    return this._error
  }

  public hasError(): boolean {
    return !!this._error
  }

  get correlationId(): string {
    return this._correlationId
  }
}

export interface RegisterEventListener {
  event: AuthorizationEvents | AuthorizationEvents[]

  /* eslint-disable-next-line  @typescript-eslint/no-explicit-any */
  listener: (...args: any[]) => void
}
