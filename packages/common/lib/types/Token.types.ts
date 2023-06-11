export enum TokenErrorResponse {
  invalid_request = 'invalid_request',
  invalid_grant = 'invalid_grant',
  invalid_client = 'invalid_client', // this code has been added only in v1_0-11, but I've added this to the common interface. @nklomp is this ok?
  invalid_scope = 'invalid_scope',
}

export class TokenError extends Error {
  private readonly _statusCode: number;
  private readonly _responseError: TokenErrorResponse;
  constructor(statusCode: number, responseError: TokenErrorResponse, message: string) {
    super(message);
    this._statusCode = statusCode;
    this._responseError = responseError;

    // 👇️ because we are extending a built-in class
    Object.setPrototypeOf(this, TokenError.prototype);
  }
  get statusCode(): number {
    return this._statusCode;
  }
  get responseError(): TokenErrorResponse {
    return this._responseError;
  }

  getDescription() {
    return this.message;
  }
}
