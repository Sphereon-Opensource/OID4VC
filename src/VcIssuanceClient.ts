import { CredentialFormat } from '@sphereon/ssi-types';

import { BAD_PARAMS, JWS_NOT_VALID, URL_NOT_VALID } from './Oidc4vciErrors';
import VcIssuanceClientBuilder from './VcIssuanceClientBuilder';
import { isValidURL, postWithBearerToken } from './functions/HttpUtils';
import {
  CredentialRequest,
  CredentialResponse,
  CredentialResponseError,
  JWTHeader,
  JWTPayload,
  JWTSignerArgs,
  JWTSignerCallback,
  JWTVerifyCallback,
  ProofOfPossession,
  ProofType,
} from './types';
import { isValidURL, post } from './functions';
import { ErrorResponse, URL_NOT_VALID } from './types';
import { CredentialRequest, CredentialResponse, ProofOfPossession } from './types';

export class VcIssuanceClient {
  _issuanceRequestOpts: Partial<{
    credentialRequestUrl: string;
    credentialType: string | string[];
    format: CredentialFormat | CredentialFormat[];
    proof: ProofOfPossession;
    token: string;
    jwtSignerCallback: JWTSignerCallback;
    jwtSignerArgs: JWTSignerArgs;
  }>;

  public constructor(opts: { builder?: VcIssuanceClientBuilder }) {
    this._issuanceRequestOpts = {
      credentialRequestUrl: opts.builder.credentialRequestUrl,
      credentialType: opts.builder.credentialType,
      format: opts.builder.format,
    };
  }

  public static builder(): VcIssuanceClientBuilder {
    return new VcIssuanceClientBuilder();
  }

  public async sendCredentialRequest(request: CredentialRequest, url?: string, token?: string): Promise<CredentialResponse | ErrorResponse> {
    const requestUrl: string = url ? url : this._issuanceRequestOpts.credentialRequestUrl;
    if (!isValidURL(requestUrl)) {
      throw new Error(URL_NOT_VALID);
    }
    const requestToken: string = token ? token : this._issuanceRequestOpts.token;
    try {
      const response = await post(requestUrl, request, requestToken);
      //TODO: remove this in the future
      const responseJson = await response.json();
      if (responseJson.error) {
        return { ...responseJson } as ErrorResponse;
      }
      return { ...responseJson } as CredentialResponse;
    } catch (e) {
      //TODO: remove this in the future
      return e;
    }
  }

  /**
   * createProofOfPossession creates and returns the ProofOfPossession object
   * @param opts
   *         - jwtSignerCallback: function to sign the proof
   *         - jwtSignerArgs: The arguments to create the signature
   *         - jwtVerifyCallback: function to verify if JWT is valid
   */
  public async createProofOfPossession(opts: {
    jwtSignerCallback: JWTSignerCallback;
    jwtSignerArgs: JWTSignerArgs;
    jwtVerifyCallback: JWTVerifyCallback;
  }): Promise<ProofOfPossession> {
    if (!opts.jwtSignerCallback || !opts.jwtSignerArgs || !opts.jwtVerifyCallback) {
      throw new Error(BAD_PARAMS);
    }
    const signerArgs = this.setJWSDefaults(opts.jwtSignerArgs);
    const jwt = await opts.jwtSignerCallback(signerArgs);
    try {
      const algorithm = opts.jwtSignerArgs.header.alg;
      await opts.jwtVerifyCallback({ jws: jwt, key: opts.jwtSignerArgs.publicKey, algorithms: [algorithm] });
    } catch {
      throw new Error(JWS_NOT_VALID);
    }
    return {
      proof_type: ProofType.JWT,
      jwt,
    };
  }

  private setJWSDefaults = (args: JWTSignerArgs): JWTSignerArgs => {
    const now = +new Date();
    const defaultPayload: Partial<JWTPayload> = {
      aud: this._issuanceRequestOpts.credentialRequestUrl,
      iat: (now / 1000) | 0,
      exp: ((now + 5 * 60000) / 1000) | 0,
    };
    const defaultHeader: JWTHeader = {
      alg: 'ES256',
      typ: 'JWT',
    };
    args.payload = { ...defaultPayload, ...args.payload };
    args.header = { ...defaultHeader, ...args.header };
    return args;
  };

  public createCredentialRequest(opts: {
    credentialType?: string | string[];
    format?: CredentialFormat | CredentialFormat[];
    proof: ProofOfPossession;
  }): CredentialRequest {
    return {
      type: opts.credentialType ? opts.credentialType : this._issuanceRequestOpts.credentialType,
      format: opts.format ? opts.format : this._issuanceRequestOpts.format,
      proof: opts.proof,
    };
  }
}
