import { CredentialFormat } from '@sphereon/ssi-types';

import VcIssuanceClientBuilder from './VcIssuanceClientBuilder';
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
