import { CredentialFormat } from '@sphereon/ssi-types';

import { URL_NOT_VALID } from './Oidc4vciErrors';
import VcIssuanceClientBuilder from './VcIssuanceClientBuilder';
import { checkUrlValidity, postWithBearerToken } from './functions/HttpUtils';
import { CredentialRequest, CredentialResponse, CredentialResponseError, ProofOfPossession } from './types';

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

  public static builder() {
    return new VcIssuanceClientBuilder();
  }

  //TODO: implement this
  public async acquireToken() {
    return 'MY-TOKEN';
  }

  public async sendCredentialRequest(
    request: CredentialRequest,
    url?: string,
    token?: string
  ): Promise<CredentialResponse | CredentialResponseError> {
    const requestUrl: string = url ? url : this._issuanceRequestOpts.credentialRequestUrl;
    if (!checkUrlValidity(requestUrl)) {
      throw new Error(URL_NOT_VALID);
    }
    const requestToken: string = token ? token : this._issuanceRequestOpts.token;
    try {
      const response = await postWithBearerToken(requestUrl, request, requestToken);
      //TODO: remove this in the future
      console.log(response);
      const responseJson = await response.json();
      if (responseJson.error) {
        return { ...responseJson } as CredentialResponseError;
      }
      return { ...responseJson } as CredentialResponse;
    } catch (e) {
      //TODO: remove this in the future
      console.log(e);
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
