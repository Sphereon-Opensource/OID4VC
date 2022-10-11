import { ClaimFormat } from '@sphereon/ssi-types';

import VcIssuanceClientBuilder from './VcIssuanceClientBuilder';
import { postWithBearerToken } from './functions/HttpUtils';
import { CredentialRequest, CredentialResponse, CredentialResponseError, ProofOfPossession } from './types';

export class VcIssuanceClient {
  _issuanceRequestOpts: Partial<{
    credentialRequestUrl: string;
    credentialType: string | string[];
    format: ClaimFormat | ClaimFormat[];
    proof: ProofOfPossession;
    token: string;
  }>;
  public constructor(opts: { builder?: VcIssuanceClientBuilder }) {
    this._issuanceRequestOpts = {
      credentialRequestUrl: opts.builder.credentialRequestUrl,
      credentialType: opts.builder.credentialType,
      format: opts.builder.format,
      proof: opts.builder.proof,
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
    try {
      const requestUrl: string = url ? url : this._issuanceRequestOpts.credentialRequestUrl;
      const requestToken: string = token ? token : this._issuanceRequestOpts.token;
      const response = await postWithBearerToken(requestUrl, request, requestToken);
      //TODO: remove this in the future
      console.log(response);
      return response.json();
    } catch (e) {
      //TODO: remove this in the future
      console.log(e);
      return e;
    }
  }

  public createCredentialRequest(): CredentialRequest {
    if (
      !this._issuanceRequestOpts.credentialType &&
      !this._issuanceRequestOpts.format &&
      !this._issuanceRequestOpts.proof
    ) {
      throw new Error('Not all the necessary values are filled.');
    }
    return {
      type: this._issuanceRequestOpts.credentialType,
      format: this._issuanceRequestOpts.format,
      proof: this._issuanceRequestOpts.proof,
    };
  }
}
