import { CredentialFormat } from '@sphereon/ssi-types';

import CredentialRequestClientBuilder from './CredentialRequestClientBuilder';
import { createProofOfPossession, isValidURL, post } from './functions';
import { CredentialRequest, CredentialResponse, ErrorResponse, ProofOfPossession, ProofOfPossessionOpts, URL_NOT_VALID } from './types';

export class CredentialRequestClient {
  _issuanceRequestOpts: Partial<{
    credentialRequestUrl: string;
    credentialType: string | string[];
    format: CredentialFormat | CredentialFormat[];
    proof: ProofOfPossession;
    token: string;
  }>;

  public getCredentialRequestUrl(): string {
    return this._issuanceRequestOpts.credentialRequestUrl;
  }

  public constructor(builder: CredentialRequestClientBuilder) {
    this._issuanceRequestOpts = { ...builder };
  }

  public static builder(): CredentialRequestClientBuilder {
    return new CredentialRequestClientBuilder();
  }

  public async sendCredentialRequest(
    request: CredentialRequest,
    opts?: { overrideCredentialRequestUrl?: string; overrideToken?: string }
  ): Promise<CredentialResponse | ErrorResponse> {
    const requestUrl: string = opts?.overrideCredentialRequestUrl
      ? opts.overrideCredentialRequestUrl
      : this._issuanceRequestOpts.credentialRequestUrl;
    if (!isValidURL(requestUrl)) {
      throw new Error(URL_NOT_VALID);
    }
    const requestToken: string = opts?.overrideToken ? opts.overrideToken : this._issuanceRequestOpts.token;
    const response = await post(requestUrl, request, requestToken);
    const responseJson = await response.json();
    if (responseJson.error) {
      return { ...responseJson } as ErrorResponse;
    }
    return { ...responseJson } as CredentialResponse;
  }

  public async createCredentialRequest(
    proof: ProofOfPossession | ProofOfPossessionOpts,
    opts?: {
      credentialType?: string | string[];
      format?: CredentialFormat | CredentialFormat[];
    }
  ): Promise<CredentialRequest> {
    const proofOfPossession = 'jwt' in proof ? proof : await createProofOfPossession(proof);
    return {
      type: opts?.credentialType ? opts.credentialType : this._issuanceRequestOpts.credentialType,
      format: opts?.format ? opts.format : this._issuanceRequestOpts.format,
      proof: proofOfPossession,
    };
  }
}
