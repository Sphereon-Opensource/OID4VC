import { CredentialFormat } from '@sphereon/ssi-types';

import { CredentialRequestClientBuilder } from './CredentialRequestClientBuilder';
import { createProofOfPossession, isValidURL, post } from './functions';
import { CredentialRequest, CredentialResponse, ErrorResponse, ProofOfPossession, ProofOfPossessionOpts, URL_NOT_VALID } from './types';

export class CredentialRequestClient {
  _issuanceRequestOpts: Partial<{
    issuerURL: string;
    clientId: string;
    credentialType: string | string[];
    format: CredentialFormat | CredentialFormat[];
    proof: ProofOfPossession;
    token: string;
  }>;

  public getIssuerUrl(): string {
    return this._issuanceRequestOpts.issuerURL;
  }

  public getClientId(): string {
    return this._issuanceRequestOpts.clientId;
  }

  public constructor(builder: CredentialRequestClientBuilder) {
    this._issuanceRequestOpts = { ...builder };
  }

  public static builder(): CredentialRequestClientBuilder {
    return new CredentialRequestClientBuilder();
  }

  public async acquireCredentialsUsingProof(
    proof: ProofOfPossession | ProofOfPossessionOpts,
    opts?: {
      credentialType?: string | string[];
      format?: CredentialFormat | CredentialFormat[];
      overrideIssuerURL?: string;
      overrideAccessToken?: string;
    }
  ): Promise<CredentialResponse | ErrorResponse> {
    const request = await this.createCredentialRequest(proof, { ...opts });
    return await this.acquireCredentialsUsingRequest(request, { ...opts });
  }

  public async acquireCredentialsUsingRequest(
    request: CredentialRequest,
    opts?: { overrideIssuerURL?: string; overrideAccessToken?: string }
  ): Promise<CredentialResponse | ErrorResponse> {
    const issuerURL: string = opts?.overrideIssuerURL ? opts.overrideIssuerURL : this._issuanceRequestOpts.issuerURL;
    if (!isValidURL(issuerURL)) {
      throw new Error(URL_NOT_VALID);
    }
    const requestToken: string = opts?.overrideAccessToken ? opts.overrideAccessToken : this._issuanceRequestOpts.token;
    // fixme: Needs to be part of the Credential/Proof refactor. For now we just append the '/credential' endpoint
    const response = await post(issuerURL + '/credential', JSON.stringify(request), { bearerToken: requestToken });
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
    const proofOfPossession =
      'jwt' in proof
        ? proof
        : await createProofOfPossession({
            issuerURL: proof.issuerURL ? proof.issuerURL : this._issuanceRequestOpts.issuerURL,
            clientId: proof.clientId ? proof.clientId : this._issuanceRequestOpts.clientId,
            ...proof,
          });
    return {
      type: opts?.credentialType ? opts.credentialType : this._issuanceRequestOpts.credentialType,
      format: opts?.format ? opts.format : this._issuanceRequestOpts.format,
      proof: proofOfPossession,
    };
  }
}
