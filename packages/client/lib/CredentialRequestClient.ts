import { CredentialFormat } from '@sphereon/ssi-types';
import Debug from 'debug';

import { CredentialRequestClientBuilder } from './CredentialRequestClientBuilder';
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';
import { isValidURL, post } from './functions';
import { CredentialRequest, CredentialResponse, OpenIDResponse, ProofOfPossession, URL_NOT_VALID } from '@sphereon/openid4vci-common/lib';

const debug = Debug('sphereon:openid4vci:credential');

export class CredentialRequestClient {
  _issuanceRequestOpts: Partial<{
    credentialEndpoint: string;
    credentialType: string | string[];
    format: CredentialFormat | CredentialFormat[];
    proof: ProofOfPossession;
    token: string;
  }>;

  public getCredentialEndpoint(): string {
    return this._issuanceRequestOpts.credentialEndpoint;
  }

  public constructor(builder: CredentialRequestClientBuilder) {
    this._issuanceRequestOpts = { ...builder };
  }

  public async acquireCredentialsUsingProof({
    proofInput,
    credentialType,
    format,
  }: {
    proofInput: ProofOfPossessionBuilder | ProofOfPossession;
    credentialType?: string | string[];
    format?: CredentialFormat | CredentialFormat[];
  }): Promise<OpenIDResponse<CredentialResponse>> {
    const request = await this.createCredentialRequest({ proofInput, credentialType, format });
    return await this.acquireCredentialsUsingRequest(request);
  }

  public async acquireCredentialsUsingRequest(request: CredentialRequest): Promise<OpenIDResponse<CredentialResponse>> {
    const credentialEndpoint: string = this._issuanceRequestOpts.credentialEndpoint;
    if (!isValidURL(credentialEndpoint)) {
      debug(`Invalid credential endpoint: ${credentialEndpoint}`);
      throw new Error(URL_NOT_VALID);
    }
    debug(`Acquiring credential(s) from: ${credentialEndpoint}`);
    const requestToken: string = this._issuanceRequestOpts.token;
    const response: OpenIDResponse<CredentialResponse> = await post(credentialEndpoint, JSON.stringify(request), { bearerToken: requestToken });
    debug(`Credential endpoint ${credentialEndpoint} response:\r\n${response}`);
    return response;
  }

  public async createCredentialRequest({
    proofInput,
    credentialType,
    format,
  }: {
    proofInput: ProofOfPossessionBuilder | ProofOfPossession;
    credentialType?: string | string[];
    format?: CredentialFormat | CredentialFormat[];
  }): Promise<CredentialRequest> {
    const proof =
      'proof_type' in proofInput ? await ProofOfPossessionBuilder.fromProof(proofInput as ProofOfPossession).build() : await proofInput.build();
    return {
      type: credentialType ? credentialType : this._issuanceRequestOpts.credentialType,
      format: format ? format : this._issuanceRequestOpts.format,
      proof,
    };
  }
}
